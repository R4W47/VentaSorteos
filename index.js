import { ClienteBalance } from './durable_objects/ClienteBalance.js';
import { SorteoLimites } from './durable_objects/SorteoLimites.js';
import { hashPassword, verifyPassword, crearToken, verificarToken, tienePermiso } from './auth.js';

export { ClienteBalance, SorteoLimites };

// Cabeceras CORS: permiten que la app (en otro dominio, ej. panel-web)
// pueda llamar a este Worker desde el navegador.
const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

export default {
    async fetch(request, env) {
        // El navegador manda una solicitud OPTIONS ("preflight") antes de la
        // real cuando hay credenciales de por medio (como Authorization).
        // Hay que responderla con las cabeceras CORS o el navegador bloquea
        // la solicitud real antes de que llegue a nuestras rutas.
        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: CORS_HEADERS });
        }

        const respuesta = await manejarSolicitud(request, env);

        // Se agregan las cabeceras CORS a CUALQUIER respuesta que salga de
        // aquí, sin importar de qué ruta venga (incluyendo las que vienen
        // directo de un Durable Object).
        const headers = new Headers(respuesta.headers);
        Object.entries(CORS_HEADERS).forEach(([clave, valor]) => headers.set(clave, valor));
        return new Response(respuesta.body, {
            status: respuesta.status,
            statusText: respuesta.statusText,
            headers
        });
    }
};

async function manejarSolicitud(request, env) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        try {
            // ============================================================
            // LOGIN DE CLIENTES
            // (el registro de un cliente NUEVO ya no es autoservicio —
            // solo el staff puede crear cuentas de clientes, ver más abajo)
            // ============================================================
            if (path === '/api/clientes/login' && method === 'POST') {
                const { usuario, password } = await request.json();
                const cliente = await env.DB.prepare(
                    'SELECT * FROM clientes WHERE usuario = ? AND activo = 1'
                ).bind(usuario).first();
                if (!cliente || !(await verifyPassword(password, cliente.password_hash))) {
                    return Response.json({ ok: false, error: 'Usuario o contraseña incorrectos' }, { status: 401 });
                }
                const token = await crearToken({ tipo: 'cliente', id: cliente.id }, env.JWT_SECRET);
                return Response.json({ ok: true, token, saldo: cliente.saldo, nombre: cliente.nombre });
            }

            // ============================================================
            // LOGIN DE STAFF
            // ============================================================
            if (path === '/api/staff/login' && method === 'POST') {
                const { usuario, password } = await request.json();
                const staff = await env.DB.prepare(
                    'SELECT * FROM staff WHERE usuario = ? AND activo = 1'
                ).bind(usuario).first();
                if (!staff || !(await verifyPassword(password, staff.password_hash))) {
                    return Response.json({ ok: false, error: 'Usuario o contraseña incorrectos' }, { status: 401 });
                }
                const token = await crearToken({ tipo: 'staff', id: staff.id, rol: staff.rol }, env.JWT_SECRET);
                return Response.json({ ok: true, token, nombre: staff.nombre, rol: staff.rol });
            }

            // A partir de aquí, los endpoints necesitan sesión iniciada
            const auth = await verificarToken(
                request.headers.get('Authorization')?.replace('Bearer ', ''),
                env.JWT_SECRET
            );

            // ============================================================
            // CREAR CLIENTE (cualquier staff logueado, sin permiso especial —
            // el único requisito es NO ser un cliente)
            // ============================================================
            if (path === '/api/clientes' && method === 'POST') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();

                const { usuario, password, nombre, telefono } = await request.json();
                if (!usuario || !password || !nombre) {
                    return Response.json({ ok: false, error: 'Faltan datos del cliente' }, { status: 400 });
                }

                const existente = await env.DB.prepare('SELECT id FROM clientes WHERE usuario = ?')
                    .bind(usuario).first();
                if (existente) {
                    return Response.json({ ok: false, error: 'Ese usuario ya existe' }, { status: 400 });
                }

                const passwordHash = await hashPassword(password);
                const cliente = await env.DB.prepare(
                    `INSERT INTO clientes (usuario, password_hash, nombre, telefono)
                     VALUES (?, ?, ?, ?) RETURNING id`
                ).bind(usuario, passwordHash, nombre, telefono || null).first();

                return Response.json({ ok: true, clienteId: cliente.id });
            }

            // ============================================================
            // MIS PERMISOS (el staff logueado consulta qué puede hacer,
            // para que el panel muestre solo las secciones permitidas)
            // ============================================================
            if (path === '/api/staff/permisos' && method === 'GET') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();

                const { results: porRol } = await env.DB.prepare(
                    'SELECT permiso_clave FROM rol_permisos WHERE rol = ?'
                ).bind(auth.rol).all();
                const { results: overrides } = await env.DB.prepare(
                    'SELECT permiso_clave, concedido FROM staff_permisos WHERE staff_id = ?'
                ).bind(auth.id).all();

                const permisos = new Set(porRol.map(p => p.permiso_clave));
                overrides.forEach(o => {
                    if (o.concedido === 1) permisos.add(o.permiso_clave);
                    else permisos.delete(o.permiso_clave);
                });

                return Response.json({ ok: true, rol: auth.rol, permisos: [...permisos] });
            }

            // ============================================================
            // BUSCAR CLIENTE POR USUARIO (para recargar/retirar sin saber su ID)
            // ============================================================
            if (path === '/api/clientes/buscar' && method === 'GET') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();

                const usuario = url.searchParams.get('usuario');
                if (!usuario) {
                    return Response.json({ ok: false, error: 'Falta el usuario a buscar' }, { status: 400 });
                }

                const cliente = await env.DB.prepare(
                    'SELECT id, usuario, nombre, saldo FROM clientes WHERE usuario = ? AND activo = 1'
                ).bind(usuario).first();

                if (!cliente) {
                    return Response.json({ ok: false, error: 'No se encontró ese cliente' }, { status: 404 });
                }
                return Response.json({ ok: true, cliente });
            }

            // ============================================================
            // RECARGAS PENDIENTES DE APROBACIÓN
            // ============================================================
            if (path === '/api/recargas/pendientes' && method === 'GET') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();
                if (!(await tienePermiso(env.DB, auth.id, auth.rol, 'aprobar_recargas'))) return sinPermiso();

                const { results } = await env.DB.prepare(
                    `SELECT m.id, m.monto, m.comprobante_url, m.creado_en,
                            c.usuario AS cliente_usuario, c.nombre AS cliente_nombre
                     FROM movimientos_saldo m
                     JOIN clientes c ON c.id = m.cliente_id
                     WHERE m.tipo = 'recarga_comprobante' AND m.estado = 'pendiente'
                     ORDER BY m.creado_en ASC`
                ).all();

                return Response.json({ ok: true, recargas: results });
            }

            // ============================================================
            // SORTEOS ABIERTOS (público para clientes logueados)
            // ============================================================
            if (path === '/api/sorteos' && method === 'GET') {
                if (!auth) return noAutorizado();

                // El cliente solo ve los abiertos; el staff con gestionar_sorteos
                // o registrar_resultado ve todos, para poder cerrarlos y pagarlos.
                let filtroEstado = "estado = 'abierto'";
                if (auth.tipo === 'staff' && (
                    await tienePermiso(env.DB, auth.id, auth.rol, 'gestionar_sorteos') ||
                    await tienePermiso(env.DB, auth.id, auth.rol, 'registrar_resultado')
                )) {
                    filtroEstado = '1=1';
                }

                const { results } = await env.DB.prepare(
                    `SELECT id, nombre, fecha, hora_cierre, estado, multiplicador_pago, banca_id
                     FROM sorteos WHERE ${filtroEstado} ORDER BY fecha DESC, hora_cierre ASC`
                ).all();
                return Response.json({ ok: true, sorteos: results });
            }

            // ============================================================
            // SALDO DEL CLIENTE
            // ============================================================
            if (path === '/api/clientes/saldo' && method === 'GET') {
                if (!auth || auth.tipo !== 'cliente') return noAutorizado();
                const stub = env.CLIENTE_DO.get(env.CLIENTE_DO.idFromName(String(auth.id)));
                return stub.fetch('http://do/', {
                    method: 'POST',
                    body: JSON.stringify({ accion: 'consultar', clienteId: auth.id })
                });
            }

            // ============================================================
            // COMPRAR VARIOS NÚMEROS DE UNA VEZ (la "colilla" completa)
            // Todo o nada: si un número falla a mitad de la lista, se
            // revierten los que ya se habían aplicado.
            // ============================================================
            if (path === '/api/comprar-lote' && method === 'POST') {
                if (!auth || auth.tipo !== 'cliente') return noAutorizado();
                const { sorteoId, items } = await request.json();

                if (!Array.isArray(items) || items.length === 0) {
                    return Response.json({ ok: false, error: 'La lista de números está vacía' }, { status: 400 });
                }
                for (const item of items) {
                    if (!item.numero || !item.monto || item.monto <= 0) {
                        return Response.json({ ok: false, error: 'Hay un número o monto inválido en la lista' }, { status: 400 });
                    }
                }

                const sorteo = await env.DB.prepare('SELECT estado FROM sorteos WHERE id = ?')
                    .bind(sorteoId).first();
                if (!sorteo || sorteo.estado !== 'abierto') {
                    return Response.json({ ok: false, error: 'El sorteo ya no está abierto' }, { status: 400 });
                }

                const clienteStub = env.CLIENTE_DO.get(env.CLIENTE_DO.idFromName(String(auth.id)));
                const sorteoStub = env.SORTEO_DO.get(env.SORTEO_DO.idFromName(String(sorteoId)));

                // Chequeo rápido del total contra el saldo actual (el chequeo
                // real y definitivo ocurre de todas formas en cada débito).
                const consultaSaldo = await (await clienteStub.fetch('http://do/', {
                    method: 'POST',
                    body: JSON.stringify({ accion: 'consultar', clienteId: auth.id })
                })).json();
                const totalSolicitado = items.reduce((acc, it) => acc + it.monto, 0);
                if (totalSolicitado > consultaSaldo.saldo) {
                    return Response.json(
                        { ok: false, error: 'El total de la lista supera tu saldo disponible' },
                        { status: 400 }
                    );
                }

                const aplicados = [];

                for (const item of items) {
                    const reserva = await (await sorteoStub.fetch('http://do/', {
                        method: 'POST',
                        body: JSON.stringify({ accion: 'reservar', sorteoId, numero: item.numero, monto: item.monto })
                    })).json();

                    if (!reserva.ok) {
                        await revertirLote(sorteoStub, clienteStub, sorteoId, auth.id, aplicados);
                        return Response.json(
                            { ok: false, error: `Número ${item.numero}: ${reserva.error}` },
                            { status: 400 }
                        );
                    }

                    const debito = await (await clienteStub.fetch('http://do/', {
                        method: 'POST',
                        body: JSON.stringify({
                            accion: 'debitar_compra', clienteId: auth.id, sorteoId,
                            numero: item.numero, monto: item.monto
                        })
                    })).json();

                    if (!debito.ok) {
                        await sorteoStub.fetch('http://do/', {
                            method: 'POST',
                            body: JSON.stringify({ accion: 'liberar', sorteoId, numero: item.numero, monto: item.monto })
                        });
                        await revertirLote(sorteoStub, clienteStub, sorteoId, auth.id, aplicados);
                        return Response.json({ ok: false, error: debito.error }, { status: 400 });
                    }

                    aplicados.push({ numero: item.numero, monto: item.monto, compraId: debito.compraId });
                }

                return Response.json({ ok: true, saldo: consultaSaldo.saldo - totalSolicitado, totalComprado: totalSolicitado, compras: aplicados.length });
            }

            // ============================================================
            // COMPRAR UN NÚMERO
            // ============================================================
            if (path === '/api/comprar' && method === 'POST') {
                if (!auth || auth.tipo !== 'cliente') return noAutorizado();
                const { sorteoId, numero, monto } = await request.json();

                if (!numero || !monto || monto <= 0) {
                    return Response.json({ ok: false, error: 'Datos de compra inválidos' }, { status: 400 });
                }

                const sorteo = await env.DB.prepare('SELECT estado FROM sorteos WHERE id = ?')
                    .bind(sorteoId).first();
                if (!sorteo || sorteo.estado !== 'abierto') {
                    return Response.json({ ok: false, error: 'El sorteo no está abierto' }, { status: 400 });
                }

                // 1) Reservar cupo en el número (Durable Object del sorteo)
                const sorteoStub = env.SORTEO_DO.get(env.SORTEO_DO.idFromName(String(sorteoId)));
                const reserva = await (await sorteoStub.fetch('http://do/', {
                    method: 'POST',
                    body: JSON.stringify({ accion: 'reservar', sorteoId, numero, monto })
                })).json();

                if (!reserva.ok) {
                    return Response.json({ ok: false, error: reserva.error }, { status: 400 });
                }

                // 2) Debitar el saldo del cliente (Durable Object del cliente)
                const clienteStub = env.CLIENTE_DO.get(env.CLIENTE_DO.idFromName(String(auth.id)));
                const debito = await (await clienteStub.fetch('http://do/', {
                    method: 'POST',
                    body: JSON.stringify({ accion: 'debitar_compra', clienteId: auth.id, sorteoId, numero, monto })
                })).json();

                if (!debito.ok) {
                    // Compensar: liberar la reserva porque no se pudo cobrar
                    await sorteoStub.fetch('http://do/', {
                        method: 'POST',
                        body: JSON.stringify({ accion: 'liberar', sorteoId, numero, monto })
                    });
                    return Response.json({ ok: false, error: debito.error }, { status: 400 });
                }

                return Response.json({ ok: true, saldo: debito.saldo, compraId: debito.compraId });
            }

            // ============================================================
            // RECARGAR SALDO EN EFECTIVO (staff con permiso recargar_saldo)
            // ============================================================
            if (path === '/api/recargas/efectivo' && method === 'POST') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();
                if (!(await tienePermiso(env.DB, auth.id, auth.rol, 'recargar_saldo'))) return sinPermiso();

                const { clienteId, monto } = await request.json();
                const stub = env.CLIENTE_DO.get(env.CLIENTE_DO.idFromName(String(clienteId)));
                return stub.fetch('http://do/', {
                    method: 'POST',
                    body: JSON.stringify({
                        accion: 'recargar', clienteId, monto, tipo: 'recarga_efectivo', staffId: auth.id
                    })
                });
            }

            // ============================================================
            // SUBIR COMPROBANTE DE RECARGA (cliente, queda pendiente)
            // ============================================================
            if (path === '/api/recargas/comprobante' && method === 'POST') {
                if (!auth || auth.tipo !== 'cliente') return noAutorizado();
                const { monto, comprobanteUrl } = await request.json();
                await env.DB.prepare(
                    `INSERT INTO movimientos_saldo (cliente_id, tipo, monto, estado, comprobante_url)
                     VALUES (?, 'recarga_comprobante', ?, 'pendiente', ?)`
                ).bind(auth.id, monto, comprobanteUrl).run();
                return Response.json({ ok: true, mensaje: 'Comprobante enviado, queda pendiente de aprobación' });
            }

            // ============================================================
            // APROBAR RECARGA POR COMPROBANTE (staff con permiso aprobar_recargas)
            // ============================================================
            const matchAprobar = path.match(/^\/api\/recargas\/(\d+)\/aprobar$/);
            if (matchAprobar && method === 'POST') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();
                if (!(await tienePermiso(env.DB, auth.id, auth.rol, 'aprobar_recargas'))) return sinPermiso();

                const movimientoId = matchAprobar[1];
                const movimiento = await env.DB.prepare(
                    "SELECT * FROM movimientos_saldo WHERE id = ? AND estado = 'pendiente'"
                ).bind(movimientoId).first();
                if (!movimiento) {
                    return Response.json({ ok: false, error: 'Recarga no encontrada o ya procesada' }, { status: 404 });
                }

                const stub = env.CLIENTE_DO.get(env.CLIENTE_DO.idFromName(String(movimiento.cliente_id)));
                return stub.fetch('http://do/', {
                    method: 'POST',
                    body: JSON.stringify({
                        accion: 'aplicar_pendiente',
                        clienteId: movimiento.cliente_id,
                        monto: movimiento.monto,
                        movimientoId,
                        staffId: auth.id
                    })
                });
            }

            // ============================================================
            // RETIRO EN EFECTIVO (cajero paga el premio en físico)
            // ============================================================
            if (path === '/api/retiros' && method === 'POST') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();
                if (!(await tienePermiso(env.DB, auth.id, auth.rol, 'retirar_saldo'))) return sinPermiso();

                const { clienteId, monto } = await request.json();
                const stub = env.CLIENTE_DO.get(env.CLIENTE_DO.idFromName(String(clienteId)));
                return stub.fetch('http://do/', {
                    method: 'POST',
                    body: JSON.stringify({ accion: 'retirar', clienteId, monto, staffId: auth.id })
                });
            }

            // ============================================================
            // CERRAR SORTEO (staff con permiso gestionar_sorteos)
            // ============================================================
            const matchCerrar = path.match(/^\/api\/sorteos\/(\d+)\/cerrar$/);
            if (matchCerrar && method === 'POST') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();
                if (!(await tienePermiso(env.DB, auth.id, auth.rol, 'gestionar_sorteos'))) return sinPermiso();

                await env.DB.prepare("UPDATE sorteos SET estado = 'cerrado' WHERE id = ?")
                    .bind(matchCerrar[1]).run();
                return Response.json({ ok: true });
            }

            // ============================================================
            // REGISTRAR RESULTADO Y PAGAR PREMIOS AUTOMÁTICAMENTE
            // (staff con permiso registrar_resultado)
            // ============================================================
            const matchResultado = path.match(/^\/api\/sorteos\/(\d+)\/resultado$/);
            if (matchResultado && method === 'POST') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();
                if (!(await tienePermiso(env.DB, auth.id, auth.rol, 'registrar_resultado'))) return sinPermiso();

                const sorteoId = matchResultado[1];
                const { numeroGanador } = await request.json();

                const sorteo = await env.DB.prepare(
                    "SELECT * FROM sorteos WHERE id = ? AND estado = 'cerrado'"
                ).bind(sorteoId).first();
                if (!sorteo) {
                    return Response.json(
                        { ok: false, error: 'El sorteo debe estar cerrado antes de registrar el resultado' },
                        { status: 400 }
                    );
                }

                await env.DB.prepare(
                    `INSERT INTO resultados_sorteo (sorteo_id, numero_ganador, registrado_por_staff_id)
                     VALUES (?, ?, ?)`
                ).bind(sorteoId, numeroGanador, auth.id).run();

                const { results: ganadoras } = await env.DB.prepare(
                    `SELECT * FROM compras
                     WHERE sorteo_id = ? AND numero = ? AND estado = 'confirmada' AND premiada = 0`
                ).bind(sorteoId, numeroGanador).all();

                let totalPagado = 0;
                for (const compra of ganadoras) {
                    const premio = compra.monto * sorteo.multiplicador_pago;
                    const stub = env.CLIENTE_DO.get(env.CLIENTE_DO.idFromName(String(compra.cliente_id)));
                    await stub.fetch('http://do/', {
                        method: 'POST',
                        body: JSON.stringify({
                            accion: 'acreditar_premio',
                            clienteId: compra.cliente_id,
                            monto: premio,
                            compraId: compra.id
                        })
                    });
                    await env.DB.prepare('UPDATE compras SET premiada = 1 WHERE id = ?').bind(compra.id).run();
                    totalPagado += premio;
                }

                await env.DB.prepare("UPDATE sorteos SET estado = 'pagado' WHERE id = ?").bind(sorteoId).run();

                return Response.json({ ok: true, ganadores: ganadoras.length, totalPagado });
            }

            // ============================================================
            // CREAR BANCA (staff con permiso gestionar_sorteos)
            // ============================================================
            if (path === '/api/bancas' && method === 'POST') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();
                if (!(await tienePermiso(env.DB, auth.id, auth.rol, 'gestionar_sorteos'))) return sinPermiso();

                const { nombre, comisionPagarPct, comisionRecibirPct } = await request.json();
                const banca = await env.DB.prepare(
                    `INSERT INTO bancas (nombre, comision_pagar_pct, comision_recibir_pct)
                     VALUES (?, ?, ?) RETURNING id`
                ).bind(nombre, comisionPagarPct || 0, comisionRecibirPct || 0).first();
                return Response.json({ ok: true, bancaId: banca.id });
            }

            if (path === '/api/bancas' && method === 'GET') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();
                const { results } = await env.DB.prepare(
                    'SELECT * FROM bancas WHERE activa = 1'
                ).all();
                return Response.json({ ok: true, bancas: results });
            }

            // ============================================================
            // CREAR SORTEO (staff con permiso gestionar_sorteos)
            // ============================================================
            if (path === '/api/sorteos' && method === 'POST') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();
                if (!(await tienePermiso(env.DB, auth.id, auth.rol, 'gestionar_sorteos'))) return sinPermiso();

                const {
                    nombre, fecha, horaCierre, bancaId, multiplicadorPago,
                    tipoLimiteDefault, montoMaximoDefault,
                    porcentajeMaximoDefault, montoMinimoGarantizadoDefault
                } = await request.json();

                if (!nombre || !fecha || !horaCierre) {
                    return Response.json({ ok: false, error: 'Faltan datos del sorteo' }, { status: 400 });
                }

                const sorteo = await env.DB.prepare(
                    `INSERT INTO sorteos (
                        nombre, fecha, hora_cierre, banca_id, multiplicador_pago,
                        tipo_limite_default, monto_maximo_default,
                        porcentaje_maximo_default, monto_minimo_garantizado_default
                     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`
                ).bind(
                    nombre, fecha, horaCierre, bancaId || null, multiplicadorPago || 0,
                    tipoLimiteDefault || 'ninguno', montoMaximoDefault || null,
                    porcentajeMaximoDefault || null, montoMinimoGarantizadoDefault || 0
                ).first();

                return Response.json({ ok: true, sorteoId: sorteo.id });
            }

            // ============================================================
            // CONFIGURAR LÍMITE DE UN NÚMERO ESPECÍFICO DENTRO DE UN SORTEO
            // (staff con permiso gestionar_sorteos)
            // ============================================================
            const matchLimite = path.match(/^\/api\/sorteos\/(\d+)\/limites$/);
            if (matchLimite && method === 'POST') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();
                if (!(await tienePermiso(env.DB, auth.id, auth.rol, 'gestionar_sorteos'))) return sinPermiso();

                const sorteoId = matchLimite[1];
                const { numero, tipoLimite, montoMaximo, porcentajeMaximo, montoMinimoGarantizado } =
                    await request.json();

                if (!numero || !tipoLimite) {
                    return Response.json({ ok: false, error: 'Faltan datos del límite' }, { status: 400 });
                }

                await env.DB.prepare(
                    `INSERT INTO limites_numero (
                        sorteo_id, numero, tipo_limite, monto_maximo,
                        porcentaje_maximo, monto_minimo_garantizado
                     ) VALUES (?, ?, ?, ?, ?, ?)
                     ON CONFLICT(sorteo_id, numero) DO UPDATE SET
                        tipo_limite = excluded.tipo_limite,
                        monto_maximo = excluded.monto_maximo,
                        porcentaje_maximo = excluded.porcentaje_maximo,
                        monto_minimo_garantizado = excluded.monto_minimo_garantizado`
                ).bind(
                    sorteoId, numero, tipoLimite, montoMaximo || null,
                    porcentajeMaximo || null, montoMinimoGarantizado || 0
                ).run();

                return Response.json({ ok: true });
            }

            if (path === '/api/staff' && method === 'GET') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();
                if (!(await tienePermiso(env.DB, auth.id, auth.rol, 'gestionar_staff'))) return sinPermiso();

                const { results } = await env.DB.prepare(
                    'SELECT id, usuario, nombre, rol, activo FROM staff ORDER BY nombre ASC'
                ).all();
                return Response.json({ ok: true, staff: results });
            }

            // ============================================================
            // CREAR CUENTA DE STAFF (staff con permiso gestionar_staff)
            // ============================================================
            if (path === '/api/staff' && method === 'POST') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();
                if (!(await tienePermiso(env.DB, auth.id, auth.rol, 'gestionar_staff'))) return sinPermiso();

                const { usuario, password, nombre, rol, salarioBase, comisionIngresosPct } =
                    await request.json();

                if (!usuario || !password || !nombre || !rol) {
                    return Response.json({ ok: false, error: 'Faltan datos del staff' }, { status: 400 });
                }

                const existente = await env.DB.prepare('SELECT id FROM staff WHERE usuario = ?')
                    .bind(usuario).first();
                if (existente) {
                    return Response.json({ ok: false, error: 'Ese usuario ya existe' }, { status: 400 });
                }

                const passwordHash = await hashPassword(password);
                const nuevoStaff = await env.DB.prepare(
                    `INSERT INTO staff (usuario, password_hash, nombre, rol, salario_base, comision_ingresos_pct)
                     VALUES (?, ?, ?, ?, ?, ?) RETURNING id`
                ).bind(usuario, passwordHash, nombre, rol, salarioBase || 0, comisionIngresosPct || null).first();

                return Response.json({ ok: true, staffId: nuevoStaff.id });
            }

            if (path === '/api/permisos' && method === 'GET') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();
                const { results } = await env.DB.prepare('SELECT clave, descripcion FROM permisos').all();
                return Response.json({ ok: true, permisos: results });
            }

            // ============================================================
            // DAR/QUITAR UN PERMISO INDIVIDUAL A UN STAFF (override de rol)
            // (staff con permiso gestionar_staff)
            // ============================================================
            const matchPermiso = path.match(/^\/api\/staff\/(\d+)\/permisos$/);
            if (matchPermiso && method === 'POST') {
                if (!auth || auth.tipo !== 'staff') return noAutorizado();
                if (!(await tienePermiso(env.DB, auth.id, auth.rol, 'gestionar_staff'))) return sinPermiso();

                const staffId = matchPermiso[1];
                const { permisoClave, concedido } = await request.json();

                await env.DB.prepare(
                    `INSERT INTO staff_permisos (staff_id, permiso_clave, concedido)
                     VALUES (?, ?, ?)
                     ON CONFLICT(staff_id, permiso_clave) DO UPDATE SET concedido = excluded.concedido`
                ).bind(staffId, permisoClave, concedido ? 1 : 0).run();

                return Response.json({ ok: true });
            }

            return Response.json({ ok: false, error: 'Ruta no encontrada' }, { status: 404 });

        } catch (error) {
            return Response.json({ ok: false, error: error.message }, { status: 500 });
        }
}

function noAutorizado() {
    return Response.json({ ok: false, error: 'No autorizado, inicia sesión de nuevo' }, { status: 401 });
}

function sinPermiso() {
    return Response.json({ ok: false, error: 'No tienes permiso para esta acción' }, { status: 403 });
}

// Deshace las compras de un lote que ya se habían aplicado, porque una
// compra posterior en la misma lista falló (todo o nada).
async function revertirLote(sorteoStub, clienteStub, sorteoId, clienteId, aplicados) {
    for (const item of aplicados) {
        await sorteoStub.fetch('http://do/', {
            method: 'POST',
            body: JSON.stringify({ accion: 'liberar', sorteoId, numero: item.numero, monto: item.monto })
        });
        await clienteStub.fetch('http://do/', {
            method: 'POST',
            body: JSON.stringify({
                accion: 'revertir_compra', clienteId, monto: item.monto, compraId: item.compraId
            })
        });
    }
}
