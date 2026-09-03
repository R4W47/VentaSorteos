// =====================================================================
// ClienteBalance (Durable Object)
// Una instancia por cliente. Cloudflare garantiza que todas las
// solicitudes a la MISMA instancia se procesan una por una, en orden —
// eso es lo que evita que dos compras/recargas simultáneas del mismo
// cliente dejen el saldo en un estado incorrecto.
// =====================================================================
export class ClienteBalance {
    constructor(state, env) {
        this.state = state;
        this.env = env;
    }

    async fetch(request) {
        const { accion, ...datos } = await request.json();

        // El saldo vive en el storage propio del Durable Object.
        // La primera vez que se usa esta instancia, se carga desde D1.
        let saldo = await this.state.storage.get('saldo');
        if (saldo === undefined) {
            const cliente = await this.env.DB.prepare(
                'SELECT saldo FROM clientes WHERE id = ?'
            ).bind(datos.clienteId).first();
            saldo = cliente ? cliente.saldo : 0;
            await this.state.storage.put('saldo', saldo);
        }

        switch (accion) {
            case 'consultar':
                return Response.json({ ok: true, saldo });

            // Recarga nueva (efectivo en el puesto): se aplica al instante
            case 'recargar': {
                const nuevoSaldo = saldo + datos.monto;
                await this.state.storage.put('saldo', nuevoSaldo);
                await this.env.DB.prepare('UPDATE clientes SET saldo = ? WHERE id = ?')
                    .bind(nuevoSaldo, datos.clienteId).run();
                await this.env.DB.prepare(
                    `INSERT INTO movimientos_saldo (cliente_id, tipo, monto, estado, staff_id)
                     VALUES (?, ?, ?, 'aplicado', ?)`
                ).bind(datos.clienteId, datos.tipo, datos.monto, datos.staffId || null).run();
                return Response.json({ ok: true, saldo: nuevoSaldo });
            }

            // Aplica una recarga por comprobante que ya estaba en `pendiente`
            // (no inserta una fila nueva, solo actualiza la existente)
            case 'aplicar_pendiente': {
                const nuevoSaldo = saldo + datos.monto;
                await this.state.storage.put('saldo', nuevoSaldo);
                await this.env.DB.prepare('UPDATE clientes SET saldo = ? WHERE id = ?')
                    .bind(nuevoSaldo, datos.clienteId).run();
                await this.env.DB.prepare(
                    "UPDATE movimientos_saldo SET estado = 'aplicado', staff_id = ? WHERE id = ?"
                ).bind(datos.staffId, datos.movimientoId).run();
                return Response.json({ ok: true, saldo: nuevoSaldo });
            }

            // Compra de un número: valida saldo suficiente antes de descontar
            case 'debitar_compra': {
                if (saldo < datos.monto) {
                    return Response.json({ ok: false, error: 'Saldo insuficiente' }, { status: 400 });
                }
                const nuevoSaldo = saldo - datos.monto;
                await this.state.storage.put('saldo', nuevoSaldo);
                await this.env.DB.prepare('UPDATE clientes SET saldo = ? WHERE id = ?')
                    .bind(nuevoSaldo, datos.clienteId).run();
                const compra = await this.env.DB.prepare(
                    `INSERT INTO compras (cliente_id, sorteo_id, numero, monto)
                     VALUES (?, ?, ?, ?) RETURNING id`
                ).bind(datos.clienteId, datos.sorteoId, datos.numero, datos.monto).first();
                await this.env.DB.prepare(
                    `INSERT INTO movimientos_saldo (cliente_id, tipo, monto, estado)
                     VALUES (?, 'compra', ?, 'aplicado')`
                ).bind(datos.clienteId, -datos.monto).run();
                return Response.json({ ok: true, saldo: nuevoSaldo, compraId: compra.id });
            }

            // Pago automático de premio al cliente ganador
            case 'acreditar_premio': {
                const nuevoSaldo = saldo + datos.monto;
                await this.state.storage.put('saldo', nuevoSaldo);
                await this.env.DB.prepare('UPDATE clientes SET saldo = ? WHERE id = ?')
                    .bind(nuevoSaldo, datos.clienteId).run();
                await this.env.DB.prepare(
                    `INSERT INTO movimientos_saldo (cliente_id, tipo, monto, estado, referencia_compra_id)
                     VALUES (?, 'premio_pagado', ?, 'aplicado', ?)`
                ).bind(datos.clienteId, datos.monto, datos.compraId).run();
                return Response.json({ ok: true, saldo: nuevoSaldo });
            }

            // Retiro en efectivo: el cajero le entrega el dinero al cliente
            case 'retirar': {
                if (saldo < datos.monto) {
                    return Response.json({ ok: false, error: 'Saldo insuficiente para retirar' }, { status: 400 });
                }
                const nuevoSaldo = saldo - datos.monto;
                await this.state.storage.put('saldo', nuevoSaldo);
                await this.env.DB.prepare('UPDATE clientes SET saldo = ? WHERE id = ?')
                    .bind(nuevoSaldo, datos.clienteId).run();
                await this.env.DB.prepare(
                    `INSERT INTO movimientos_saldo (cliente_id, tipo, monto, estado, staff_id)
                     VALUES (?, 'retiro_efectivo', ?, 'aplicado', ?)`
                ).bind(datos.clienteId, -datos.monto, datos.staffId).run();
                return Response.json({ ok: true, saldo: nuevoSaldo });
            }

            // Revierte una compra ya aplicada (usado cuando una compra en
            // lote falla a mitad de camino y hay que deshacer las anteriores)
            case 'revertir_compra': {
                const nuevoSaldo = saldo + datos.monto;
                await this.state.storage.put('saldo', nuevoSaldo);
                await this.env.DB.prepare('UPDATE clientes SET saldo = ? WHERE id = ?')
                    .bind(nuevoSaldo, datos.clienteId).run();
                await this.env.DB.prepare("UPDATE compras SET estado = 'anulada' WHERE id = ?")
                    .bind(datos.compraId).run();
                await this.env.DB.prepare(
                    `INSERT INTO movimientos_saldo (cliente_id, tipo, monto, estado, referencia_compra_id)
                     VALUES (?, 'reversion', ?, 'aplicado', ?)`
                ).bind(datos.clienteId, datos.monto, datos.compraId).run();
                return Response.json({ ok: true, saldo: nuevoSaldo });
            }

            default:
                return Response.json({ ok: false, error: 'Acción no reconocida' }, { status: 400 });
        }
    }
}
