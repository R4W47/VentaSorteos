# Ventas Clientes Worker

Sistema independiente (base de datos y Worker propios, sin conexión con
el sistema actual de vendedores) para que los clientes compren números
directamente con su saldo.

## Despliegue

1. Si aún no creaste la base de datos, hazlo primero (ver `schema.sql`):
   ```
   wrangler d1 create ventas-clientes-db
   ```
   Copia el `database_id` que te devuelve y pégalo en `wrangler.toml`.

2. Instala las dependencias del proyecto (no hay dependencias externas,
   solo necesitas Wrangler):
   ```
   npm install -g wrangler
   ```

3. Define el secreto para firmar los tokens de sesión (nunca lo pongas
   directo en `wrangler.toml`):
   ```
   wrangler secret put JWT_SECRET
   ```
   Pega cualquier texto largo y aleatorio cuando te lo pida.

4. Despliega:
   ```
   wrangler deploy
   ```

Wrangler te dará la URL pública del Worker (algo como
`https://ventas-clientes-worker.tu-cuenta.workers.dev`).

## Endpoints disponibles

| Método | Ruta | Quién | Descripción |
|---|---|---|---|
| POST | `/api/clientes/login` | público | Login de cliente, devuelve token |
| POST | `/api/clientes` | staff (cualquier rol) | Crea una cuenta de cliente (no es autoservicio) |
| POST | `/api/staff/login` | público | Login de staff, devuelve token |
| GET | `/api/sorteos` | cliente/staff | Lista sorteos abiertos |
| GET | `/api/clientes/saldo` | cliente | Consulta el saldo actual |
| POST | `/api/comprar` | cliente | Compra un número (valida saldo y límite) |
| POST | `/api/recargas/efectivo` | staff (`recargar_saldo`) | Recarga instantánea en efectivo |
| POST | `/api/recargas/comprobante` | cliente | Sube un comprobante, queda pendiente |
| POST | `/api/recargas/:id/aprobar` | staff (`aprobar_recargas`) | Aprueba una recarga pendiente |
| POST | `/api/retiros` | staff (`retirar_saldo`) | Retira efectivo del saldo del cliente |
| POST | `/api/sorteos/:id/cerrar` | staff (`gestionar_sorteos`) | Cierra el sorteo a nuevas compras |
| POST | `/api/sorteos/:id/resultado` | staff (`registrar_resultado`) | Registra el número ganador y paga premios |
| POST | `/api/bancas` | staff (`gestionar_sorteos`) | Crea una banca externa (con % de comisión) |
| GET | `/api/bancas` | staff | Lista las bancas activas |
| POST | `/api/sorteos` | staff (`gestionar_sorteos`) | Crea un sorteo nuevo |
| POST | `/api/sorteos/:id/limites` | staff (`gestionar_sorteos`) | Configura el límite de un número específico |
| POST | `/api/staff` | staff (`gestionar_staff`) | Crea una cuenta de staff (cajero, supervisor, etc.) |
| POST | `/api/staff/:id/permisos` | staff (`gestionar_staff`) | Otorga o revoca un permiso individual a un staff |

Todas las rutas privadas requieren el encabezado:
```
Authorization: Bearer <token>
```

## Probar con curl (ejemplo de flujo completo)

```bash
# 1. Crear un cliente
curl -X POST https://TU-WORKER.workers.dev/api/clientes/registro \
  -H "Content-Type: application/json" \
  -d '{"usuario":"juan","password":"1234","nombre":"Juan Perez"}'

# 2. Un staff (ya creado directo en D1) recarga saldo en efectivo
curl -X POST https://TU-WORKER.workers.dev/api/recargas/efectivo \
  -H "Authorization: Bearer TOKEN_DEL_STAFF" \
  -H "Content-Type: application/json" \
  -d '{"clienteId":1,"monto":500}'

# 3. El cliente compra un número
curl -X POST https://TU-WORKER.workers.dev/api/comprar \
  -H "Authorization: Bearer TOKEN_DEL_CLIENTE" \
  -H "Content-Type: application/json" \
  -d '{"sorteoId":1,"numero":"23","monto":100}'
```

## Pendientes para la siguiente ronda

- Los sorteos todavía se crean uno por uno a mano vía `/api/sorteos`.
  Falta definir si conviene generarlos automáticamente cada día según
  un horario fijo (ej. una tarea programada que cree la "Diaria 11am"
  todos los días sin que nadie tenga que crearla a mano).
- El envío del comprobante de recarga asume que `comprobanteUrl` ya es
  un enlace a una imagen subida en otro lugar (ej. R2 de Cloudflare).
  Falta definir dónde y cómo se sube esa imagen.
- No hay todavía un panel visual (solo los endpoints) — falta construir
  la interfaz web para clientes y para staff.
