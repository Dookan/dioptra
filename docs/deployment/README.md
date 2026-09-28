# Dioptra — Despliegue / Deployment

> **Idiomas / Languages:** [Español](#español) · [English](#english)
>
> Excepción registrada a la regla "English everywhere" de `CLAUDE.md`: esta guía
> es bilingüe por pedido de `mmarin` (2026-09-24), porque la leen los operadores
> de la fábrica. / Recorded exception to CLAUDE.md's "English everywhere" rule:
> this guide is bilingual at `mmarin`'s request (2026-09-24), because the
> factory's operators read it.

---

# Español

## 1. Qué se despliega

Dioptra son **ocho servicios** Docker más **tres imágenes** que el worker lanza
por demanda:

| Servicio | Qué hace | Imagen |
|---|---|---|
| `frontend` | nginx: sirve la interfaz (React ya compilado) y reenvía `/api/` al backend | `docker/frontend.Dockerfile` |
| `api` | FastAPI: toda la lógica, la autenticación y las compuertas | `docker/api.Dockerfile` |
| `migrate` | Se ejecuta una vez al arrancar: aplica las migraciones y termina | `docker/api.Dockerfile` |
| `worker` | Ejecuta los análisis (E3) y la verificación en sandbox (E7). **Es el único con el socket de Docker** | `docker/api.Dockerfile` |
| `report-worker` | Genera los PDF del reporte. **Sin socket de Docker** | `docker/api.Dockerfile` |
| `postgres` | Base de datos (PostgreSQL 18). **Opcional**: puede ser un PostgreSQL instalado fuera de Docker (§12) | `postgres:18-alpine` |
| `valkey` | Cola de trabajos (Valkey 9, sustituto libre de Redis) | `valkey/valkey:9-alpine` |
| — | Contenedores efímeros de análisis: Semgrep, Gitleaks, OSV-Scanner, Syft, Lizard, cloc. Siempre con `--network none` | `dioptra-analysis:latest` |
| — | Sandbox de tests JS/TS y Python (E7). Siempre con `--network none` | `dioptra-sandbox:latest` |
| — | Sandbox de tests PHP (E7). Opcional si no se auditan sistemas PHP | `dioptra-sandbox-php:latest` |

## 2. Dos formas de desplegar

### A. Un solo servidor

Todo en una máquina: `docker compose -f docker/docker-compose.yml up -d --build`.
Es lo más simple; si es tu caso, sigue §4 y §5 saltando lo que dice "servidor
frontend".

### B. Frontend y backend en IPs distintas (recomendado para la fábrica)

```
                    Usuarios (navegador)
                           │  HTTPS :443
                           ▼
           ┌───────────────────────────────┐
           │ Proxy TLS de la institución   │  termina HTTPS (certificado institucional)
           └───────────────┬───────────────┘
                           │  HTTP :8080
                           ▼
 ┌───────────────────────────────────────────┐
 │ SERVIDOR FRONTEND   (ej. 10.0.0.10)        │
 │  nginx :8080                               │
 │   ├── /          → la interfaz (estática)  │
 │   └── /api/      → http://10.0.0.20:8000   │
 └───────────────────┬───────────────────────┘
                     │  HTTP :8000  (red interna; solo desde 10.0.0.10)
                     ▼
 ┌─────────────────────────────────────────────────────────────────┐
 │ SERVIDOR BACKEND    (ej. 10.0.0.20)                              │
 │  api :8000 ──► postgres :5432   (red interna de Docker, NO       │
 │   │   │        valkey   :6379    publicados fuera del servidor)  │
 │   │   └──────────────┐                                           │
 │   ▼                  ▼                                           │
 │  worker ──────────► valkey ◄────── report-worker                 │
 │   │  /var/run/docker.sock                                        │
 │   ▼                                                              │
 │  contenedores efímeros de análisis y sandbox  (--network none)   │
 │                                                                  │
 │  $DIOPTRA_DATA_DIR (/var/lib/dioptra): código subido, PDFs,      │
 │  ejecuciones del sandbox, base OSV — compartido por api/workers  │
 └──────────────────────────┬──────────────────────────────────────┘
                            │ HTTPS :443 saliente, SOLO si la sincronización
                            ▼ está activada (ver §8)
          osv-vulnerabilities.storage.googleapis.com · nvd.nist.gov
```

**Por qué se divide así y no de otra forma:**

- El navegador habla con **un solo origen** (el frontend). nginx reenvía `/api/`
  al backend, así que para el navegador la división no existe: la cookie de
  sesión sigue siendo `SameSite=Strict`, la CSP sigue siendo `default-src
  'self'` y **no hace falta CORS**. No expongas la API directamente a los
  usuarios.
- `api`, `worker` y `report-worker` **deben estar en el mismo servidor**: comparten
  `$DIOPTRA_DATA_DIR` (la API extrae ahí el código que el worker analiza, y el
  report-worker deja ahí el PDF que la API entrega). Valkey va con ellos, en la
  red interna de Docker. PostgreSQL también, **o en su propio servidor fuera de
  Docker** (§12).

## 3. Requisitos de los servidores

Cifras de partida para una fábrica pequeña (unos pocos analistas y
programadores). Los límites que las fundamentan son los valores por defecto de
`backend/app/core/config.py`: cada contenedor de análisis hasta **2 GB de RAM y
2 CPU**, cada sandbox **1 GB y 1 CPU**, y un PDF de ~500 páginas tarda **~50 s**
en generarse. No son medidas de carga; ajústalas con el uso real.

### Servidor backend

| Recurso | Mínimo | Recomendado |
|---|---|---|
| Sistema | Linux x86_64 (probado en Debian 13) | — |
| Docker | Docker Engine 24+ con Compose v2 | la versión estable más reciente |
| CPU | 4 vCPU | 8 vCPU |
| RAM | 8 GB | 16 GB |
| Disco | 60 GB SSD | 100 GB SSD o más |
| Red | IP fija en la LAN | — |

El disco se reparte así: ~4 GB de imágenes (análisis 1 GB, sandbox 0,7 GB,
sandbox PHP 0,75 GB, postgres 0,4 GB, más la imagen de la API), **más ~10 GB
libres durante la construcción** (caché de compilación), la base de datos, el
código extraído de cada análisis (se conserva mientras exista el análisis), la
base OSV local (0,2–1 GB según ecosistemas) y el espacio de PDFs (tope 2 GiB).

**Cada ZIP que se sube ocupa, mientras se analiza, su propio tamaño más el de
su código descomprimido.** Con los topes por defecto (1 GiB comprimido, 8 GiB
descomprimido) cuenta hasta ~9 GB por subida simultánea en
`DIOPTRA_DATA_DIR/workspaces`. El ZIP se borra en cuanto se descomprime; el
código descomprimido se queda mientras exista el análisis.

### Servidor frontend

| Recurso | Mínimo |
|---|---|
| Sistema | Linux x86_64 con Docker Engine 24+ y Compose v2 |
| CPU | 1 vCPU |
| RAM | 1 GB |
| Disco | 10 GB (la construcción usa Node; la imagen final pesa ~100 MB) |

### Construcción sin internet

`docker compose build` descarga imágenes base, paquetes npm y Python. En una red
aislada, construye en una máquina conectada y lleva las imágenes con
`docker save` / `docker load`. En ejecución, Dioptra **no carga nada de
internet** (ni CDN ni consultas en vivo).

## 4. Puertos y conexiones

| Origen | Destino | Puerto | Para qué | ¿Obligatorio? |
|---|---|---|---|---|
| Navegadores | Proxy TLS institucional | 443/tcp | la interfaz y la API, por HTTPS | sí |
| Proxy TLS | Servidor frontend | 8080/tcp (`DIOPTRA_HTTP_PORT`) | nginx | sí |
| Servidor frontend | Servidor backend | 8000/tcp (`DIOPTRA_API_PORT`) | `/api/` reenviado a la API | sí |
| api / workers | postgres | 5432/tcp | base de datos — **red interna de Docker, no se publica** | sí (base en contenedor) |
| api / workers / migrate | PostgreSQL externo | 5432/tcp (`DIOPTRA_DB_PORT`) | base de datos fuera de Docker (§12) | sí (base externa) |
| api / workers | valkey | 6379/tcp | cola — **red interna de Docker, no se publica** | sí |
| worker | socket de Docker | `/var/run/docker.sock` | lanzar los contenedores de análisis y sandbox | sí |
| worker | internet | 443/tcp saliente | sincronizar OSV + NVD | **no**: solo si `DIOPTRA_VULNDB_SYNC_ENABLED=true` |
| worker | servidor git | 443/tcp saliente | ingesta por URL git (HTTPS) | solo si se usa la ingesta por git |

**Reglas de firewall sugeridas**

- **Servidor backend**: aceptar 8000/tcp **solo desde la IP del frontend**.
  Nada más entrante (salvo SSH de administración). PostgreSQL y Valkey no se
  publican: no les abras puertos.

  > **Ojo: `ufw` (o una regla en la cadena INPUT) NO filtra un puerto
  > publicado por Docker.** Docker lo redirige antes de que INPUT lo vea, así
  > que con solo `ufw allow from <frontend>` el 8000 queda abierto a toda la
  > LAN. La regla que sí funciona va en la cadena `DOCKER-USER`:
  >
  > ```bash
  > sudo iptables -I DOCKER-USER -p tcp -m conntrack \
  >      --ctorigdst <IP backend> --ctorigdstport <DIOPTRA_API_PORT, ej. 8000> \
  >      ! --ctorigsrc <IP del frontend> -j DROP
  > ```
  >
  > Todo va sobre la conexión **original** (`--ctorig…`), no sobre el paquete:
  > `DOCKER-USER` ve también las respuestas de la API, que salen del contenedor
  > y no del frontend, así que una regla con `! -s <frontend>` las tiraría y el
  > frontend se quedaría colgado. Hazla persistente con `iptables-persistent` o
  > el equivalente en nftables; si publicas la API en una dirección IPv6, repite
  > la regla con `ip6tables`. Compruébalo en los dos sentidos:
  >
  > - desde el **frontend**: `curl http://<IP backend>:<DIOPTRA_API_PORT>/api/v1/health` responde;
  > - desde **otra máquina** de la LAN: el mismo `curl` se queda sin respuesta.
- **Servidor frontend**: aceptar 8080/tcp solo desde el proxy TLS.
- **Saliente del backend**: 443/tcp hacia los dos dominios de §8 si hay
  sincronización, y hacia el servidor git si se ingiere por URL.

> **Importante — git interno:** la ingesta por URL git **rechaza servidores en
> IPs privadas** (10.x, 172.16–31.x, 192.168.x, loopback). Es la protección
> contra SSRF (`docs/threat-model.md`). Si el GitLab/Gitea de la institución está
> en la LAN, sube el código como ZIP.

## 5. Instalación del servidor backend

```bash
# 1. El repositorio y la configuración
git clone <repositorio> dioptra && cd dioptra
cp .env.example .env
```

Edita `.env`:

| Variable | Valor |
|---|---|
| `DIOPTRA_ENV` | `prod` (desactiva `/api/docs` y el seed) |
| `DIOPTRA_JWT_SECRET` | `openssl rand -base64 48` (mínimo 32 caracteres) |
| `POSTGRES_PASSWORD` | `openssl rand -base64 48` — dueño del esquema, solo lo usa `migrate`. Va dentro de una URL: evita `%` y `@` |
| `DIOPTRA_APP_DB_PASSWORD` | `openssl rand -base64 48` — el rol con el que se conectan la API y los workers |
| `DIOPTRA_REFRESH_COOKIE_SECURE` | `true` (la cookie de sesión exige HTTPS) |
| `DIOPTRA_API_BIND` | la IP de LAN de **este** servidor, ej. `10.0.0.20` |
| `DIOPTRA_DATA_DIR` | `/var/lib/dioptra` |
| `DIOPTRA_DOCKER_GID` | salida de `stat -c %g /var/run/docker.sock` |
| `DIOPTRA_VULNDB_SYNC_ENABLED` | `true` con salida a internet, `false` en red aislada (§8) |
| `DIOPTRA_SEED_PASSWORD_*` | **vacías** en producción |

```bash
# 2. Directorios de datos (misma ruta en el servidor y en los contenedores)
sudo mkdir -p /var/lib/dioptra/{workspaces,osv,runs,vulndb,reports}
sudo chown -R 10001:10001 /var/lib/dioptra

# 3. Limitar el tamaño de las ejecuciones del sandbox (NO es opcional: un test
#    que escribe sin fin llenaría el disco, base de datos incluida)
sudo mount -t tmpfs -o size=512m,uid=10001,gid=10001,mode=0770 tmpfs /var/lib/dioptra/runs
#    y añádelo a /etc/fstab para que sobreviva al reinicio:
#    tmpfs /var/lib/dioptra/runs tmpfs size=512m,uid=10001,gid=10001,mode=0770 0 0

# 4. Base OSV local para el escaneo de dependencias (en una máquina con
#    internet; luego copia el directorio a /var/lib/dioptra/osv)
scripts/osv_db_download.sh /var/lib/dioptra/osv

# 5. Levantar todo menos el frontend, con la API publicada en DIOPTRA_API_BIND
docker compose -f docker/docker-compose.yml -f docker/docker-compose.backend.yml up -d --build
```

**Primer administrador.** En producción el seed está desactivado y todavía no
hay pantalla de usuarios (`tasks/phase6-user-administration.md`), así que la
primera cuenta se crea dentro del contenedor de la API. La contraseña se pide
sin mostrarse y la cuenta debe cambiarla en su primer ingreso:

```bash
docker compose -f docker/docker-compose.yml -f docker/docker-compose.backend.yml exec -it api python -c "
import getpass, app.db.registry
from app.auth.models import Role
from app.auth.service import create_user
from app.db.session import get_session_factory
s = get_session_factory()()
create_user(s, username='srosales', display_name='Saile Rosales', role=Role.ADMIN,
            password=getpass.getpass('Contraseña inicial: '))
s.commit(); print('cuenta creada')
"
```

Repite con `Role.ANALYST` / `Role.DEVELOPER` para las demás cuentas. Usuario =
inicial + apellido, minúsculas, sin puntos. Esta vía **no deja fila en la
bitácora**; la pantalla de administración de la fase 6 lo resolverá.

## 6. Instalación del servidor frontend

Solo necesita el repositorio y Docker. **Ningún secreto** del backend existe en
este servidor.

```bash
git clone <repositorio> dioptra && cd dioptra
DIOPTRA_API_UPSTREAM=http://10.0.0.20:8000 \
  docker compose -f docker/docker-compose.frontend.yml up -d --build
```

`DIOPTRA_API_UPSTREAM` es la dirección de la API en el servidor backend
(`DIOPTRA_API_BIND:DIOPTRA_API_PORT`). nginx escucha en `DIOPTRA_HTTP_PORT`
(8080 por defecto).

**Topes de subida.** nginx aplica su propia copia de los topes de la API:
`DIOPTRA_MAX_ZIP_MIB` (1024 por defecto) para el ZIP del código y
`DIOPTRA_VULNDB_MAX_DUMP_MIB` (1025) para el volcado de vulnerabilidades. Si
cambias `DIOPTRA_MAX_ZIP_BYTES` o `DIOPTRA_VULNDB_MAX_DUMP_BYTES` en el backend,
cambia también estos en el frontend: `DIOPTRA_MAX_ZIP_MIB × 1048576` debe ser
igual a `DIOPTRA_MAX_ZIP_BYTES`, y el del volcado lleva 1 MiB más por el
formulario. Si no coinciden, manda el menor.

`DIOPTRA_API_UPSTREAM` va **sin barra final** (`http://10.0.0.20:8000`, no
`…:8000/`): con barra, nginx se niega a arrancar ("proxy_pass cannot have URI
part in location given by regular expression").

**HTTPS.** nginx habla HTTP en el 8080. El proxy TLS de la institución debe
publicar `https://dioptra.<institución>` y reenviar al `http://10.0.0.10:8080`.
Sin HTTPS no se puede iniciar sesión en producción: la cookie de sesión es
`Secure`.

## 7. Comprobar que funciona

```bash
# Desde el servidor frontend: ¿llega a la API?
curl -s http://10.0.0.20:8000/api/v1/health
# Desde cualquier navegador de la LAN, a través de todo el camino:
curl -s https://dioptra.<institución>/api/v1/health
# Estado de los servicios en el backend
docker compose -f docker/docker-compose.yml -f docker/docker-compose.backend.yml ps
```

Luego entra con el administrador, crea un proyecto y sube un ZIP pequeño: si el
análisis termina, la cola, el worker y las imágenes de análisis funcionan.

## 8. Base de vulnerabilidades: con o sin internet

- **Con salida a internet** (`DIOPTRA_VULNDB_SYNC_ENABLED=true`): el worker
  descarga OSV y NVD cada `DIOPTRA_VULNDB_SYNC_INTERVAL_HOURS` (24 h) desde
  `osv-vulnerabilities.storage.googleapis.com` y `nvd.nist.gov`, solo HTTPS. Es
  **la única conexión saliente** de la plataforma.
- **Red aislada** (`false`): en el panel Inventario, "Importar base de
  vulnerabilidades" con los archivos descargados en otra máquina. La fecha de la
  última actualización siempre está visible.
- La base OSV del **escaneo de dependencias** (`/var/lib/dioptra/osv`, §5 paso
  4) es aparte: se refresca volviendo a ejecutar `scripts/osv_db_download.sh`.

## 9. Operación

| Tarea | Comando (en el backend) |
|---|---|
| Ver registros | `docker compose -f docker/docker-compose.yml -f docker/docker-compose.backend.yml logs -f api worker` |
| Respaldo de la base | `docker compose … exec postgres pg_dump -U dioptra dioptra > dioptra-$(date +%F).sql` |
| Respaldo de archivos | `/var/lib/dioptra/workspaces` (el código de cada análisis) |
| Actualizar | `git pull` y el mismo `up -d --build` en cada servidor; `migrate` aplica las migraciones nuevas |

## 10. Limitaciones conocidas

- **La IP en la bitácora es la del frontend**, no la del usuario: la API ignora
  `X-Forwarded-For` a propósito para que nadie pueda falsificar la bitácora
  (`backend/app/auth/deps.py::client_ip`).
- **El tramo frontend → backend va en HTTP** por la LAN y lleva tokens y
  contraseñas. Protégelo con el firewall de §4 (solo el frontend llega al
  8000, regla en `DOCKER-USER`) o con una VLAN dedicada. TLS en ese tramo no
  está construido.
- **Sin nginx delante, la API aplica sus topes igual.** Desde la fase 10 la
  API comprueba la sesión ANTES de leer el cuerpo y cuenta los bytes del ZIP
  mientras llegan (1 GiB por defecto), sin importar lo que diga la cabecera;
  el ZIP va al disco, no a la RAM. El volcado de vulnerabilidades también:
  se lee por partes, la justificación a memoria y el archivo directo al disco
  (1 GiB por defecto), y solo después de comprobar que quien lo sube es admin
  o analista.
- **Valkey no tiene contraseña**: por eso nunca se publica fuera de la red de
  Docker.
- **El worker tiene el socket de Docker**, equivalente a root en el backend. Es
  lo que le permite lanzar los análisis aislados; ningún otro servicio lo tiene.

## 11. Desarrollo local (`scripts/dev.sh`)

Para trabajar en el código, no para producción: la API con recarga automática y
Vite en la misma máquina, contra un PostgreSQL en Docker.

**Requisitos:** Docker, [uv](https://docs.astral.sh/uv/) (instala Python 3.13 y
el backend), Node.js 22 con npm, y un `.env` con `DIOPTRA_JWT_SECRET`,
`POSTGRES_PASSWORD` y las `DIOPTRA_SEED_PASSWORD_*` de las tres cuentas.

```bash
cd backend && uv sync && cd ../frontend && npm ci && cd ..   # una vez

scripts/dev.sh                 # API en :8000, interfaz en http://localhost:5173
scripts/dev.sh seed            # además crea srosales / mmarin / pperez
scripts/dev.sh workers         # cola real: Valkey + los dos workers de RQ
scripts/dev.sh seed workers    # los argumentos se combinan
scripts/dev.sh reset workers   # BORRA todo (base, cola, archivos subidos) y
                               # arranca de cero con las tres cuentas; pide
                               # escribir "delete" para confirmar
```

| Puerto (local) | Qué |
|---|---|
| 5173 | interfaz (Vite) — abre esta |
| 8000 | API (`/api/docs` disponible en dev) |
| 55432 | PostgreSQL de desarrollo (`dioptra-dev-pg`) |
| 56379 | Valkey de desarrollo (`dioptra-dev-valkey`, solo con `workers`) |

Los datos viven en `~/.cache/dioptra-dev`. Para que los análisis y la
verificación funcionen hacen falta las imágenes:
`docker compose -f docker/docker-compose.yml build analysis-image sandbox-image sandbox-php-image`.
Ctrl+C detiene todo. Tras una migración nueva, reinicia `dev.sh`.

## 12. Base de datos fuera de Docker

PostgreSQL puede estar instalado directamente en un servidor, el mismo backend
o uno propio, en lugar del contenedor `postgres`. La plataforma no cambia: solo
cambia a dónde apuntan las conexiones.

**Requisitos del servidor de base de datos:** PostgreSQL **18** (la versión con
la que se desarrolla y prueba; el contenedor usa `postgres:18-alpine`), 2 vCPU,
4 GB de RAM y disco SSD según el volumen de análisis (empieza con 20 GB).

### Paso 1: crear el dueño, la base y el rol de ejecución

Como superusuario del servidor (`postgres`). Esto lo hace solo el contenedor en
su primer arranque; un servidor externo no, así que se hace a mano **una vez,
antes del primer `up`**:

```bash
# El dueño del esquema (ejecuta las migraciones) y la base
# La contraseña se escribe en el prompt de \password, nunca en la línea de
# comandos (quedaría en el historial del shell y en la lista de procesos)
sudo -u postgres psql -c "CREATE ROLE dioptra LOGIN;"
sudo -u postgres psql -c "\password dioptra"   # pega POSTGRES_PASSWORD del .env
sudo -u postgres psql -c "CREATE DATABASE dioptra OWNER dioptra;"

# El rol con el que se conectan la API y los workers: el mismo script que usa
# el contenedor, con un psql cualquiera (lee la contraseña del entorno)
# (desde el clon del repositorio, en cualquier máquina que llegue al servidor)
DIOPTRA_APP_DB_PASSWORD='<DIOPTRA_APP_DB_PASSWORD del .env>' POSTGRES_USER=dioptra POSTGRES_DB=dioptra \
  psql -h <servidor-bd> -U postgres -v ON_ERROR_STOP=1 -d dioptra -f docker/initdb/01-runtime-role.sql
```

`dioptra_app` puede leer y escribir filas pero no es dueño de nada: no puede
borrar los triggers que hacen la bitácora inalterable. Esto está comprobado
sobre un PostgreSQL 18 vacío siguiendo exactamente estos pasos: la migración
completa, `dioptra_app` lee y escribe, y `DROP TRIGGER` responde "must be owner".

### Paso 2: dejar entrar a Dioptra

- `postgresql.conf`: `listen_addresses` debe incluir la IP por la que llegan los
  contenedores (la del servidor de base de datos en la LAN; si PostgreSQL está en
  el mismo backend, la del puente de Docker, normalmente `172.17.0.1`).
- `pg_hba.conf`: permite a `dioptra` y `dioptra_app` **solo** desde el backend,
  con contraseña cifrada:

  ```
  # base de datos en otro servidor: la IP del backend
  hostssl  dioptra  dioptra,dioptra_app  10.0.0.20/32     scram-sha-256
  # base de datos en el mismo backend: las redes de Docker
  host     dioptra  dioptra,dioptra_app  172.16.0.0/12    scram-sha-256
  ```

- Firewall del servidor de base de datos: 5432/tcp solo desde el backend.

### Paso 3: apuntar Dioptra a esa base

En el `.env` del backend:

| Variable | Valor |
|---|---|
| `DIOPTRA_DB_HOST` | IP del servidor de base de datos (ej. `10.0.0.30`), o `host.docker.internal` si PostgreSQL está en el mismo backend |
| `DIOPTRA_DB_PORT` | `5432` |
| `DIOPTRA_DB_SSLMODE` | **obligatoria** (sin ella `docker compose` se niega a arrancar). `verify-full` si la base está en otra máquina: cifra **y** comprueba que responde tu servidor. `require` solo cifra, no comprueba quién responde. `prefer` (o `disable`) solo en el mismo servidor |
| `DIOPTRA_DB_SSLROOTCERT` | con `verify-full`: la ruta, en el backend, del certificado de la CA que firmó el del servidor PostgreSQL (PEM) |
| `POSTGRES_USER`, `POSTGRES_DB`, `POSTGRES_PASSWORD`, `DIOPTRA_APP_DB_PASSWORD` | los mismos valores del paso 1 |

Y añade `docker/docker-compose.external-db.yml` al comando: apaga el contenedor
`postgres` y deja que los servicios arranquen sin esperarlo. Con `verify-full`
añade también `docker/docker-compose.external-db-ca.yml`, que monta la CA de
`DIOPTRA_DB_SSLROOTCERT` en solo lectura. Va en un archivo aparte a propósito:
PostgreSQL comprueba el certificado siempre que exista una CA, incluso con
`require` o `prefer`, así que montarla por defecto rompería una base en el
mismo servidor con un certificado autofirmado.

```bash
# backend con frontend aparte y base externa en otra máquina (verify-full)
docker compose -f docker/docker-compose.yml -f docker/docker-compose.backend.yml \
               -f docker/docker-compose.external-db.yml \
               -f docker/docker-compose.external-db-ca.yml up -d --build
# un solo servidor con base externa
docker compose -f docker/docker-compose.yml -f docker/docker-compose.external-db.yml up -d --build
```

### Respaldos

Con la base fuera de Docker, el respaldo es el del servidor:
`sudo -u postgres pg_dump dioptra > dioptra-$(date +%F).sql`, o la política de
respaldo que la institución ya tenga para sus bases.

---

# English

## 1. What gets deployed

Dioptra is **eight Docker services** plus **three images** the worker starts on
demand:

| Service | What it does | Image |
|---|---|---|
| `frontend` | nginx: serves the UI (prebuilt React) and forwards `/api/` to the backend | `docker/frontend.Dockerfile` |
| `api` | FastAPI: all the logic, authentication and gates | `docker/api.Dockerfile` |
| `migrate` | Runs once at start-up: applies the migrations and exits | `docker/api.Dockerfile` |
| `worker` | Runs analyses (E3) and sandbox verification (E7). **The only one with the Docker socket** | `docker/api.Dockerfile` |
| `report-worker` | Renders the report PDFs. **No Docker socket** | `docker/api.Dockerfile` |
| `postgres` | Database (PostgreSQL 18). **Optional**: it can be a PostgreSQL installed outside Docker (§12) | `postgres:18-alpine` |
| `valkey` | Job queue (Valkey 9, the free replacement for Redis) | `valkey/valkey:9-alpine` |
| — | Ephemeral analysis containers: Semgrep, Gitleaks, OSV-Scanner, Syft, Lizard, cloc. Always `--network none` | `dioptra-analysis:latest` |
| — | JS/TS and Python test sandbox (E7). Always `--network none` | `dioptra-sandbox:latest` |
| — | PHP test sandbox (E7). Optional if no PHP system is audited | `dioptra-sandbox-php:latest` |

## 2. Two ways to deploy

### A. One server

Everything on one machine: `docker compose -f docker/docker-compose.yml up -d --build`.
The simplest option; if it is yours, follow §4 and §5 and skip what says
"frontend server".

### B. Frontend and backend on different IPs (recommended for the factory)

See the diagram in the Spanish section (§2.B) — it is language-neutral. In
short: browsers → HTTPS 443 → the institution's TLS proxy → **frontend server**
(nginx :8080, e.g. 10.0.0.10) → HTTP :8000 over the internal network →
**backend server** (e.g. 10.0.0.20: api, worker, report-worker, postgres,
valkey, and the ephemeral containers).

**Why it is split this way and not another:**

- The browser talks to **one origin** (the frontend). nginx forwards `/api/` to
  the backend, so to the browser the split does not exist: the session cookie
  stays `SameSite=Strict`, the CSP stays `default-src 'self'`, and **no CORS is
  needed**. Do not expose the API to users directly.
- `api`, `worker` and `report-worker` **must share one server**: they share
  `$DIOPTRA_DATA_DIR` (the API extracts there the code the worker analyses, and
  the report worker leaves there the PDF the API hands out). Valkey sits with
  them, on Docker's internal network. So does PostgreSQL — **or on its own
  server outside Docker** (§12).

## 3. Server requirements

Starting figures for a small factory (a few analysts and developers). The
limits behind them are the defaults in `backend/app/core/config.py`: each
analysis container up to **2 GB RAM and 2 CPUs**, each sandbox **1 GB and 1
CPU**, and a ~500-page PDF takes **~50 s** to render. They are not load
measurements; adjust them to real use.

### Backend server

| Resource | Minimum | Recommended |
|---|---|---|
| OS | Linux x86_64 (tested on Debian 13) | — |
| Docker | Docker Engine 24+ with Compose v2 | latest stable |
| CPU | 4 vCPU | 8 vCPU |
| RAM | 8 GB | 16 GB |
| Disk | 60 GB SSD | 100 GB SSD or more |
| Network | fixed LAN IP | — |

Disk goes to: ~4 GB of images (analysis 1 GB, sandbox 0.7 GB, PHP sandbox
0.75 GB, postgres 0.4 GB, plus the API image), **plus ~10 GB free while
building** (build cache), the database, the extracted code of each analysis
(kept while the analysis exists), the local OSV data (0.2–1 GB depending on
ecosystems) and the PDF spool (capped at 2 GiB).

**Each uploaded ZIP takes, while it is analysed, its own size plus its
unpacked code.** With the default caps (1 GiB compressed, 8 GiB unpacked)
plan up to ~9 GB per concurrent upload in `DIOPTRA_DATA_DIR/workspaces`. The
ZIP is deleted as soon as it is unpacked; the unpacked code stays as long as
the analysis exists.

### Frontend server

| Resource | Minimum |
|---|---|
| OS | Linux x86_64 with Docker Engine 24+ and Compose v2 |
| CPU | 1 vCPU |
| RAM | 1 GB |
| Disk | 10 GB (the build uses Node; the final image is ~100 MB) |

### Building without internet

`docker compose build` pulls base images, npm and Python packages. On an
isolated network, build on a connected machine and move the images with
`docker save` / `docker load`. At runtime Dioptra **loads nothing from the
internet** (no CDN, no live lookups).

## 4. Ports and connections

| From | To | Port | Purpose | Required? |
|---|---|---|---|---|
| Browsers | Institution's TLS proxy | 443/tcp | the UI and the API, over HTTPS | yes |
| TLS proxy | Frontend server | 8080/tcp (`DIOPTRA_HTTP_PORT`) | nginx | yes |
| Frontend server | Backend server | 8000/tcp (`DIOPTRA_API_PORT`) | `/api/` forwarded to the API | yes |
| api / workers | postgres | 5432/tcp | database — **Docker internal network, never published** | yes (containerised DB) |
| api / workers / migrate | external PostgreSQL | 5432/tcp (`DIOPTRA_DB_PORT`) | database outside Docker (§12) | yes (external DB) |
| api / workers | valkey | 6379/tcp | queue — **Docker internal network, never published** | yes |
| worker | Docker socket | `/var/run/docker.sock` | start the analysis and sandbox containers | yes |
| worker | internet | 443/tcp outbound | sync OSV + NVD | **no**: only if `DIOPTRA_VULNDB_SYNC_ENABLED=true` |
| worker | git server | 443/tcp outbound | git URL ingest (HTTPS) | only if git ingest is used |

**Suggested firewall rules**

- **Backend server**: accept 8000/tcp **from the frontend's IP only**. Nothing
  else inbound (besides admin SSH). PostgreSQL and Valkey are not published:
  open no port for them.

  > **Beware: `ufw` (or a rule in the INPUT chain) does NOT filter a port
  > Docker publishes.** Docker redirects it before INPUT sees it, so with only
  > `ufw allow from <frontend>` port 8000 stays open to the whole LAN. The rule
  > that works goes in the `DOCKER-USER` chain:
  >
  > ```bash
  > sudo iptables -I DOCKER-USER -p tcp -m conntrack \
  >      --ctorigdst <backend IP> --ctorigdstport <DIOPTRA_API_PORT, e.g. 8000> \
  >      ! --ctorigsrc <frontend IP> -j DROP
  > ```
  >
  > Everything matches the **original** connection (`--ctorig…`), not the
  > packet: `DOCKER-USER` also sees the API's replies, which leave from the
  > container and not from the frontend, so a rule written with
  > `! -s <frontend>` would drop them and the frontend would hang. Make it
  > persistent with `iptables-persistent` or the nftables equivalent; if you
  > publish the API on an IPv6 address, repeat the rule with `ip6tables`. Check
  > it both ways:
  >
  > - from the **frontend**: `curl http://<backend IP>:<DIOPTRA_API_PORT>/api/v1/health` answers;
  > - from **another** LAN machine: the same `curl` gets no answer.
- **Frontend server**: accept 8080/tcp from the TLS proxy only.
- **Backend outbound**: 443/tcp to the two domains in §8 if syncing, and to the
  git server if ingesting by URL.

> **Important — internal git:** git URL ingest **refuses servers on private
> IPs** (10.x, 172.16–31.x, 192.168.x, loopback). That is the SSRF guard
> (`docs/threat-model.md`). If the institution's GitLab/Gitea is on the LAN,
> upload the code as a ZIP.

## 5. Installing the backend server

```bash
# 1. The repository and the configuration
git clone <repository> dioptra && cd dioptra
cp .env.example .env
```

Edit `.env`:

| Variable | Value |
|---|---|
| `DIOPTRA_ENV` | `prod` (disables `/api/docs` and the seed) |
| `DIOPTRA_JWT_SECRET` | `openssl rand -base64 48` (32 characters minimum) |
| `POSTGRES_PASSWORD` | `openssl rand -base64 48` — schema owner, used only by `migrate`. It goes inside a URL: avoid `%` and `@` |
| `DIOPTRA_APP_DB_PASSWORD` | `openssl rand -base64 48` — the role the API and workers connect as |
| `DIOPTRA_REFRESH_COOKIE_SECURE` | `true` (the session cookie requires HTTPS) |
| `DIOPTRA_API_BIND` | **this** server's LAN IP, e.g. `10.0.0.20` |
| `DIOPTRA_DATA_DIR` | `/var/lib/dioptra` |
| `DIOPTRA_DOCKER_GID` | output of `stat -c %g /var/run/docker.sock` |
| `DIOPTRA_VULNDB_SYNC_ENABLED` | `true` with internet egress, `false` on an isolated network (§8) |
| `DIOPTRA_SEED_PASSWORD_*` | **empty** in production |

```bash
# 2. Data directories (same path on the host and in the containers)
sudo mkdir -p /var/lib/dioptra/{workspaces,osv,runs,vulndb,reports}
sudo chown -R 10001:10001 /var/lib/dioptra

# 3. Bound the size of sandbox runs (NOT optional: a test that writes forever
#    would fill the disk, database included)
sudo mount -t tmpfs -o size=512m,uid=10001,gid=10001,mode=0770 tmpfs /var/lib/dioptra/runs
#    and add it to /etc/fstab so it survives a reboot:
#    tmpfs /var/lib/dioptra/runs tmpfs size=512m,uid=10001,gid=10001,mode=0770 0 0

# 4. Local OSV data for dependency scanning (on a machine with internet;
#    then copy the directory to /var/lib/dioptra/osv)
scripts/osv_db_download.sh /var/lib/dioptra/osv

# 5. Start everything but the frontend, with the API published on DIOPTRA_API_BIND
docker compose -f docker/docker-compose.yml -f docker/docker-compose.backend.yml up -d --build
```

**First administrator.** In production the seed is disabled and there is no
user screen yet (`tasks/phase6-user-administration.md`), so the first account
is created inside the API container. The password is prompted without echo
and the account must change it at first login:

```bash
docker compose -f docker/docker-compose.yml -f docker/docker-compose.backend.yml exec -it api python -c "
import getpass, app.db.registry
from app.auth.models import Role
from app.auth.service import create_user
from app.db.session import get_session_factory
s = get_session_factory()()
create_user(s, username='srosales', display_name='Saile Rosales', role=Role.ADMIN,
            password=getpass.getpass('Initial password: '))
s.commit(); print('account created')
"
```

Repeat with `Role.ANALYST` / `Role.DEVELOPER` for the other accounts. Username
= initial + last name, lowercase, no dots. This path **writes no audit-log
row**; the phase-6 administration screen will close that.

## 6. Installing the frontend server

It needs only the repository and Docker. **None** of the backend's secrets
exists on this server.

```bash
git clone <repository> dioptra && cd dioptra
DIOPTRA_API_UPSTREAM=http://10.0.0.20:8000 \
  docker compose -f docker/docker-compose.frontend.yml up -d --build
```

`DIOPTRA_API_UPSTREAM` is the API's address on the backend server
(`DIOPTRA_API_BIND:DIOPTRA_API_PORT`). nginx listens on `DIOPTRA_HTTP_PORT`
(8080 by default).

**Upload caps.** nginx applies its own copy of the API's caps:
`DIOPTRA_MAX_ZIP_MIB` (1024 by default) for the code ZIP and
`DIOPTRA_VULNDB_MAX_DUMP_MIB` (1025) for the vulnerability dump. If you change
`DIOPTRA_MAX_ZIP_BYTES` or `DIOPTRA_VULNDB_MAX_DUMP_BYTES` on the backend,
change these on the frontend too: `DIOPTRA_MAX_ZIP_MIB × 1048576` must equal
`DIOPTRA_MAX_ZIP_BYTES`, and the dump's carries 1 MiB more for the form. If
they differ, the smaller one decides.

`DIOPTRA_API_UPSTREAM` takes **no trailing slash** (`http://10.0.0.20:8000`,
not `…:8000/`): with one, nginx refuses to start ("proxy_pass cannot have URI
part in location given by regular expression").

**HTTPS.** nginx speaks HTTP on 8080. The institution's TLS proxy publishes
`https://dioptra.<institution>` and forwards to `http://10.0.0.10:8080`.
Without HTTPS nobody can sign in in production: the session cookie is
`Secure`.

## 7. Checking it works

```bash
# From the frontend server: does it reach the API?
curl -s http://10.0.0.20:8000/api/v1/health
# From any browser on the LAN, through the whole path:
curl -s https://dioptra.<institution>/api/v1/health
# Service status on the backend
docker compose -f docker/docker-compose.yml -f docker/docker-compose.backend.yml ps
```

Then sign in as the administrator, create a project and upload a small ZIP: if
the analysis finishes, the queue, the worker and the analysis images work.

## 8. Vulnerability database: with or without internet

- **With internet egress** (`DIOPTRA_VULNDB_SYNC_ENABLED=true`): the worker
  downloads OSV and NVD every `DIOPTRA_VULNDB_SYNC_INTERVAL_HOURS` (24 h) from
  `osv-vulnerabilities.storage.googleapis.com` and `nvd.nist.gov`, HTTPS only.
  It is **the platform's only outbound connection**.
- **Isolated network** (`false`): in the Inventario panel, "Importar base de
  vulnerabilidades" with the files downloaded on another machine. The date of
  the last update is always visible.
- The OSV data used by **dependency scanning** (`/var/lib/dioptra/osv`, §5 step
  4) is separate: refresh it by re-running `scripts/osv_db_download.sh`.

## 9. Operations

| Task | Command (on the backend) |
|---|---|
| Logs | `docker compose -f docker/docker-compose.yml -f docker/docker-compose.backend.yml logs -f api worker` |
| Database backup | `docker compose … exec postgres pg_dump -U dioptra dioptra > dioptra-$(date +%F).sql` |
| File backup | `/var/lib/dioptra/workspaces` (each analysis' code) |
| Upgrade | `git pull` and the same `up -d --build` on each server; `migrate` applies new migrations |

## 10. Known limitations

- **The IP in the audit log is the frontend's**, not the user's: the API
  deliberately ignores `X-Forwarded-For` so nobody can forge the trail
  (`backend/app/auth/deps.py::client_ip`).
- **The frontend → backend hop is plain HTTP** on the LAN and carries tokens
  and passwords. Protect it with the §4 firewall (only the frontend reaches
  8000, rule in `DOCKER-USER`) or a dedicated VLAN. TLS on that hop is not
  built.
- **Without nginx in front, the API still applies its caps.** Since phase 10
  the API checks the session BEFORE reading the body and counts the ZIP's
  bytes as they arrive (1 GiB by default), whatever the header says; the ZIP
  goes to disk, not to RAM. So does the vulnerability dump: it is read part by
  part, the justification to memory and the file straight to disk (1 GiB by
  default), and only after checking that whoever uploads it is an admin or an
  analyst.
- **Valkey has no password**: that is why it is never published outside
  Docker's network.
- **The worker holds the Docker socket**, which is root-equivalent on the
  backend. It is what lets it start the isolated analyses; no other service has
  it.

## 11. Local development (`scripts/dev.sh`)

For working on the code, not for production: the API with hot reload and Vite
on the same machine, against PostgreSQL in Docker.

**Requirements:** Docker, [uv](https://docs.astral.sh/uv/) (installs Python
3.13 and the backend), Node.js 22 with npm, and a `.env` with
`DIOPTRA_JWT_SECRET`, `POSTGRES_PASSWORD` and the `DIOPTRA_SEED_PASSWORD_*` of
the three accounts.

```bash
cd backend && uv sync && cd ../frontend && npm ci && cd ..   # once

scripts/dev.sh                 # API on :8000, UI on http://localhost:5173
scripts/dev.sh seed            # also creates srosales / mmarin / pperez
scripts/dev.sh workers         # a real queue: Valkey + the two RQ workers
scripts/dev.sh seed workers    # arguments combine
scripts/dev.sh reset workers   # WIPES everything (database, queue, uploads)
                               # and starts from zero with the three accounts;
                               # asks you to type "delete" to confirm
```

| Port (local) | What |
|---|---|
| 5173 | UI (Vite) — open this one |
| 8000 | API (`/api/docs` available in dev) |
| 55432 | development PostgreSQL (`dioptra-dev-pg`) |
| 56379 | development Valkey (`dioptra-dev-valkey`, only with `workers`) |

Data lives in `~/.cache/dioptra-dev`. Analyses and verification need the
images: `docker compose -f docker/docker-compose.yml build analysis-image sandbox-image sandbox-php-image`.
Ctrl+C stops everything. After a new migration, restart `dev.sh`.

## 12. Database outside Docker

PostgreSQL can be installed directly on a server, the backend itself or its
own, instead of the `postgres` container. The platform does not change: only
where the connections point does.

**Database server requirements:** PostgreSQL **18** (the version it is
developed and tested with; the container is `postgres:18-alpine`), 2 vCPU, 4 GB
RAM, and SSD disk sized to the analysis volume (start with 20 GB).

### Step 1: create the owner, the database and the runtime role

As the server's superuser (`postgres`). The container does this on its first
start; an external server does not, so it is done by hand **once, before the
first `up`**:

```bash
# The schema owner (runs the migrations) and the database
# The password is typed at the \password prompt, never on the command line
# (it would land in the shell history and the process list)
sudo -u postgres psql -c "CREATE ROLE dioptra LOGIN;"
sudo -u postgres psql -c "\password dioptra"   # paste POSTGRES_PASSWORD from .env
sudo -u postgres psql -c "CREATE DATABASE dioptra OWNER dioptra;"

# The role the API and the workers connect as: the same script the container
# uses, through any psql (it reads the password from the environment)
# (from the repository clone, on any machine that reaches the server)
DIOPTRA_APP_DB_PASSWORD='<DIOPTRA_APP_DB_PASSWORD from .env>' POSTGRES_USER=dioptra POSTGRES_DB=dioptra \
  psql -h <db-server> -U postgres -v ON_ERROR_STOP=1 -d dioptra -f docker/initdb/01-runtime-role.sql
```

`dioptra_app` can read and write rows but owns nothing: it cannot drop the
triggers that make the audit log append-only. This was checked on an empty
PostgreSQL 18 following exactly these steps: the migration completes,
`dioptra_app` reads and writes, and `DROP TRIGGER` answers "must be owner".

### Step 2: let Dioptra in

- `postgresql.conf`: `listen_addresses` must include the address the containers
  arrive on (the database server's LAN IP; if PostgreSQL is on the backend
  itself, Docker's bridge address, usually `172.17.0.1`).
- `pg_hba.conf`: allow `dioptra` and `dioptra_app` **only** from the backend,
  with hashed passwords:

  ```
  # database on another server: the backend's IP
  hostssl  dioptra  dioptra,dioptra_app  10.0.0.20/32     scram-sha-256
  # database on the backend itself: Docker's networks
  host     dioptra  dioptra,dioptra_app  172.16.0.0/12    scram-sha-256
  ```

- Database server firewall: 5432/tcp from the backend only.

### Step 3: point Dioptra at it

In the backend's `.env`:

| Variable | Value |
|---|---|
| `DIOPTRA_DB_HOST` | the database server's IP (e.g. `10.0.0.30`), or `host.docker.internal` if PostgreSQL is on the backend itself |
| `DIOPTRA_DB_PORT` | `5432` |
| `DIOPTRA_DB_SSLMODE` | **mandatory** (without it `docker compose` refuses to start). `verify-full` if the database is on another machine: it encrypts **and** checks that your server is the one answering. `require` only encrypts, it never checks who answers. `prefer` (or `disable`) on the same server only |
| `DIOPTRA_DB_SSLROOTCERT` | with `verify-full`: the path, on the backend, of the CA certificate that signed the PostgreSQL server's (PEM) |
| `POSTGRES_USER`, `POSTGRES_DB`, `POSTGRES_PASSWORD`, `DIOPTRA_APP_DB_PASSWORD` | the same values as in step 1 |

And add `docker/docker-compose.external-db.yml` to the command: it switches the
`postgres` container off and lets the services start without waiting for it.
With `verify-full` also add `docker/docker-compose.external-db-ca.yml`, which
mounts the CA at `DIOPTRA_DB_SSLROOTCERT` read-only. It is a separate file on
purpose: PostgreSQL checks the certificate whenever a CA file exists, even under
`require` or `prefer`, so mounting one by default would break a same-host
database with a self-signed certificate.

```bash
# backend with a separate frontend and an external database on another machine (verify-full)
docker compose -f docker/docker-compose.yml -f docker/docker-compose.backend.yml \
               -f docker/docker-compose.external-db.yml \
               -f docker/docker-compose.external-db-ca.yml up -d --build
# one server with an external database
docker compose -f docker/docker-compose.yml -f docker/docker-compose.external-db.yml up -d --build
```

### Backups

With the database outside Docker, the backup is the server's:
`sudo -u postgres pg_dump dioptra > dioptra-$(date +%F).sql`, or whatever
backup policy the institution already has for its databases.
