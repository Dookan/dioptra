# Frontend image: build the bundle, then serve it as static files.
#
# The browser talks only to this origin; nginx forwards /api to the backend.
# No script, style or font is ever fetched from a third-party host.

FROM node:22-slim AS build

WORKDIR /srv/build

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

FROM nginx:1.29-alpine AS runtime

# A template, rendered by the nginx entrypoint into conf.d/default.conf at start.
COPY docker/nginx.conf /etc/nginx/templates/default.conf.template
# Where /api/ is forwarded. Same host (Compose): the `api` service. Separate
# hosts: the backend's LAN address, e.g. -e DIOPTRA_API_UPSTREAM=http://10.0.0.20:8000
ENV DIOPTRA_API_UPSTREAM=http://api:8000
COPY --from=build /srv/build/dist /usr/share/nginx/html

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
    CMD wget --spider -q http://127.0.0.1:8080/ || exit 1
