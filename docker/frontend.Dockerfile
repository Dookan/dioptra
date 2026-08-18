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

COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /srv/build/dist /usr/share/nginx/html

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
    CMD wget --spider -q http://127.0.0.1:8080/ || exit 1
