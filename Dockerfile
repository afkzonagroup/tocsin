# syntax=docker/dockerfile:1
# Tocsin — NIS2 incident register. Copyright 2026 MB AFKzona Group. AGPL-3.0-only.
# Base image pinned by version and digest; Dependabot keeps it current.
FROM node:22.23.4-alpine3.24@sha256:0e1754758c2df4cfa3e68d59e2e1b7374bb7fd9ea6328eaaacf15cc934af8202 AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

FROM node:22.23.4-alpine3.24@sha256:0e1754758c2df4cfa3e68d59e2e1b7374bb7fd9ea6328eaaacf15cc934af8202
# No runtime dependencies are needed; remove the package managers to shrink the attack surface.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn* /usr/local/bin/yarn /usr/local/bin/yarnpkg \
 && mkdir -p /data && chown node:node /data && chmod 700 /data
ENV NODE_ENV=production \
    TOCSIN_STORE=/data/tocsin-store.tocsin \
    TOCSIN_CONFIG=/data/tocsin.config.json
WORKDIR /app
COPY --from=build /src/dist ./dist
COPY bin ./bin
COPY package.json LICENSE LICENSE-ADDITIONAL-TERMS.md ./
USER node
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["node", "/app/bin/tocsin.js"]
# Inside the container the UI must listen on all interfaces; publish it on the host's loopback only:
#   docker run -p 127.0.0.1:8080:8080 ...
CMD ["ui", "--host", "0.0.0.0", "--port", "8080", "--allow-non-loopback", "--allowed-host", "127.0.0.1:8080", "--allowed-host", "localhost:8080"]
