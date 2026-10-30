# The web build is the same on every architecture, so it runs natively on the build machine.
FROM --platform=$BUILDPLATFORM node:24-alpine AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html tsconfig.json tsconfig.app.json tsconfig.node.json vite.config.ts ./
COPY shared ./shared
COPY src ./src
COPY public ./public
RUN npm run build

FROM node:24-alpine AS runtime

ENV NODE_ENV=production \
    TS_HOST=0.0.0.0 \
    TS_PORT=8797 \
    TS_DATA_DIR=/data

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY server ./server
COPY shared ./shared
# The bundled zero-breach indicator set, its signed manifest and the key the updater pins.
COPY third_party ./third_party
# The endpoint agent, served to computers that enroll (/agent/theyspy-agent.py).
COPY agent ./agent
COPY --from=build /app/dist ./dist

# /data holds the database; BoxPilot mounts its volume here and backs it up.
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 8797

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${TS_PORT}/healthz" >/dev/null || exit 1

CMD ["node", "server/index.mjs"]
