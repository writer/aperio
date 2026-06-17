# syntax=docker/dockerfile:1.7

FROM node:20-bookworm AS node_deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM golang:1.25-bookworm AS go_builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/aperio ./cmd/aperio \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/ingestion-worker ./cmd/ingestion-worker \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/siem-dispatcher ./cmd/siem-dispatcher \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/google-workspace-poller ./cmd/google-workspace-poller \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/google-workspace-bigquery-sync ./cmd/google-workspace-bigquery-sync \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/google-workspace-directory-sync ./cmd/google-workspace-directory-sync \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/google-workspace-oauth-sync ./cmd/google-workspace-oauth-sync

FROM node_deps AS web_builder
WORKDIR /app
COPY . .
RUN npm run db:generate && NEXT_TELEMETRY_DISABLED=1 npm run build:web

FROM node:20-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    APERIO_CONNECT_ADDR=:4100 \
    APERIO_API_PROXY_TARGET=http://127.0.0.1:4100 \
    NEXT_PUBLIC_CONNECT_API_BASE_URL=
COPY --from=node_deps /app/node_modules ./node_modules
COPY --from=web_builder /app/apps/web/.next ./apps/web/.next
COPY --from=web_builder /app/apps/web/next.config.mjs ./apps/web/next.config.mjs
COPY --from=web_builder /app/package.json /app/package-lock.json ./
COPY --from=web_builder /app/packages ./packages
COPY --from=web_builder /app/prisma.config.ts ./
COPY --from=web_builder /app/scripts ./scripts
COPY --from=go_builder /out/* /usr/local/bin/
COPY scripts/runtime-entrypoint.sh /usr/local/bin/aperio-runtime
RUN chmod +x /usr/local/bin/aperio-runtime
EXPOSE 3000 4100
ENTRYPOINT ["/usr/local/bin/aperio-runtime"]
CMD ["web"]
