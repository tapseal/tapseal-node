# TAPSEAL soft node: indexer + API + site in one small image. Light mode by default (no Bitcoin node needed).
#   docker compose up -d              (see docker-compose.yml)
#   docker run -d -p 8090:8090 -v tapseal:/data tapseal-node      → http://localhost:8090
FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/tapseal
COPY app/api/package.json app/api/package-lock.json app/api/
RUN cd app/api && npm ci --omit=dev --no-audit --no-fund --loglevel=error && npm cache clean --force
COPY app/ app/
RUN chmod +x app/bin/tapseal-node && ln -s /opt/tapseal/app/bin/tapseal-node /usr/local/bin/tapseal-node \
 && useradd --system --home /data --uid 10001 tapseal && mkdir -p /data && chown tapseal /data
USER tapseal
ENV TAPSEAL_HOME=/data TAPSEAL_APP=/opt/tapseal/app
VOLUME /data
EXPOSE 8090
# First start configures the node from the seed (or from TAPSEAL_INIT_ARGS), then runs it.
CMD ["sh", "-c", "[ -f /data/node.json ] || tapseal-node init --public ${TAPSEAL_INIT_ARGS:-}; exec tapseal-node start"]
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s CMD node -e "fetch('http://127.0.0.1:8090/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
