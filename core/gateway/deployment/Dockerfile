FROM metacubex/mihomo:v1.19.34@sha256:4c2495d705f152897a58eac410350f243835fd01ce2fe44949a571faa824d532 AS engine
FROM python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e
COPY --from=engine /mihomo /usr/local/bin/mihomo
COPY gateway.py /app/gateway.py
ENTRYPOINT ["python", "-B", "-u", "/app/gateway.py"]
