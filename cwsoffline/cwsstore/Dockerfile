# Stage 1: build the React storefront from source.
FROM node:22-alpine AS frontend
WORKDIR /store
COPY frontend/package.json frontend/package-lock.json ./frontend/
RUN cd frontend && npm ci --no-audit --no-fund
COPY frontend/ ./frontend/
RUN cd frontend && npm run build
# Build output lands in /store/app/static/app (vite.config outDir).

# Stage 2: the store runtime. No Node.js in the final image; the built
# frontend is plain static files served by FastAPI, so running the store
# needs no network access.
FROM python:3.12-slim

WORKDIR /store

ENV CWS_ARTIFACTS_DIR=/store/artifacts
ENV CWS_ASSETS_DIR=/store/assets
ENV CWS_INTAKE_DIR=/store/intake

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
# Freshly built frontend assets from stage 1 win over any committed copy.
COPY --from=frontend /store/app/static/app ./app/static/app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8005

ENTRYPOINT ["sh", "/entrypoint.sh"]
