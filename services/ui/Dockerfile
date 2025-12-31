FROM node:18-alpine AS builder

# Show progress during npm operations
ENV NPM_CONFIG_PROGRESS=true
ENV NPM_CONFIG_LOGLEVEL=info

WORKDIR /app

# Copy package files first (better layer caching)
# Copy package files first (better layer caching)
COPY package.json package-lock.json* ./

# DEBUG: List files to verify lockfile presence
RUN ls -la

# DEBUG: Check network connectivity
RUN ping -c 3 registry.npmjs.org || echo "WARN: registry.npmjs.org not reachable via ping"

# Use npm ci for faster, cleaner installs (falls back to npm install if no lock file)
RUN if [ -f package-lock.json ]; then \
    echo "🚀 Using npm ci (fast mode)..." && npm ci --verbose; \
    else \
    echo "📦 Installing dependencies (slow mode)..." && npm install --verbose; \
    fi

COPY . .
RUN echo "🔨 Building production bundle..." && npm run build

FROM nginx:alpine

# Scoped project label for cleanup
LABEL project="samnet-wg"

# Copy both configs
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx-https.conf /etc/nginx/conf.d/https.conf.template
COPY nginx-lan.conf /etc/nginx/conf.d/lan.conf.template

# Entrypoint script to select config based on NGINX_MODE and substitute API_PORT
# With --network=host, we use 127.0.0.1 (localhost) for API connection
RUN echo '#!/bin/sh' > /docker-entrypoint.d/40-select-config.sh && \
    echo 'API_PORT=${API_PORT:-8766}' >> /docker-entrypoint.d/40-select-config.sh && \
    echo 'if [ "$NGINX_MODE" = "https" ]; then' >> /docker-entrypoint.d/40-select-config.sh && \
    echo '  cat /etc/nginx/conf.d/https.conf.template | sed "s/127.0.0.1:8766/127.0.0.1:$API_PORT/g" > /etc/nginx/conf.d/default.conf' >> /docker-entrypoint.d/40-select-config.sh && \
    echo 'else' >> /docker-entrypoint.d/40-select-config.sh && \
    echo '  cat /etc/nginx/conf.d/lan.conf.template | sed "s/127.0.0.1:8766/127.0.0.1:$API_PORT/g" > /etc/nginx/conf.d/default.conf' >> /docker-entrypoint.d/40-select-config.sh && \
    echo 'fi' >> /docker-entrypoint.d/40-select-config.sh && \
    chmod +x /docker-entrypoint.d/40-select-config.sh

EXPOSE 80 443
CMD ["nginx", "-g", "daemon off;"]
