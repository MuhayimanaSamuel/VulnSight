# VulnSight Main Gateway & Frontend Production Dockerfile
FROM node:22-alpine AS build

WORKDIR /app

# Install build dependencies
COPY package*.json ./
RUN npm ci

# Copy source code and build client assets
COPY . .
RUN npm run build

# Production Runtime Stage
FROM node:22-alpine AS runner

WORKDIR /app

# Security: Non-root user
RUN addgroup -S vulnsight && adduser -S vulnsight -G vulnsight

ENV NODE_ENV=production \
    PORT=3000

COPY --from=build /app/package*.json ./
RUN npm ci --only=production

COPY --from=build /app/dist ./dist
COPY --from=build /app/server.ts ./server.ts
COPY --from=build /app/src/data ./src/data
COPY --from=build /app/src/types ./src/types

USER vulnsight

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/health || exit 1

CMD ["npx", "tsx", "server.ts"]
