FROM node:22-alpine AS base

RUN corepack enable && corepack prepare pnpm@9 --activate
WORKDIR /app

# Install dependencies
FROM base AS deps
COPY package.json pnpm-lock.yaml* ./
COPY packages ./packages
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile

# Development stage
FROM deps AS development
COPY . .
ENV NODE_ENV=development
EXPOSE 3000
CMD ["pnpm", "dev"]

# Build stage
FROM deps AS builder
COPY . .
RUN pnpm build

# Production stage
FROM node:22-alpine AS production
RUN corepack enable && corepack prepare pnpm@9 --activate

WORKDIR /app
ENV NODE_ENV=production

# Copy production dependencies
COPY package.json pnpm-lock.yaml* ./
COPY packages ./packages
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --prod

# Copy built files
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/src/views ./dist/views

# Security: run as non-root
RUN addgroup -g 1001 -S nodejs && \
    adduser -S oauth -u 1001 -G nodejs && \
    chown -R oauth:nodejs /app
USER oauth

EXPOSE 3000
CMD ["node", "dist/index.js"]
