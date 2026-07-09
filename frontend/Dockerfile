FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --legacy-peer-deps || npm install --legacy-peer-deps --no-audit --no-fund

FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN mkdir -p public

ARG NEXT_PUBLIC_API_URL=http://localhost:8080/api/v1
ARG NEXT_PUBLIC_API_PORT=18080
ARG NEXT_PUBLIC_DEPLOY_ENV=production
ARG NEXT_PUBLIC_ENABLE_DEMO_MODE=false
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_API_PORT=$NEXT_PUBLIC_API_PORT
ENV NEXT_PUBLIC_DEPLOY_ENV=$NEXT_PUBLIC_DEPLOY_ENV
ENV NEXT_PUBLIC_ENABLE_DEMO_MODE=$NEXT_PUBLIC_ENABLE_DEMO_MODE

RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

RUN mkdir -p public
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

CMD ["node", "server.js"]
