FROM node:24-alpine AS build
WORKDIR /app
ENV API_INTERNAL_URL=http://api:8000 NEXT_TELEMETRY_DISABLED=1
COPY package*.json ./
RUN npm install --no-audit --no-fund
COPY . .
RUN npm run build
FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production HOSTNAME=0.0.0.0
# The runtime only executes server.js; npm/corepack are build-time tools and
# their bundled dependency trees are unnecessary attack surface in production.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
    /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
USER node
EXPOSE 3000
CMD ["node", "server.js"]
