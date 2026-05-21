FROM node:22-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM node:22-alpine AS runtime

WORKDIR /app

ENV NODE_ENV=production
ENV FRONTEND_PORT=3000

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts \
	&& npm cache clean --force

COPY --from=build /app/server.js ./server.js
COPY --from=build /app/dist ./dist

EXPOSE 3000

CMD ["node", "server.js"]
