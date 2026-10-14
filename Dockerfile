FROM node:22-alpine
ENV NODE_ENV=production PORT=8080
RUN apk add --no-cache curl
WORKDIR /app
COPY --chown=node:node server.js ./
COPY --chown=node:node enc ./enc
USER node
EXPOSE 8080
CMD ["node", "server.js"]
