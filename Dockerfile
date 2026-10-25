# VaultDrop — tiny image: Node only, zero npm dependencies.
FROM node:22-bookworm-slim
ENV NODE_ENV=production DATA_DIR=/data TRUST_PROXY=1 PORT=3000
WORKDIR /app
COPY package.json server.js ./
COPY public ./public
RUN mkdir -p /data
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/api/state').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "--disable-warning=ExperimentalWarning", "server.js"]
