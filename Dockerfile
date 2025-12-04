FROM node:24-alpine
LABEL app="opensesame-back" stack.binary="node" stack.version="24-alpine"

WORKDIR /usr/app

# Dockerfile config.env* means that if no config.env file is present, Dockerfile will be copied instead
COPY Dockerfile config.env* ./
COPY src src
COPY package.json ./
COPY pnpm-lock.yaml ./
COPY .eslintignore ./
COPY .eslintrc.js ./
COPY .npmrc ./
COPY .prettierrc ./
COPY tsconfig.json ./

RUN pnpm i --frozen-lockfile
RUN pnpm build

EXPOSE 8080

HEALTHCHECK --interval=120s --retries=2 --start-period=5m --timeout=30s CMD wget -q -O- http://localhost:8080/healthcheck || exit 1

CMD ["pnpm", "start"]
