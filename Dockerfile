FROM node:22-alpine
LABEL app="opensesame-back" stack.binary="node" stack.version="22-alpine"

WORKDIR /usr/app

# Dockerfile config.env* means that if no config.env file is present, Dockerfile will be copied instead
COPY Dockerfile config.env* ./
COPY src src
COPY package.json ./
COPY yarn.lock ./
COPY .eslintignore ./
COPY .eslintrc.js ./
COPY .npmrc ./
COPY .prettierrc ./
COPY tsconfig.json ./

RUN yarn install --frozen-lockfile
RUN yarn build

EXPOSE 8080

HEALTHCHECK --interval=120s --retries=2 --start-period=5m --timeout=30s CMD wget -q -O- http://localhost:8080/healthcheck || exit 1

CMD ["yarn", "start"]
