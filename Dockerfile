FROM node:20.15.1-alpine
LABEL app="mywebpage" stack.binary="node" stack.version="20.15.1-alpine"

WORKDIR /usr/app

COPY config.env ./
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

CMD ["yarn", "start"]
