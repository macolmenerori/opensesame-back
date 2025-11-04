# opensesame-back

An authentication API, the back part of the project.

Manage users and assign them roles and permissions to perform certain actions.

## Requirements

- MongoDB database set up and running ([MongoDB Atlas](https://www.mongodb.com/atlas) recommended)
- [Node JS](https://nodejs.org/en) `>=24.0.0`
- [yarn](https://yarnpkg.com/getting-started/install) `>=1.22`

## API Documentation

The API documentation can be found in openAPI format under `docs/openapi.yml`

## How to set up and run (Docker)

Easiest way to set up the project to use it right away.

### Requirements:

- [Docker](https://www.docker.com/) installed and running
- MongoDB database set up and running ([MongoDB Atlas](https://www.mongodb.com/atlas) recommended)

### Steps

1. Edit the file `config.env.example` with all the parameters, then rename it to `config.env`
2. Generate the Docker image

```
docker build -t opensesame-back:latest .
```

3. Run the Docker image

```
docker run -p 8080:8080 --name opensesame-back opensesame-back
```

## How to set up and run (Native)

For feature-testing and development.

### Requirements:

- Node JS
- yarn
- MongoDB database set up and running

### Steps

1. Edit the file `config.env.example` with all the parameters, then rename it to `config.env`
2. Install packages `yarn install`
3. Run the dev environment `yarn dev`

## Configuration

```
NODE_ENV=production # The environment, leave production for usage

PORT=8080 # Port in which the API will run
DB_NAME=opensesame # Name of the database
DATABASE=mongo_string # mongoDB database connection string

PASSWORD_HASH_DIFFICULTY=12 # The higher, the more seure the password will be stored but the slower it will be encoded/decoded
JWT_SECRET=pioedhgfjoi # Random string, just to sign the tokens
JWT_EXPIRES_IN=7d # The life of the issued JWT. 7 days in this example
JWT_COOKIE_EXPIRES_IN=7 # The life of the issued cookie. 7 days in this example

RATELIMIT_MAXCONNECTIONS=100 # Only allow 100 requests from the same IP
RATELIMIT_WINDOWMS=3600000 # Those previous 100 requests must have been in 1 hour
CORS_WHITELIST=http://localhost:3000,http://mydomain.net # Allowed domains by CORS, comma separated
```
