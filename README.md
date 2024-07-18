# opensesame-back

An authentication API, the back part of the project.

Manage users and assign them roles and permissions to perform certain actions.

## Requirements

- mongoDB database set up and running
- Node JS `>=20.15.0`
- [yarn](https://yarnpkg.com/getting-started/install) `>=1.22`

## API Documentation

The API documentation can be found in openAPI format under `docs/openapi.yml`

## How to set up and run (Docker, easy)

1. Edit the file `config.env.example` with all the parameters, then rename it to `config.env`
2. Generate the Docker image

```
docker build -t opensesame-back:latest .
```

3. Run the Docker image

```
docker run --name opensesame-back opensesame-back
```

## How to set up and run (Native)

[TBD]

## Configuration

```
NODE_ENV=production # The environment, leave production for usage

PORT=3000 # Port in which the API will run
DB_NAME=opensesame # Name of the database
DATABASE=mongo_string # mongoDB database connection string

PASSWORD_HASH_DIFFICULTY=12 # The higher, the more seure the password will be stored but the slower it will be encoded/decoded
JWT_SECRET=pioedhgfjoi # Random string, just to sign the tokens
JWT_EXPIRES_IN=7d # The life of the issued JWT. 7 days in this example
JWT_COOKIE_EXPIRES_IN=7 # The life of the issued cookie. 7 days in this example

RATELIMIT_MAXCONNECTIONS=100 # Only allow 100 requests from the same IP
RATELIMIT_WINDOWMS=3600000 # Those previous 100 requests must have been in 1 hour
```
