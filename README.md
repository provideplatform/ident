# ident

[![Go Report Card](https://goreportcard.com/badge/github.com/provideplatform/ident)](https://goreportcard.com/report/github.com/provideplatform/ident)

Microservice for authn, authz and identity.

## Usage

See the [ident API Reference](https://docs.provide.services/ident).

## Run your own ident with Docker

Requires [Docker](https://www.docker.com/get-started)

```shell
/ops/docker-compose up
```

## Build and run your own ident from source

Requires [GNU Make](https://www.gnu.org/software/make), [Go](https://go.dev/doc/install), [Postgres](https://www.postgresql.org/download), [Redis](https://redis.io/docs/getting-started/installation)

```shell
make run_local
```

## Executables

The project comes with several wrappers/executables found in the `cmd`
directory.

|       Command        | Description                     |
|:--------------------:|---------------------------------|
|      **`api`**       | Runs the API server.            |
| **`api_accountant`** | Runs the API accountant server. |
|      `consumer`      | Runs a consumer.                |
|      `migrate`       | Runs migrations.                |
|        `sudo`        | Runs as sudo.                   |
