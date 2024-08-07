# Docker Dynamic Upstreams for Caddy.

This package implements a docker dynamic upstreams module for Caddy.

This is a fork which puts more emphasis on using the Caddyfile for routing instead of container labels.

Requires Caddy 2+.

## Installation

Download from [official website](https://caddyserver.com/download?package=github.com%2Fv4violet%2Fcaddy-docker-upstreams)
or build yourself using [xcaddy](https://github.com/caddyserver/xcaddy).

Here is a Dockerfile example.

```dockerfile
FROM caddy:<version>-builder AS builder

RUN xcaddy build \
    --with github.com/v4violet/caddy-docker-upstreams

FROM caddy:<version>

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

## Caddyfile Syntax

```caddy
example.com {
  reverse_proxy /api/* {
    dynamic docker "api"
  }

  reverse_proxy {
    dynamic docker "frontend"
  }
}
```

## Docker Labels

This module requires the Docker Labels to provide the necessary information.

| Label           | Description                                                                                                                                                                                             |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `caddy`         | required, should match the label in the Caddyfile (eg. `caddy=api` matches upstream definition of `dynamic docker "api"`)                                                                               |
| `caddy.network` | optional but suggested if your container is attached to multiple networks, specify the docker network which caddy connecting through (if it is empty, the first network of container will be specified) |
| `caddy.port`    | optional unless the plugin cant auto detect the port                                                                                                                                                    |

## Docker Client

Environment variables could configure the docker client:

- `DOCKER_HOST` to set the URL to the docker server.
- `DOCKER_API_VERSION` to set the version of the API to use, leave empty for latest.
- `DOCKER_CERT_PATH` to specify the directory from which to load the TLS certificates ("ca.pem", "cert.pem", "key.pem').
- `DOCKER_TLS_VERIFY` to enable or disable TLS verification (off by default).
