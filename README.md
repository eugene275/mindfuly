# Mindfuly

A simple web-based wellness tracker.

## Installation Steps

1. Make an `.env` file containing the following, and DO NOT check it into git:

```
POSTGRES_HOST=db
POSTGRES_USER=<some shared username>
POSTGRES_PASSWORD=<some shared password>
```

2. Launch the application by running

```
$ docker compose watch
```

The service is now running on `localhost:8200/`.

If you edit any of the files in this repo, the server restarts to reflect your changes.