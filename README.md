# Mindfuly

A simple web-based wellness tracker.

## Installation Steps

1. Make an `.env` file containing the following, and DO NOT check it into git:

```
POSTGRES_HOST=db
POSTGRES_USER=<some shared username>
POSTGRES_PASSWORD=<some shared password>
GITHUB_TOKEN=<some shared PAT token>
JWT_SECRET_KEY=<some secret JWT key>
WEATHER_API_KEY=<some shared weather API key>
YOUTUBE_API_KEY=<some shared YouTube API key>
```

2. Launch the application by running

```
$ docker compose watch
```

The service is now running on `localhost:8200/`.

If you edit any of the files in this repo, the server restarts to reflect your changes.

3. If you need to reset containers in any way, run

```
$ docker compose down
$ rm -rf ./volumes/db
$ docker compose watch
```