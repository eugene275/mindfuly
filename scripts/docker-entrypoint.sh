#!/bin/bash

alembic upgrade head

sed -i 's/\r$//' scripts/docker-entrypoint.sh

exec "$@"
