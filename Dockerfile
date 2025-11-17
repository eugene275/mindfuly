FROM python:3.13

COPY --from=ghcr.io/astral-sh/uv:0.8.22 /uv /uvx /bin/

COPY . /app
WORKDIR /app
RUN pip install -e .
RUN pip install python-jose[cryptography]

ARG GITHUB_TOKEN

RUN if [ -z "$GITHUB_TOKEN" ]; then \
        echo "ERROR: GITHUB_TOKEN is not set."; exit 1; \
    fi && \
    pip install --no-cache-dir \
    git+https://${GITHUB_TOKEN}@github.com/JovKun/user_service_v2.git@main

ENTRYPOINT ["./scripts/docker-entrypoint.sh"]
CMD ["uvicorn", "mindfuly.api:app", "--host", "0.0.0.0", "--port", "8200"]