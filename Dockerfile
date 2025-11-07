FROM python:3.13

COPY --from=ghcr.io/astral-sh/uv:0.8.22 /uv /uvx /bin/

COPY . /app
WORKDIR /app
RUN pip install -e .

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

ENTRYPOINT ["./scripts/docker-entrypoint.sh"]
CMD ["uvicorn", "mindfuly.api:app", "--host", "0.0.0.0", "--port", "8200"]