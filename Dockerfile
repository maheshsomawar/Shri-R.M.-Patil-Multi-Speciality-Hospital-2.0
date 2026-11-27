FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080 \
    DEBUG=false

# Create non-root user for container hardening
RUN useradd --create-home --shell /usr/sbin/nologin hospital
WORKDIR /app

COPY server.py db.py migrations.py backup_db.py db_optimize.py ./
COPY public ./public

RUN mkdir -p /app/data /app/backups && chown -R hospital:hospital /app
USER hospital

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3)" || exit 1

CMD ["python3", "server.py"]
