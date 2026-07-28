# syntax=docker/dockerfile:1

# ---- Stage 1: build -----------------------------------------------------
# Compilers and headers live here only. Nothing from this stage reaches the
# published image except the finished virtualenv, so the shipped container
# has no toolchain in it for anyone who gets a shell to use.
FROM python:3.13-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# A self-contained virtualenv is the unit copied across stages. Copying
# site-packages out of the system Python would drag its console scripts and
# path assumptions along with it.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Only the runtime manifest. Test and lint tooling has no business in a
# production image, which is why requirements-dev.txt is a separate file.
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ---- Stage 2: runtime ---------------------------------------------------
FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# This service makes outbound requests to hosts chosen by whoever uses it.
# It has no reason to hold root, and a fixed high UID keeps the numeric
# owner stable if the image is ever run against a mounted volume.
RUN useradd --create-home --uid 10001 netgrade

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=netgrade:netgrade . .

USER netgrade

EXPOSE 8000

# Shell form, so ${PORT} resolves at container start. Fly and Railway inject
# the port they expect the process to listen on; a hardcoded 8000 passes
# locally and then fails health checks on Railway.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import os,sys,urllib.request; p=os.getenv('PORT','8000'); sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+p+'/health', timeout=2).status == 200 else 1)"

# exec, so uvicorn replaces the shell and becomes PID 1. Without it sh holds
# PID 1, SIGTERM on redeploy is delivered to the shell rather than to uvicorn,
# and the platform kills the container after its grace period every time.
CMD ["sh", "-c", "exec uvicorn netgrade.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
