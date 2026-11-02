# Browser container: runs the untrusted extension. Has no route to anything except the gateway.
FROM rust:1.90-slim-bookworm AS geckodriver
RUN cargo install geckodriver --version 0.36.0 --locked --root /opt/gd

FROM python:3.11-slim-bookworm

ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN pip install "playwright==1.63.0" "selenium==4.51.0"
RUN playwright install --with-deps --no-shell chromium
RUN apt-get update \
    && apt-get install -y --no-install-recommends firefox-esr \
    && rm -rf /var/lib/apt/lists/*
COPY --from=geckodriver /opt/gd/bin/geckodriver /usr/local/bin/geckodriver

RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin sandbox \
    && mkdir -p /input /output /opt/extdrift \
    && chown sandbox:sandbox /input /output

COPY engine/__init__.py /opt/extdrift/engine/__init__.py
COPY engine/features/ /opt/extdrift/engine/features/
COPY engine/sandbox/ /opt/extdrift/engine/sandbox/

ENV PYTHONPATH=/opt/extdrift HOME=/tmp/home
WORKDIR /tmp
USER 1000:1000
ENTRYPOINT ["python", "-m", "engine.sandbox.container_runner"]
