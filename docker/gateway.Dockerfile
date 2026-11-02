# Gateway container: mitmproxy answering every request locally. Sits on the same no-route network.
FROM python:3.12-slim-bookworm

ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1

RUN pip install "mitmproxy==12.1.2"

RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin gateway \
    && mkdir -p /evidence /opt/extdrift \
    && chown gateway:gateway /evidence

COPY engine/__init__.py /opt/extdrift/engine/__init__.py
COPY engine/sandbox/__init__.py engine/sandbox/gateway_addon.py engine/sandbox/markers.py \
     engine/sandbox/replay.py engine/sandbox/synthetic_web.py engine/sandbox/testsite.py \
     engine/sandbox/scenarios.py engine/sandbox/preflight.py \
     /opt/extdrift/engine/sandbox/

ENV PYTHONPATH=/opt/extdrift HOME=/tmp/home
WORKDIR /tmp
USER 1000:1000
ENTRYPOINT ["sh", "-c", "python -m engine.sandbox.preflight --role gateway --out /evidence/preflight.json && exec mitmdump -q -s /opt/extdrift/engine/sandbox/gateway_addon.py --listen-port 8080 --set confdir=/tmp/mitm --set connection_strategy=lazy --set upstream_cert=false --set block_global=false --set body_size_limit=16m"]
