# Containerfile
FROM registry.access.redhat.com/ubi9-minimal:latest

ARG PYTHON=python3
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    DB_PATH=/data/monitor.db \
    MONITOR_INTERVAL=300


RUN microdnf -y install \
      python3 \
      python3-pip \
      iputils \
      traceroute \
      nmap \
    && microdnf -y clean all \
    && pip3 --no-cache-dir install --upgrade pip


WORKDIR /app
COPY requirements.txt .
RUN pip3 --no-cache-dir install -r requirements.txt

COPY app.py ./app.py
COPY templates ./templates


RUN mkdir -p /data \
 && chgrp -R 0 /app /data \
 && chmod -R g=u /app /data

EXPOSE 8000

USER 1001

CMD ["python3", "app.py"]
