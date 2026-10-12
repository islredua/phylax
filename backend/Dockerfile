# Multi-stage build para imagen de desarrollo
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Dependencias de sistema para escáneres y clientes de red
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap \
      curl \
      ca-certificates \
      wget \
      jq \
      git \
      build-essential \
      libpq-dev \
      libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# nmap como usuario no root: capabilities de archivo para raw sockets (-sS, -O).
# Solo el contenedor worker-discovery recibe NET_RAW/NET_ADMIN (cap_add); en los demás
# nmap no se ejecuta. Sin capabilities, Phylax lo detecta y degrada a -sT.
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

# nuclei: descarga del release oficial de ProjectDiscovery
RUN NUCLEI_VERSION=3.3.5 && \
    curl -L "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip || true

# Grype: instalador oficial de Anchore
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

WORKDIR /app

# Instalar dependencias Python
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copiar el resto del código
COPY . .

# Usuario sin privilegios (uid 1000, coincide con el usuario típico de WSL/Linux para
# los bind mounts). Los volúmenes de datos se crean con su propiedad.
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin phylax \
    && mkdir -p /data/media /data/scan-results /data/cti-cache \
    && chown -R phylax:phylax /data
USER phylax

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
