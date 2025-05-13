FROM python:3.11-slim

WORKDIR /kintun
ENV DEBIAN_FRONTEND=noninteractive

# Instalar dependencias necesarias del sistema
RUN apt update && apt install -y --no-install-recommends \
    shelldap \
    expect \
    rpcbind \
    smbclient \
    dnsutils \
    ntp \
    netcat-traditional \
    redis-tools \
    postgresql-client \
    curl \
    nmap \
    wget \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Add MongoDB repository and install mongosh
RUN wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | apt-key add - \
    && echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-6.0.list \
    && apt update \
    && apt install -y mongodb-mongosh \
    && rm -rf /var/lib/apt/lists/*

# Instalar dependencias Python
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código fuente
COPY . .

# Comando por defecto
CMD [ "python3", "-m", "flask", "run", "--host=0.0.0.0" ]
