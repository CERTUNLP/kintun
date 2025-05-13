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
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Instalar MongoDB Shell (mongosh) versión 7.0
RUN curl -fsSL https://pgp.mongodb.com/server-7.0.asc | gpg --dearmor -o /usr/share/keyrings/mongodb-server-7.0.gpg \
    && echo "deb [ signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/debian bookworm/mongodb-org/7.0 main" > /etc/apt/sources.list.d/mongodb-org-7.0.list \
    && apt update && apt install -y mongodb-mongosh \
    && rm -rf /var/lib/apt/lists/*

# Instalar dependencias Python
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código fuente
COPY . .

# Comando por defecto
CMD [ "python3", "-m", "flask", "run", "--host=0.0.0.0" ]
