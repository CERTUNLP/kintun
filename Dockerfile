FROM python:3.13.3-slim

WORKDIR /kintun

# Configurar entorno no interactivo
ENV DEBIAN_FRONTEND=noninteractive

# Instalar dependencias necesarias, incluyendo MongoDB Shell (mongosh) y Nmap
RUN apt update && apt install -y --no-install-recommends \
    shelldap \
    expect \
    rpcbind \
    smbclient \
    wget \
    dnsutils \
    ntp \
    netcat-traditional \
    redis-tools \
    postgresql-client \
    nmap \
    curl \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Add MongoDB repository and install mongosh
RUN curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | \
   gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg \
   --dearmor \
    && echo "deb [ signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] http://repo.mongodb.org/apt/debian bookworm/mongodb-org/8.0 main" | tee /etc/apt/sources.list.d/mongodb-org-8.0.list \
    && apt update \
    && apt install -y mongodb-mongosh \
    && rm -rf /var/lib/apt/lists/*

# Instalar dependencias de Python
COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

# Copiar el código fuente
COPY . .

# Comando por defecto
CMD [ "python3", "-m", "flask", "run", "--host=0.0.0.0" ]