# syntax=docker/dockerfile:1

FROM ubuntu:22.04
WORKDIR /kintun

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y \
    python3-pip \
    shelldap \
    expect \
    rpcbind \
    smbclient \
    wget \
    dnsutils \
    ntp \
    build-essential \
    libssl-dev \
    gnupg \
    netcat \
    redis-tools \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Add MongoDB repository and install mongosh
RUN wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | apt-key add - \
    && echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-6.0.list \
    && apt update \
    && apt install -y mongodb-mongosh \
    && rm -rf /var/lib/apt/lists/*

# Download and install Nmap 7.94
RUN wget https://nmap.org/dist/nmap-7.94.tgz \
    && tar -xzvf nmap-7.94.tgz \
    && cd nmap-7.94 \
    && ./configure \
    && make \
    && make install \
    && cd .. \
    && rm -rf nmap-7.94 nmap-7.94.tgz

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]
