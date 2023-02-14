# syntax=docker/dockerfile:1

FROM ubuntu:22.04
WORKDIR /kintun

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y \
    python3-pip \
    shelldap \
    expect \
    rpcbind \
    nmap \
    smbclient \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]

