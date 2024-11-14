#!/bin/bash

CONFIG_FILE="config.json"
EXAMPLE_CONFIG_FILE="config.json.example"
ENV_FILE=".env"
EXAMPLE_ENV_FILE=".env.example"

if [ ! -f "$CONFIG_FILE" ]; then
  echo "Warning: $CONFIG_FILE not found."
  echo "Please copy $EXAMPLE_CONFIG_FILE to $CONFIG_FILE and configure it before starting Kintun."
  echo "You can do this with the following command:"
  echo "    cp $EXAMPLE_CONFIG_FILE $CONFIG_FILE"
  echo "Then, open $CONFIG_FILE and update your MongoDB and other settings as needed."
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  echo "Warning: $ENV_FILE not found."
  echo "Please copy $EXAMPLE_ENV_FILE to $ENV_FILE and configure it before starting Kintun."
  echo "You can do this with the following command:"
  echo "    cp $EXAMPLE_ENV_FILE $ENV_FILE"
  echo "Then, open $ENV_FILE and update your environment variables as needed."
  exit 1
fi

echo "$CONFIG_FILE and $ENV_FILE found. Verifying configuration..."

MONGO_HOST=$(jq -r '.databases.mongodb.host' "$CONFIG_FILE")
MONGO_PORT=$(jq -r '.databases.mongodb.port' "$CONFIG_FILE")

echo "Using MongoDB server at $MONGO_HOST:$MONGO_PORT"
echo "If this is incorrect, please update the 'host' and 'port' values in $CONFIG_FILE."

read -p "Do you want to start Kintun with Docker? (y/n): " USE_DOCKER

if [ "$USE_DOCKER" = "y" ]; then
  if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed. Please install Docker and try again."
    exit 1
  fi

  if ! docker compose version &> /dev/null; then
    echo "Error: Docker Compose plugin is not available. Please install Docker Compose and try again."
    exit 1
  fi

  echo "Starting Kintun with Docker..."
  docker compose up
else
  echo "Starting Kintun locally with Python..."

  if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install it and try again."
    exit 1
  fi

  if ! command -v pip3 &> /dev/null; then
    echo "Error: pip is not installed. Please install it and try again."
    exit 1
  fi

  echo "Installing required Python packages..."
  pip3 install -r requirements.txt

  echo "Installing system dependencies..."
  sudo apt update
  sudo apt install -y shelldap expect rpcbind smbclient wget dnsutils ntp build-essential libssl-dev gnupg netcat redis-tools mongodb-mongosh nmap

  python3 app.py
fi