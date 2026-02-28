#!/bin/bash
# AthenaPass - Quick Setup

set -e

DOCKER_NAME="athenapass"
IMAGE_NAME="athenapass"
VOLUME_NAME="athenapass-data"

echo "AthenaPass Docker Setup"
echo "==========================="

echo -e "\n[1] Building Docker image..."
sudo docker build -t $IMAGE_NAME .

echo -e "\n[2] Creating Docker volume..."
sudo docker volume create $VOLUME_NAME

echo -e "\n[3] Cleaning up old container..."
sudo docker rm -f $DOCKER_NAME

echo -e "\n[4] Starting container..."
CONTAINER_ID=$(sudo docker run -d \
  --name $DOCKER_NAME \
  -p 4134:4134 \
  -v $VOLUME_NAME:/app \
  $IMAGE_NAME)

echo "   Container ID: $CONTAINER_ID"

echo -e "\n[5] Waiting for server startup..."
sleep 3

if sudo docker ps | grep -q $DOCKER_NAME; then
    echo "   ✓ Container is running"
else
    echo "   ✗ Container failed to start"
    echo "   Logs:"
    sudo docker logs $DOCKER_NAME
    exit 1
fi