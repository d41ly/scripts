#!/bin/bash

# Use this shell script to quickly update specific docker containers to the lastest image releases

# Configuration, replace with your values
container_name="name"
image_name="image/image:latest"
email_address="your@email.com"

# Function to send email
send_email() {
    subject=$1
    body=$2
    echo -e "Subject:${subject}\n\n${body}" | sendmail ${email_address}
}

# Check if the container is running
if docker ps | grep -q ${container_name}; then
    echo "Container is running, stopping and removing..."
    docker stop ${container_name}
    docker rm ${container_name}
else
    echo "Container is not running. Removing if exists..."
fi

# Remove the existing image
docker rmi ${image_name}

# Execute docker run command, replace with your arguments
docker run -d \
 --name ${container_name} \
 --add-host=internal:host-gateway \
 --restart unless-stopped \
 ${image_name}

# Wait for a minute to let the container stabilize
echo "Waiting for the container to stabilize..."
sleep 30

# Check if the container is running successfully
container_status=$(docker inspect --format="{{.State.Status}}" ${container_name})
if [ "${container_status}" == "running" ]; then
    echo "Container is running successfully."
    send_email "Docker container update success" "The docker container ${container_name} has been updated and is running successfully."
else
    echo "Container failed to start."
    send_email "Docker container update failure" "The docker container ${container_name} failed to start. Check it manually."
fi