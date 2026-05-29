#!/bin/bash

# This script follows instructions from https://docs.docker.com/engine/install/ubuntu/

# Check if the user is root
if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

echo "Starting Docker installation on Ubuntu 22.04..."

# 1. Uninstall old versions
echo "Removing any old versions of Docker..."
$SUDO apt-get remove -y docker docker-engine docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc

# Update package list
echo "Updating package list..."
$SUDO apt-get update

# 2. Install necessary packages to allow apt to use a repository over HTTPS
echo "Installing prerequisite packages..."
$SUDO apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release
	
$SUDO install -m 0755 -d /etc/apt/keyrings

# 3. Add Docker’s official GPG key
echo "Adding Docker’s official GPG key..."
$SUDO curl -fsSL https://download.docker.com/linux/ubuntu/gpg  -o /etc/apt/keyrings/docker.asc
$SUDO chmod a+r /etc/apt/keyrings/docker.asc

# 4. Set up the stable repository
echo "Setting up Docker repository..."
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  $SUDO tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update the package list to include Docker packages
echo "Updating package list to include Docker packages..."
$SUDO apt-get update

# 5. Install the latest version of Docker Engine, CLI, and containerd
echo "Installing Docker Engine..."
$SUDO apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 6. Verify the installation by running the hello-world image
echo "Verifying Docker installation..."
$SUDO docker run hello-world

# Check if the hello-world image is running
if $SUDO docker ps -a | grep -q hello-world; then
    echo "Docker is installed and the hello-world container ran successfully."
    # Remove the hello-world container
    echo "Cleaning up the hello-world container..."
    $SUDO docker rm $(docker ps -a -q --filter ancestor=hello-world)
    echo "Docker installation verified and clean-up complete."
else
    echo "Docker installation or hello-world run failed."
    exit 1
fi

echo "Docker installation script completed."