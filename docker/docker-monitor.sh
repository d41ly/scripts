#!/bin/bash

# Cron this to monitor your docker container status and send a webhook on a fail

# Define the webhook URL, change to your endpoint
WEBHOOK_URL="https://your.webhook.url/here"

# Initialize an empty payload string
PAYLOAD='['
FIRST=true

# Use process substitution to avoid subshell issues
while read line; do

    # If this isn't the first container, add a comma before the next one
    if [ "$FIRST" = true ]; then
        FIRST=false
    else
        PAYLOAD+=','
    fi

    # Parse the container information
    CONTAINER_NAME=$(echo $line | awk '{print $1}')
    CONTAINER_STATUS=$(echo $line | awk '{print $2}')
    CONTAINER_DURATION=$(echo $line | cut -d ' ' -f 3-)

    # Append to the payload string
    PAYLOAD+='{"container_name": "'"$CONTAINER_NAME"'", "status": "'"$CONTAINER_STATUS"'", "duration": "'"$CONTAINER_DURATION"'"}'
    
done < <(docker ps -a --format "{{.Names}} {{.Status}}" | grep "Exited")

# Close the JSON array
PAYLOAD+=']'

# Send webhook notification (only if there were exited containers)
if [ "$PAYLOAD" != "[]" ]; then
    curl -X POST $WEBHOOK_URL \
         -H "Content-Type: application/json" \
         -d "$PAYLOAD"
fi
