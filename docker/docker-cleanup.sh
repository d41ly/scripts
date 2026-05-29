#!/bin/bash

# Cron this script to clean older files up in your S3 storage (docker backups) via rclone 

# Variables, change to yours
BUCKET_NAME="YOURBUCKET"
REMOTE_NAME="YOURREMOTE"
PATH="your/path"
FILE_AGE=7

# rclone command to list files older than X days
echo "Files to be deleted:"
/usr/bin/rclone --min-age ${FILE_AGE}d ls ${REMOTE_NAME}:${BUCKET_NAME}/${PATH}

# rclone command to delete files older than X days
/usr/bin/rclone --min-age ${FILE_AGE}d delete ${REMOTE_NAME}:${BUCKET_NAME}/${PATH}

# rclone command to cleanup the bucket (remove empty directories)
# rclone rmdirs ${REMOTE_NAME}:${BUCKET_NAME}/${PATH}