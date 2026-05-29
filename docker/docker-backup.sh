#!/bin/bash

# Cron this script to quickly backup docker volumes to an S3 storage via rclone. A remote should already be setup in rclone.
DATETIME=`date +%y%m%d-%H_%M_%S`
SRC=/var/lib/docker/volumes/
# Replace with your remote destination
DST=YOURREMOTE:YOURBUCKET/PATH
GIVENNAME=docker_backup
tarandzip(){
    tar -czf $GIVENNAME-$DATETIME.tar.gz $SRC
}
movetos3(){
    rclone move $GIVENNAME-$DATETIME.tar.gz $DST
}
if [ ! -z "$GIVENNAME" ]; then
    if tarandzip; then
        movetos3
    fi
fi
