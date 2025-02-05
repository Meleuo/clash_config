#!/usr/local/bin/bash

while true
do
        cd /home/pGaTTTO4fyv90r/local/clash_config
        gunicorn -b 0.0.0.0:17894 main:app
        sleep 0.1
done