#!/bin/bash

docker-compose -f ./ops/docker-compose.yml build --no-cache ident
docker-compose -f ./ops/docker-compose.yml up -d
TAGS=integration ./ops/run_local_tests.sh
# docker-compose -f ./ops/docker-compose.yml down
docker volume rm ops_ident-db
