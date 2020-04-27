#!/bin/bash

./ops/run_api.sh &
./ops/run_api_accountant.sh &
GOLDMINE_API_HOST=localhost:8080 GOLDMINE_API_SCHEME=http ./ops/run_consumer.sh &
