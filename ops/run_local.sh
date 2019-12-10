#!/bin/bash

./ops/run_api.sh &
./ops/run_api_accountant.sh &
./ops/run_consumer.sh &
