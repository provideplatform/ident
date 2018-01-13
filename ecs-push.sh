#!/usr/bin/env bash

./build.sh

$(aws ecr get-login --no-include-email --region us-east-1)
docker build --no-cache -t provide/ident .
docker tag provide/ident:latest 085843810865.dkr.ecr.us-east-1.amazonaws.com/provide/ident:latest
docker push 085843810865.dkr.ecr.us-east-1.amazonaws.com/provide/ident:latest
