#!/bin/bash

#
# Copyright 2017-2022 Provide Technologies Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# this file does not actually invoke sudo... it is named sudo.sh because
# it gives authorized ident administrators keys to the kingdom...

if [[ -z "${AUTH0_INTEGRATION_ENABLED}" ]]; then
  AUTH0_INTEGRATION_ENABLED=false
fi

if [[ -z "${AUTH0_CLIENT_ID}" ]]; then
  AUTH0_CLIENT_ID='1MypDFhR6y28Ue2hLfSbvkyH0Mf9yA1e' # sandbox creds
fi

if [[ -z "${AUTH0_CLIENT_SECRET}" ]]; then
  AUTH0_CLIENT_SECRET='ICRXYzYio-lizO7YYn6mmhhgIqjEJr7WrVO1D8U7n9Lfwk05tKgmeEvrDdXp4Lee' # sandbox creds
fi

if [[ -z "${AUTH0_DOMAIN}" ]]; then
  AUTH0_DOMAIN=https://prvd-staging.auth0.com
fi

if [[ -z "${AUTH0_AUDIENCE}" ]]; then
  AUTH0_AUDIENCE=https://prvd-staging.auth0.com/api/v2/
fi

if [[ -z "${JWT_SIGNER_PRIVATE_KEY}" ]]; then
  JWT_SIGNER_PRIVATE_KEY='-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----'
fi

if [[ -z "${JWT_SIGNER_PUBLIC_KEY}" ]]; then
  JWT_SIGNER_PUBLIC_KEY='-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAullT/WoZnxecxKwQFlwE
9lpQrekSD+txCgtb9T3JvvX/YkZTYkerf0rssQtrwkBlDQtm2cB5mHlRt4lRDKQy
EA2qNJGM1Yu379abVObQ9ZXI2q7jTBZzL/Yl9AgUKlDIAXYFVfJ8XWVTi0l32Vsx
tJSd97hiRXO+RqQu5UEr3jJ5tL73iNLp5BitRBwa4KbDCbicWKfSH5hK5DM75EyM
R/SzR3oCLPFNLs+fyc7zH98S1atglbelkZsMk/mSIKJJl1fZFVCUxA+8CaPiKbpD
QLpzydqyrk/y275aSU/tFHidoewvtWorNyFWRnefoWOsJFlfq1crgMu2YHTMBVtU
SJ+4MS5D9fuk0queOqsVUgT7BVRSFHgDH7IpBZ8s9WRrpE6XOE+feTUyyWMjkVgn
gLm5RSbHpB8Wt/Wssy3VMPV3T5uojPvX+ITmf1utz0y41gU+iZ/YFKeNN8WysLxX
AP3Bbgo+zNLfpcrH1Y27WGBWPtHtzqiafhdfX6LQ3/zXXlNuruagjUohXaMltH+S
K8zK4j7n+BYl+7y1dzOQw4CadsDi5whgNcg2QUxuTlW+TQ5VBvdUl9wpTSygD88H
xH2b0OBcVjYsgRnQ9OZpQ+kIPaFhaWChnfEArCmhrOEgOnhfkr6YGDHFenfT3/RA
PUl1cxrvY7BHh4obNa6Bf8ECAwEAAQ==
-----END PUBLIC KEY-----'
fi

if [[ -z "${LOG_LEVEL}" ]]; then
  LOG_LEVEL=info
fi

if [[ -z "${NATS_CLUSTER_ID}" ]]; then
  NATS_CLUSTER_ID=provide
fi

if [[ -z "${NATS_TOKEN}" ]]; then
  NATS_TOKEN=testtoken
fi

if [[ -z "${NATS_URL}" ]]; then
  NATS_URL=nats://localhost:4222
fi

if [[ -z "${NATS_JETSTREAM_URL}" ]]; then
  NATS_JETSTREAM_URL=nats://localhost:4222
fi

if [[ -z "${NATS_FORCE_TLS}" ]]; then
  NATS_FORCE_TLS=false
fi

if [[ -z "${DATABASE_HOST}" ]]; then
  DATABASE_HOST=localhost
fi

if [[ -z "${DATABASE_NAME}" ]]; then
  DATABASE_NAME=ident_dev
fi

if [[ -z "${DATABASE_USER}" ]]; then
  DATABASE_USER=ident
fi

if [[ -z "${DATABASE_PASSWORD}" ]]; then
  DATABASE_PASSWORD='...'
fi

if [[ -z "${DATABASE_LOGGING}" ]]; then
  DATABASE_LOGGING=false
fi

AUTH0_INTEGRATION_ENABLED=$AUTH0_INTEGRATION_ENABLED \
AUTH0_AUDIENCE=$AUTH0_AUDIENCE \
AUTH0_DOMAIN=$AUTH0_DOMAIN \
AUTH0_CLIENT_ID=$AUTH0_CLIENT_ID \
AUTH0_CLIENT_SECRET=$AUTH0_CLIENT_SECRET \
DATABASE_HOST=$DATABASE_HOST \
DATABASE_NAME=$DATABASE_NAME \
DATABASE_USER=$DATABASE_USER \
DATABASE_PASSWORD=$DATABASE_PASSWORD \
DATABASE_LOGGING=$DATABASE_LOGGING \
JWT_SIGNER_PUBLIC_KEY=$JWT_SIGNER_PUBLIC_KEY \
JWT_SIGNER_PRIVATE_KEY=$JWT_SIGNER_PRIVATE_KEY \
LOG_LEVEL=$LOG_LEVEL \
NATS_CLUSTER_ID=$NATS_CLUSTER_ID \
NATS_TOKEN=$NATS_TOKEN \
NATS_URL=$NATS_URL \
NATS_JETSTREAM_URL=$NATS_JETSTREAM_URL \
NATS_STREAMING_CONCURRENCY=$NATS_JETSTREAM_URL \
NATS_FORCE_TLS=$NATS_FORCE_TLS \
./.bin/ident_sudo "$@"
