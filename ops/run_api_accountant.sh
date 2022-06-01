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

if [[ -z "${API_ACCOUNTING_LISTEN_ADDRESS}" ]]; then
  API_ACCOUNTING_LISTEN_ADDRESS=0.0.0.0:8889
fi

if [[ -z "${LOG_LEVEL}" ]]; then
  LOG_LEVEL=debug
fi

if [[ -z "${DATABASE_HOST}" ]]; then
  DATABASE_HOST=0.0.0.0
fi

if [[ -z "${DATABASE_NAME}" ]]; then
  DATABASE_NAME=ident_dev
fi

if [[ -z "${DATABASE_USER}" ]]; then
  DATABASE_USER=ident
fi

if [[ -z "${DATABASE_PASSWORD}" ]]; then
  DATABASE_PASSWORD=
fi

if [[ -z "${DATABASE_LOGGING}" ]]; then
  DATABASE_LOGGING=false
fi

LOG_LEVEL=$LOG_LEVEL \
DATABASE_HOST=$DATABASE_HOST \
DATABASE_NAME=$DATABASE_NAME \
DATABASE_USER=$DATABASE_USER \
DATABASE_PASSWORD=$DATABASE_PASSWORD \
DATABASE_LOGGING=$DATABASE_LOGGING \
SYSLOG_ENDPOINT=${SYSLOG_ENDPOINT} \
API_ACCOUNTING_LISTEN_ADDRESS=$API_ACCOUNTING_LISTEN_ADDRESS \
./.bin/ident_api_accountant
