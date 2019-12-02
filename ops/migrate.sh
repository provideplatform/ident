#!/bin/bash

if [[ -z "${LOG_LEVEL}" ]]; then
  LOG_LEVEL=info
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
  DATABASE_PASSWORD=
fi

if [[ -z "${DATABASE_LOGGING}" ]]; then
  DATABASE_LOGGING=false
fi

createuser $DATABASE_USER --superuser 2>/dev/null
createdb $DATABASE_NAME -O $DATABASE_USER 2>/dev/null

DATABASE_HOST=$DATABASE_HOST \
DATABASE_NAME=$DATABASE_NAME \
DATABASE_USER=$DATABASE_USER \
DATABASE_PASSWORD=$DATABASE_PASSWORD \
DATABASE_LOGGING=$DATABASE_LOGGING \
LOG_LEVEL=$LOG_LEVEL \
./.bin/ident_migrate
