#!/bin/bash
# Script for Continuous Integration
# Example Jenkins usage: 
#       /bin/bash -c \
#           "AWS_ACCESS_KEY_ID=xyz \
#           AWS_SECRET_ACCESS_KEY=abc \
#           AWS_DEFAULT_REGION=us-east-1 \
#           AWS_DEFAULT_OUTPUT=json \
#           ECR_REPOSITORY_NAME=provide/ident \
#           ECS_TASK_DEFINITION_FAMILY=ident-fargate \
#           ECS_CLUSTER=production \
#           ECS_SERVICE_NAME=ident \
#           '$WORKSPACE/scripts/ci-process.sh'"
set -o errexit # set -e
set -o nounset # set -u
set -o pipefail
# set -o verbose
trap die ERR
die() 
{
    echo "Failed at line $BASH_LINENO"; exit 1
}
echo Executing $0 $*

setup_go() 
{
    if hash go 2>/dev/null
    then
        echo 'Using' `go version`
    else
        echo 'Installing go'
        wget https://dl.google.com/go/go1.11.linux-amd64.tar.gz
        sudo tar -xvf go1.11.linux-amd64.tar.gz
        sudo mv go /usr/lib/go-1.11
        sudo ln -s /usr/lib/go-1.11 /usr/lib/go
        sudo ln -s /usr/lib/go-1.11/bin/go /usr/bin/go
        sudo ln -s /usr/lib/go-1.11/bin/gofmt /usr/bin/gofmt
    fi

    # Set up Go environment to treat this workspace as within GOPATH. 
    export GOPATH=`pwd`
    export GOBIN=$GOPATH/bin
    export PATH=~/.local/bin:$GOBIN:$PATH
    echo "PATH is: '$PATH'"
    mkdir -p $GOPATH/src/github.com/provideapp
    ln -f -s `pwd` $GOPATH/src/github.com/provideapp/ident
    echo "GOPATH is: $GOPATH"
    mkdir -p $GOBIN

    if hash glide 2>/dev/null
    then
        echo 'Using glide...'
    else 
        echo 'Installing glide...'
        curl https://glide.sh/get | sh
    fi

    go env
}

bootstrap_environment() 
{
    echo '....Setting up environment....'
    setup_go
    mkdir -p reports/linters
    echo '....Environment setup complete....'
}

# Preparation
echo '....Running the full continuous integration process....'
scriptDir=`dirname $0`
pushd ${scriptDir}/.. &>/dev/null
echo 'Working Directory =' `pwd`

# The Process
echo '....[PRVD] Setting Up....'
bootstrap_environment

make clean

glide cache-clear
glide --debug install

(cd vendor/ && tar c .) | (cd src/ && tar xf -)
rm -rf vendor/

make lint > reports/linters/golint.txt # TODO: add -set_exit_status once we clean current issues up. 

DATABASE_USER=postgres DATABASE_PASSWORD=postgres make test

if [ "$RUN_INTEGRATION_SUITE" = "true" ]; then
  DATABASE_USER=postgres DATABASE_PASSWORD=postgres make integration
fi

make build
make ecs_deploy

popd &>/dev/null
echo '....CI process completed....'
