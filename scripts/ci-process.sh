#1/bin/bash
# Script for Continuous Integration
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

# TODO: make sure GOPATH is set up somewhere relative to --or inside of-- WORKSPACE

bootstrap_environment() 
{
    echo '....Setting up environment....'
    mkdir -p reports/linters
    if hash go 2>/dev/null
    then
        echo 'Using' `go version`
    else
        echo 'Installing go'
        sudo apt-get update
        sudo apt-get -y install golang
        export GOROOT=/usr/lib/go
        export GOBIN=/usr/bin/go # TODO: or =$GOPATH/bin ?
        export PATH=$PATH:$GOBIN
    fi
    # export GOPATH=./go # TODO: Do we want to do this (pros and cons)?
    echo "GOPATH is: $GOPATH"
    echo '....Go-Getting....'
    go get ./... # -v
    # TODO: any dependency / package management we want to add here. 
    # go env
    echo '....Environment setup complete....'
}

# Preparation
echo '....Running the full continuous integration process....'
scriptDir=`dirname $0`
pushd ${scriptDir}/.. &>/dev/null
echo 'Working Directory =' `pwd`
bootstrap_environment

# The Process
# TODO: any other option flags we want for a CI run?
echo '....[PRVD] Setting Up....'
rm ./ident 2>/dev/null || true # silence error if not present
go fix .
go fmt
go clean -i
echo '....[PRVD] Analyzing...'
go vet
golint -set_exit_status > reports/linters/golint.txt
echo '....[PRVD] Building....'
go build -v
echo '....[PRVD] Testing....'
go test -v -race -cover -html=cover/coverage.cov -o coverage.html ./... # TODO: -msan (for Clang's MemorySanitizer)
# TODO: build for deployment... go build -o $GOPATH/../build/ident
# echo '....[PRVD] Docker Build....'
# echo '....[PRVD] Docker Tag....'
# echo '....[PRVD] Docker Push....'

# Finalization
popd &>/dev/null
echo '....CI process completed....'
