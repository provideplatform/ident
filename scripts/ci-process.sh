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
    # TODO: Decide if we really want this GOPATH change or not 
    #       (might slow down builds beyond the benefit of the isolation).
    #       This also, as is, would mean disabling `set -u` above. 
    # if [ -z "$WORKSPACE" ]
    # then
    #     echo 'Running on Jenkins'
    # else
    #     echo 'Not running on Jenkins'
    #     export GOPATH=$WORKSPACE/go
    # fi
    echo "GOPATH is: $GOPATH"
    echo '....Go-Getting....'
    go get ./... # -v
    # TODO: any dependency / package management we want to add here. 
    # go env
    go version
    echo '....Environment setup complete....'
}

# Preparation
echo '....Running the full continuous integration process....'
scriptDir=`dirname $0`
pushd ${scriptDir}/.. &>/dev/null
echo 'Working Directory =' `pwd`
bootstrap_environment

# The Process
echo '....[PRVD] Setting Up....'
rm ./ident 2>/dev/null || true # silence error if not present
go fix .
go fmt
go clean -i
echo '....[PRVD] Analyzing...'
go vet
echo '....[PRVD] Building....'
go build -v
echo '....[PRVD] Testing....'
go test -cover -v ./...
# TODO: build for deployment... go build -o $GOPATH/../build/ident
# echo '....[PRVD] Docker Build....'
# echo '....[PRVD] Docker Tag....'
# echo '....[PRVD] Docker Push....'

# Finalization
popd &>/dev/null
echo '....CI process completed....'
