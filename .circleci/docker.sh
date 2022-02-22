#!/usr/bin/env bash

VERSION="0.0.1"
NAME="itwte/ss-ci"
BUILD=false
PUSH=false

# parse commandline args
while getopts ":bpv:" opt; do
  case $opt in
    b) BUILD=true
    ;;
    p) PUSH=true
    ;;
    v) VERSION="${OPTARG}"
    ;;
    \?) echo "Invalid option -$OPTARG" >&2
    ;;
  esac
done

if [ "$BUILD" = true ]; then
    echo "Building container $NAME:$VERSION"
    docker build --compress -t $NAME:$VERSION .
fi

if [ "$PUSH" = true ]; then
    echo "Pushing container $NAME:$VERSION"
    docker push $NAME:$VERSION
fi
