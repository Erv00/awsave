#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "$SCRIPT_DIR"
AWS_SHARED_CREDENTIALS_FILE="aws.keys" ./target/release/awsave
