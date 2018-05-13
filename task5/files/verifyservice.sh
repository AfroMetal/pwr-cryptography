#!/usr/bin/env bash

filename=$1
signature=$2
pub_key=$3

if [[ $# -lt 3 ]] ; then
  echo "Usage: verifyservice <file> <signature> <public_key>"
  exit 1
fi

openssl x509 -in $pub_key -pubkey -out /tmp/grade.key
openssl dgst -md5 -verify /tmp/grade.key -signature $signature $filename
rm /tmp/grade.key
