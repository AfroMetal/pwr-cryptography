#!/bin/sh
i=$1
if [ -z "$i" ]; then
  echo "Usage: $0 integer"; exit
fi
msieve -np -q $i | grep p | awk {'print $2'} | uniq
