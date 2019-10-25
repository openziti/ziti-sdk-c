#!/usr/bin/env bash

echo '{ "files": [' > publish.json
for f in build-*/*-pub-spec.json
do
      if [ -n "$first" ]; then
        echo "," >> publish.json
      fi
  	  cat $f >> publish.json
  	  first="done"
done
echo "]}" >> publish.json
