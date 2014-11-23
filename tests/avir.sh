#!/bin/bash

content=$(tee)

if [[ $content =~ .*kitten  ]]; then
	echo "Oh my god! : Kitten FOUND"
	exit 1
fi

echo "$1 : OK"
