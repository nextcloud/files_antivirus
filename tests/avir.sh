#!/bin/bash
#
# SPDX-FileCopyrightText: 2014 ownCloud, Inc.
# SPDX-License-Identifier: AGPL-3.0-only
content=$(tee)

if [[ $content =~ .*kitten  ]]; then
	echo "Oh my god! : Kitten FOUND"
	exit 1
fi

echo "$1 : OK"
