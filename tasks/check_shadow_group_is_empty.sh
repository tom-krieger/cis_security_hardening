#!/bin/bash

awk -F: '($1=="shadow") {print $NF}' /etc/group
awk -F: -v GID="$(awk -F: '($1=="shadow") {print $3}' /etc/group)" '($4==GID) {print $1}' /etc/passwd

exit 0
