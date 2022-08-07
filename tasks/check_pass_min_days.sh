#!/bin/bash

pmin=$(grep ^PASS_MIN_DAYS /etc/login.defs | cut -f 2 -d ' ')
echo "PASS_MIN_DAYS = ${pmin}"
awk -F : -v P=$pmin '(/^[^:]+:[^!*]/ && $4 < P){print $1 " " $4}' /etc/shadow

exit 0
