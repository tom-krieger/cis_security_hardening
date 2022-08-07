#!/bin/bash

pmax=$(grep ^PASS_MAX_DAYS /etc/login.defs | cut -f 2 -d ' ')
echo "PASS_MAX_DAYS = ${pmax}"
awk -F : -v P=$pmax '(/^[^:]+:[^!*]/ && $4 < P){print $1 " " $4}' /etc/shadow

exit 0
