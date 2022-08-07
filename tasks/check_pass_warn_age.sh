#!/bin/bash

pwrn=$(grep ^PASS_WARN_AGE /etc/login.defs | cut -f 2 -d ' ')
echo "PASS_WARN_AGE = ${pwrn}"
awk -F : -v P=$pwrn '(/^[^:]+:[^!*]/ && $4 < P){print $1 " " $4}' /etc/shadow

exit 0
