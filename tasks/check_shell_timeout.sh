#!/bin/bash

output1=""
output2=""

[ -f /etc/bash.bashrc ] && BRC="/etc/bash.bashrc"

for f in "$BRC" /etc/profile /etc/profile.d/*.sh ; do
    grep -Pq "\bTMOUT=(${PT_tmout}|[1-5][0-9][0-9]|[1-9][0-9]|[1-9])\b" "$f" && grep -Pq "\breadonly\h+TMOUT(\h+|\h*;|\h*$|=(${PT_tmout}|[1-5][0-9][0-9]|[1-9][0-9]|[1-9]))\b" "$f" && grep -Pq '\bexport\h+([^#\n\r]+\h+)?TMOUT\b' "$f" && output1="$f"
done

output2=$(grep -Ps "\bTMOUT=(${PT_tmout:1:1}[0-9][1-9]|[7-9][0-9][0-9]|[1-9]{3,}|0+)\b" /etc/profile /etc/profile.d/*.sh $BRC)

if [ -n "$output1" ] && [ -z "$output2" ]
then
    echo -e "\nPASSED\n\nTMOUT is configured in: \"$output1\"\n"
else
    [ -z "$output1" ] && echo -e "\nFAILED\n\nTMOUT is not configured\n"
    [ -n "$output2" ] && echo -e "\nFAILED\n\nTMOUT is incorrectly configured in: \"$output2\"\n"
fi

exit 0