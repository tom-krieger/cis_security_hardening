#!/bin/bash

awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
    if [ -d "$dir" ]
    then
        echo "checking ${dir}"
        for file in "$dir"/.*; do
            if [ ! -h "$file" ] && [ -f "$file" ]
            then
                fileperm=$(stat -L -c "%A" "$file")
                if [ "$(echo "$fileperm" | cut -c6)" != "-" ] || [ "$(echo "$fileperm" | cut -c9)" != "-" ]
                then
                    echo "User: \"$user\" file: \"$file\" has permissions: \"$fileperm\""
                fi
                if [ "${PT_stig}" = 'y' ] && [ "$(echo "$fileperm" | cut -c8)" != "-" ]
                then 
                    echo "User: \"$user\" file: \"$file\" has permissions: \"$fileperm\""
                fi
            fi
        done 
    fi
done

exit 0
