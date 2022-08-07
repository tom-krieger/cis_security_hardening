#!/bin/bash

awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) {print $6}' /etc/passwd | while read -r dir; do
    if [ -d "$dir" ]
    then
        dirperm=$(stat -L -c "%A" "$dir")
        if [ "$(echo "$dirperm" | cut -c6)" != "-" ] || [ "$(echo "$dirperm" | cut -c8)" != "-" ] || [ "$(echo "$dirperm" | cut -c9)" != "-" ] || [ "$(echo "$dirperm" | cut -c10)" != "-" ]
        then
            echo "Directory ${dir} has wrong permissions"
            if [ $PT_fix = "yes" ]
            then
                echo "Fixing permissions on ${dir}"
                chmod g-w,o-rwx "$dir"
            fi
        fi
    fi
    
done 

exit 0
