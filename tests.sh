#!/bin/bash

rm -f result.txt

find spec/classes/rules/common/ -name "*_spec.rb" -print | while read f ; do

    echo "working on $f"
    pdk test unit --tests $f --parallel --format=junit > /dev/null 2>&1
    if [ $? != 0 ] ; then
        echo "test failed: $f" >> result.txt
    fi

done

find spec/classes/rules/redhat/ -name "*_spec.rb" -print | while read f ; do

    echo "working on $f"
    pdk test unit --tests $f --parallel --format=junit > /dev/null 2>&1
    if [ $? != 0 ] ; then
        echo "test failed: $f" >> result.txt
    fi

done

exit 0
