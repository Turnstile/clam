#!/bin/bash
current=$(date +%s)

if [ -s ./lastrun.log ]
then
	last=$(head -n 1 ./lastrun.log)
	seconds=$((current - last))
else
	seconds=86400 
fi

echo $current > ./lastrun.log

$(python3 scan_computers.py -s $seconds)
