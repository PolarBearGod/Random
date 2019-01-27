#!/bin/bash

DATE=2016-01-01
for i in {0..744}
do
        PREVIOUS_DATE=$(date +%m/%d/%Y:%H:%M:%S -d "$DATE + $i hour")
        NEXT_DATE=$(date +%m/%d/%Y:%H:%M:%S -d "$DATE + $(expr $i + 1) hour")
        python fetchsec.py -e $PREVIOUS_DATE -l $NEXT_DATE
done
