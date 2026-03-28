#!/bin/bash
set -e

construction_start_ns=$(python3 -c 'import time; print(time.time_ns())')

rm -f 1hs 1hc
rm -f 2hs 2hc
rm -f 3hs 3hc 
rm -f ../realrun/tree*

./sp -r "$1" -s 4 -d 4 
mv tree* ../realrun/
t1=""
t2=""
t3=""

if [ -f 1hs ] 
then
    t1="0"
fi

if [ -f 1hc ] 
then
    t1="1"
fi

if [ -f 2hs ] 
then
    t2="0"
fi

if [ -f 2hc ] 
then
    t2="1"
fi

if [ -f 3hs ] 
then
    t3="0"
fi

if [ -f 3hc ] 
then
    t3="1"
fi


cd ../realrun/
bash ./cc.sh "$t1" "$t2" "$t3"
construction_end_ns=$(python3 -c 'import time; print(time.time_ns())')
construction_ms=$(python3 -c "print((${construction_end_ns} - ${construction_start_ns}) / 1000000.0)")
echo "BENCHMARK.CONSTRUCTION_MS=${construction_ms}"
./realpc -r "$1" -t "$2" -l tree0 -m tree1 -n tree2
