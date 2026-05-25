#!/bin/bash
set -e

echo ">>> Building Blockchain Voting System Components..."

GPP="g++"

INC="/mingw64/include"
LIB="/mingw64/lib"

FLAGS="-I$INC -L$LIB -lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32"

echo "1/4: Building Core System..."
$GPP core.cpp -o core.exe $FLAGS

echo "2/4: Building Admin Panel..."
$GPP admin.cpp -o admin.exe $FLAGS

echo "3/4: Building Polling Agent Panel..."
$GPP agent.cpp -o agent.exe $FLAGS

echo "4/4: Building Voter App..."
$GPP voter.cpp -o voter.exe $FLAGS

echo ">>> Build Complete!"