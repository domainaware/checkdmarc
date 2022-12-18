#!/bin/bash
git pull
cd ../checkdmarc-docs || exit
git pull
cd ../checkdmarc || exit
./build.sh
cd ../checkdmarc-docs || exit
git add .
git commit -m "Update docs"
git push
