#!/usr/bin/env bash

set -e

if [ ! -d "venv" ]; then
  virtualenv venv || exit
fi

. venv/bin/activate
pip install -U pip
pip install -U -r requirements.txt
black .
cd docs
make clean
make html
touch build/html/.nojekyll
if [ -d "../../checkdmarc-docs" ]; then
  cp -rf build/html/* ../../checkdmarc-docs/
fi
cd ..
rm -rf dist/ build/
hatch build