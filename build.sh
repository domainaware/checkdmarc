#!/usr/bin/env bash

set -e

if [ ! -d "venv" ]; then
  virtualenv venv || exit
fi

. venv/bin/activate
pip install -U -r requirements.txt
flake8 checkdmarc.py
flake8 tests.py
cd docs
make clean
make html
touch build/html/.nojekyll
cp -rf build/html/* ../../checkdmarc-docs/
cd ..
rm -rf dist/ build/
hatch build