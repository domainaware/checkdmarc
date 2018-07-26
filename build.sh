#!/usr/bin/env bash

. ~/venv/domainaware/bin/activate
pip install -U -r requirements.txt
cd docs && make html && cp -r build/html/* ../../checkdmarc-docs/
cd ..
rm -rf dist/ build/
flake8 checkdmarc.py
flake8 tests.py
python3 setup.py sdist
python3 setup.py bdist_wheel

