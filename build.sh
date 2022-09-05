#!/usr/bin/env bash

. venv/bin/activate
pip3 install -U -r requirements.txt && cd docs && make html && cp -r build/html/* ../../checkdmarc-docs/ && cd .. && flake8 checkdmarc.py && flake8 tests.py && python3 tests.py && rm -rf dist/ build/ && hatch build


