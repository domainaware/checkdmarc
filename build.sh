#!/usr/bin/env bash

pip install -U -r requirements.txt && rstcheck README.rst && cd docs && make html && cp -r build/html/* ../../checkdmarc-docs/ && cd .. && flake8 checkdmarc.py && flake8 tests.py && python3 tests.py && rm -rf dist/ build/ && python3 setup.py sdist && python3 setup.py bdist_wheel


