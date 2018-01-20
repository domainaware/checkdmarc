#!/usr/bin/env bash

. ~/venv/checkdmarc/bin/activate
cd docs && make html && cp -r build/html/* ../../checkdmarc-docs/
