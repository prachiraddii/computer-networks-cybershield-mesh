#!/bin/bash
set -e
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
if [ "${CYBERSHIELD_SKIP_TESTS:-0}" != "1" ]; then python -m pytest -v; fi
streamlit run app.py
