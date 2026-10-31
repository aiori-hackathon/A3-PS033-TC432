$ErrorActionPreference = "Stop"
if (-not (Test-Path ".venv")) { py -m venv .venv }
& .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python setup_lab.py
python app.py
