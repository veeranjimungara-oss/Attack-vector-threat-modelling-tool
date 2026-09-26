# Vector Threat Modeling Studio

A local, defensive threat-modeling workspace built with Flask, SQLite, and vanilla JavaScript. It maps system assets and trust paths, applies an explainable STRIDE ruleset, and exports a JSON model or printable report. It does not probe or exploit live systems.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. The first run creates `threat_models.sqlite3` and seeds an editable example architecture. Set `THREAT_MODEL_DB` to choose a different database file, or `PORT` to use another port.

## Analysis model

Risk is scored as likelihood × impact, each from 1 to 5. Scores 1–4 are Low, 5–9 Medium, 10–16 High, and 17–25 Critical. Rules use asset type and direct trust paths to surface review prompts; they are intentionally transparent and are not a substitute for security testing or expert review.