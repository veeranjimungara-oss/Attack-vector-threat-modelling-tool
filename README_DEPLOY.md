# Deploying the app

The app supports GitHub Pages as a static site and Render as a Flask service.

## Publish on GitHub Pages

1. Push the project to the `main` branch of the GitHub repository.
2. In GitHub, open **Settings → Pages**.
3. Under **Build and deployment**, choose **Deploy from a branch**, select `main` and `/(root)`, then save.
4. Open `https://veeranjimungara-oss.github.io/Attack-vector-threat-modelling-tool/` after the Pages deployment finishes.

The root `index.html` is the Pages entry point. Models and edits are saved in that browser's local storage; they do not sync to other browsers or devices. The app's analysis and exports work without a server.

## Deploy on Render

1. In Render, choose **New** and then **Blueprint**.
2. Connect `veeranjimungara-oss/Attack-vector-threat-modelling-tool` and deploy it.
3. When the deployment finishes, open the service URL ending in `.onrender.com`.

Render reads `render.yaml` for the Python version, build command, Gunicorn start command, and environment settings. Render supplies the `PORT` value automatically; do not use `python app.py` as the production start command.

## SQLite persistence

The current database is a local SQLite file. On Render's default filesystem, data may be lost when the service is redeployed or restarted. For persistent production data, configure a persistent disk and set `THREAT_MODEL_DB` to a path on that disk, or migrate the app to a managed database.
