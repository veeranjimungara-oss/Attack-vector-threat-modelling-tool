# Deploying the app

This project is a Flask application and is not suitable for static GitHub Pages hosting. It needs a runtime host that can execute Python.

## Recommended options

### 1) Render
- Create a new Web Service on Render
- Connect this repository
- Use the following settings:
  - Build command: `pip install -r requirements.txt`
  - Start command: `python app.py`
  - Set environment variables:
    - `PORT=10000`
    - `FLASK_DEBUG=0`

### 2) Railway
- Import the repository into Railway
- Set the start command to: `python app.py`
- Ensure Python 3.12 is selected

### 3) Fly.io
- Deploy with `flyctl launch`
- Use a Dockerfile or the built-in Python runtime

## Notes
- GitHub Pages only supports static files and will not run the Flask app or SQLite backend.
- The app binds to `0.0.0.0` for deployment compatibility.
