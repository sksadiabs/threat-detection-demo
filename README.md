# Threat Detection Demo

A simple web app that reads computer log lines and flags the suspicious ones.

## What it does

1. **Rule checklist:** Like a security guard checking badges, each log line is compared against a list of warning signs (failed logins, SQL injection, path traversal, and more). Points are added up and each line is labeled OK, LOW, MEDIUM, or HIGH.
2. **AI summary (optional):** An AI reads the lines and explains the risk in plain English.

## Files

- `app.py`: the whole app (rules, AI summary, and the web page)
- `requirements.txt`: the list of tools the app needs to run

## Running it on your own computer

1. Install Python 3.10 or newer.
2. Open a terminal in this folder and run: `pip install -r requirements.txt`
3. Run: `python app.py`
4. Open the address it shows (usually http://127.0.0.1:7860) in your browser.

To turn on the AI summary, set your key first (never paste the key into app.py):
- Mac/Linux: `export ANTHROPIC_API_KEY=your-key-here`
- Windows: `set ANTHROPIC_API_KEY=your-key-here`

## Note

This is a teaching demo. Real security tools read far more data and use much larger rule sets.
