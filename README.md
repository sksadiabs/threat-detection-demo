# Threat Detection Demo

A simple web page that reads computer log lines and flags the suspicious ones.
It runs entirely in the browser, so no log data is sent anywhere.

## What it does

- **Rule checklist:** Like a security guard checking badges, each log line is compared against a list of warning signs (failed logins, SQL injection, command injection, path traversal, privilege escalation, and more). Points are added up, and each line is labeled OK, LOW, MEDIUM, or HIGH.
- **Cross-line check:** Counts failed logins per IP address across the whole batch to spot password guessing.
- **Controls:** Turn rules on or off, adjust sensitivity, add your own watchlist words, ignore trusted IPs, filter by level, and download a report.
- **AI summary:** Coming soon.

## Files

- `index.html`: the live web version (hosted on GitHub Pages)
- `app.py` and `requirements.txt`: an earlier Python version, kept for reference

## Note

This is a teaching demo. Real security tools read far more data and use much larger rule sets.
