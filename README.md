**SSRF Lab — Vulnerable App & Simulated Metadata Server**

This repository contains a local, intentionally vulnerable demonstration designed for security research, teaching, and safe experimentation with Server‑Side Request Forgery (SSRF) patterns. Use only in isolated, offline, or otherwise controlled environments. Never run these examples against systems you do not own or have explicit authorization to test.

**Quick Overview**
- `start.py` — Vulnerable Flask application demonstrating multiple SSRF vectors and an "indirect file access" feature. Runs on port 5000 by default.
- `victem_server.py` — Simulated AWS metadata / victim service (CTF-style). Runs on port 8081 and exposes metadata endpoints that contain demonstration tokens.
- `hacker.py` — SSRF fuzzer / scanner used to test endpoints with payloads (supports HTTP/HTTPS, placeholders, and wordlists).
- `database.json` — Local JSON storage used by the app.
- `templates/` — HTML templates used by the Flask app (login, dashboard, upload, etc.).

**Safety & Legal Notice**
- This project is strictly for education, research, and defensive testing in environments you control.
- Do not use these tools against external systems without explicit written permission — doing so may be illegal and unethical.

**Requirements**
- Python 3.8+ (3.10/3.11 recommended)
- Typical Python packages used by the code: flask, requests, colorama, paramiko (some components), and standard library modules.

Quick install (recommended inside a venv):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install flask requests colorama paramiko
```

Or create a `requirements.txt` and run `pip install -r requirements.txt`.

**Run the lab (local only)**
1. Start the vulnerable app (`start.py`):

```powershell
python start.py
```

App runs on http://localhost:5000 by default.

2. (Optional) Start the simulated metadata/victim server (`victem_server.py`):

```powershell
python victem_server.py
```

Victim server runs on http://localhost:8081 and exposes metadata endpoints used in lab exercises.

3. Example test using the scanner (`hacker.py`):

```powershell
python hacker.py -u "http://localhost:5000/api/preview?url=FUZZ" -w payloads.txt
```

Replace `payloads.txt` with a payload list, or omit `-w` to use built‑in defaults.

**Common Endpoints & Notes**
- Vulnerable app (`start.py`):
	- `/upload` and `/profile/update-avatar` — accept URLs and perform server requests (SSRF vectors).
	- `/api/preview` — previews an arbitrary URL (no validation).
	- `/api/access/file` and `/api/access/file-post` — indirect file access endpoints (demonstrate weak token logic and URL fetching).
	- `/hidden/files/<id>` — direct file download endpoint (no auth in demo).

- Victim metadata server (`victem_server.py`):
	- `/latest/meta-data/` and related paths expose simulated metadata and example tokens (e.g., `flag_haile_123`) for lab exercises.
	- `/files?token=TOKEN` — protected file listing (CTF-style access once token is obtained).

**Example exercise (safe, local)**
1. Start `victem_server.py` (port 8081).
2. Start `start.py` (port 5000).
3. Use a browser or `hacker.py` to call an endpoint that fetches external URLs, for example:

```powershell
curl "http://localhost:5000/api/preview?url=http://localhost:8081/latest/meta-data/"
```

4. Observe returned metadata and use the demonstrated token locally to access `/files?token=TOKEN` on the victim server.

**Security recommendations (to harden the app)**
- Never fetch user‑controlled URLs without validation and allowlisting.
- Restrict schemes (block `file://`, disallow requests to `127.0.0.1`/`169.254.169.254` unless explicitly allowed).
- Use strong, non‑predictable tokens and require authentication for sensitive endpoints.
- Run exercises in isolated networks or containers to avoid accidental exposure.

**Files of interest**
- [start.py](start.py)
- [victem_server.py](victem_server.py)
- [hacker.py](hacker.py)
- [database.json](database.json)
- [templates/](templates/)

**Next steps I can implement**
- Add `requirements.txt` and `run.ps1` helper.
- Add a Docker Compose setup to run services in isolated containers.
- Add a short lab guide with step‑by‑step exercises and expected outcomes.

Reply which item you'd like and I will implement it.
