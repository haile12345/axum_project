# SSRF Test Project

A minimal project containing an SSRF test script and an intentionally vulnerable target for local testing and learning.

**Purpose**
- Provide a local environment to experiment with Server-Side Request Forgery (SSRF) techniques safely.
- NOT for unauthorized or malicious testing against systems you do not own or have explicit permission to test.

**Contents**
- `start.py`: (placeholder) entry script for running tests or demos.
- Local vulnerable target and test script(s): use these only in isolated, controlled environments.

**Requirements**
- Python 3.8+ (no additional packages required by default). Install packages if your test scripts need them.

**Quick Start**
1. Open a terminal in this project folder.
2. Run the script (replace with the actual script name if different):

```powershell
python start.py
```

If your tests require extra modules, create a `requirements.txt` and run:

```powershell
pip install -r requirements.txt
```

**Usage Notes**
- This project is for education and defensive testing only. Always obtain written permission before testing any external systems.
- Keep the vulnerable target isolated from networks containing sensitive data.

**Responsible Disclosure & Legal**
- Do not use these tools on systems without explicit authorization. Misuse may be illegal.

**Questions / Next Steps**
- If you want, I can: add a real example script, add a `requirements.txt`, or include a simple vulnerable web service and run instructions.
