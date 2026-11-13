# Red Team vs Blue Team

This package contains the supplied dashboard frontend connected to a local FastAPI sandbox backend.

## Project structure
- `frontend/index.html` — original dashboard plus a backend-link panel.
- `backend/main.py` — API, guardian policy baseline, mock tools, attack round, audit log and scoreboard.
- `backend/requirements.txt` — Python dependencies.

## Run on Windows
1. Install Python 3.10+.
2. Open a terminal in the `backend` folder.
3. Run:
   ```bash
   py -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   uvicorn main:app --reload
   ```
4. Keep the terminal open. API docs: http://127.0.0.1:8000/docs
5. Open `frontend/index.html` in Chrome. The **CYBER-02 · BACKEND LINK** panel appears at bottom-right.
6. Click **Run API Round**, **Run Legitimate Task**, **Refresh Logs** and **Reset**.

## Run on macOS/Linux
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```
Then open `frontend/index.html` in a browser.

## Important limitations
This is a hackathon prototype, not a production security gateway. The red-team round is deterministic and simulated; the guardian is a transparent rule-based baseline, not a trained semantic model. Email, files, browser and payment are synthetic/in-memory only. No real money moves and no real accounts or personal files are accessed. Before deployment, restrict CORS, add authentication, persistent storage, scoped credentials, monitoring and human approval for high-impact actions.
