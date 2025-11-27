# Task Manager Skeleton

Minimal starter skeleton for the **Task Manager with FastAPI & Angular** lab.

## Structure

```text
task-manager-skeleton/
  backend/
    app/
      __init__.py
      database.py
      models.py
      schemas.py
      crud.py
      main.py
    auth.py
    requirements.txt
  frontend/
    README-frontend-skeleton.md
```

## Backend Quickstart

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Then open http://localhost:8000/docs and test:
- `/token` with `demo@example.com` / `password123`
- `/tasks` CRUD endpoints

## Frontend Quickstart (during lab)

Follow the **Incremental Lab Guide** to scaffold the Angular app under `frontend/`.
