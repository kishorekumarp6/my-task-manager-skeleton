# Incremental Lab Guide: Task Manager with FastAPI & Angular

**Goal:** Build a full-stack task manager with a JWT-based login flow from scratch, step by step.

- **Backend:** FastAPI (async endpoints) + SQLite + SQLAlchemy + JWT auth
- **Frontend:** Angular 20 (standalone components) + route guards + interceptor
- **Reference Solution:** GitHub repo `my-task-manager` (for comparison after the lab)

---

## 0.0. Start Options: Empty Folder vs Skeleton Repo

You can start this lab in two ways:

- **Option A – From Scratch (recommended for first-time run):**
  - Create a fresh `task-manager-lab/` folder and follow all steps from Section 1 onward.
- **Option B – From Skeleton Repo (time-constrained / repeat runs):**
  - Clone or download the `task-manager-skeleton` repo from the provided URL.
  - Backend is pre-populated with working FastAPI + JWT + CRUD.
  - Frontend folder is empty, ready for Angular scaffolding.

If you pick **Option B**, you can safely **skip** the detailed code-entry steps for the backend and start from these checkpoints:

- Backend: Start reading from **Checkpoint 5 (Backend Functional)** to understand how it works rather than typing it all.
- Frontend: Begin hands-on work at **Section 3.1 (Create Angular App)** and follow all frontend steps and checkpoints.

The learning objectives are the same; Option B simply saves typing time on the backend.

---

## 0. Prerequisites & Tools

- Python **3.12+** installed
- Node.js **v20+ or v22+** installed
- Angular CLI **v20** installed
- Git installed (optional but recommended)

```powershell
# Install Angular CLI (if not already installed)
npm install -g @angular/cli@20
```

---

## 1. Create the Project Folder Structure

From your working directory (e.g., `crossskill-session/`), create the main folders:

```powershell
# From the root where you want the lab folders
mkdir task-manager-lab
cd task-manager-lab

mkdir backend
mkdir frontend
```

You should now have:

```text
task-manager-lab/
  backend/
  frontend/
```

This mirrors the structure used in the reference repo `my-task-manager`.

**Checkpoint 0:** You have a `task-manager-lab/` folder with empty `backend/` and `frontend/` subfolders.

---

## 2. Backend – FastAPI + SQLite (Incremental)

We will build the backend inside `backend/` step by step.

### 2.1. Create and Activate Virtual Environment

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2.2. Install Backend Dependencies

```powershell
pip install fastapi uvicorn[standard] sqlalchemy pydantic bcrypt python-jose[cryptography] python-multipart
```

Create `requirements.txt` so the environment can be reproduced:

```powershell
@"
fastapi
uvicorn[standard]
sqlalchemy
pydantic
bcrypt
python-jose[cryptography]
python-multipart
"@ | Out-File -Encoding UTF8 requirements.txt
```

**Checkpoint 1 (Backend Setup):**
- Virtual environment is activated.
- Dependencies are installed without errors.
- `requirements.txt` exists in `backend/`.

### 2.3. Create Backend Package Structure

Create the `app` package and base files:

```powershell
mkdir app
New-Item app\__init__.py -ItemType File
New-Item app\database.py -ItemType File
New-Item app\models.py -ItemType File
New-Item app\schemas.py -ItemType File
New-Item app\crud.py -ItemType File
New-Item app\main.py -ItemType File
New-Item auth.py -ItemType File
```

Target structure:

```text
backend/
  app/
    __init__.py
    main.py
    models.py
    database.py
    crud.py
    schemas.py
  auth.py
  requirements.txt
```

### 2.4. Implement the Database Layer (`app/database.py`)

Open `app/database.py` and add:

```python
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./tasks.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

### 2.5. Define the Task Model (`app/models.py`)

```python
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from .database import Base


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    done = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
```

> Note: We use `done` (not `completed`) and include `created_at`.

### 2.6. Define Pydantic Schemas (`app/schemas.py`)

Define Pydantic models that clearly separate input from output and use `TaskRead` consistently as the response type.

```python
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class TaskBase(BaseModel):
    title: str = Field(..., max_length=255)
    description: Optional[str] = None
    done: bool = False


class TaskCreate(TaskBase):
    pass


class TaskUpdate(BaseModel):
    title: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    done: Optional[bool] = None


class TaskRead(TaskBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True
```

- We now have **TaskRead** as the response model, aligned with the endpoints.

**Checkpoint 2 (Domain Model Ready):**
- `Task` ORM model exists in `models.py`.
- `TaskBase`, `TaskCreate`, `TaskUpdate`, and `TaskRead` exist in `schemas.py`.
- Naming uses `done` and `TaskRead` consistently (supports REST + Angular).

### 2.7. Implement CRUD Operations (`app/crud.py`)

This step implements **synchronous CRUD** used by async endpoints, resolving the earlier **conflicting async CRUD** issue.

```python
from typing import List, Optional

from sqlalchemy.orm import Session

from . import models, schemas


def create_task(db: Session, task_in: schemas.TaskCreate) -> models.Task:
    task = models.Task(
        title=task_in.title,
        description=task_in.description,
        done=task_in.done,
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def get_tasks(db: Session) -> List[models.Task]:
    return db.query(models.Task).order_by(models.Task.created_at.desc()).all()


def get_task(db: Session, task_id: int) -> Optional[models.Task]:
    return db.query(models.Task).filter(models.Task.id == task_id).first()


def update_task(db: Session, task_id: int, task_in: schemas.TaskUpdate) -> Optional[models.Task]:
    task = get_task(db, task_id)
    if not task:
        return None

    if task_in.title is not None:
        task.title = task_in.title
    if task_in.description is not None:
        task.description = task_in.description
    if task_in.done is not None:
        task.done = task_in.done

    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def delete_task(db: Session, task_id: int) -> bool:
    task = get_task(db, task_id)
    if not task:
        return False
    db.delete(task)
    db.commit()
    return True
```

> Note: All CRUD functions are sync; FastAPI will run them in a thread pool when called from async endpoints.

**Checkpoint 3 (Persistence Layer):**
- `crud.py` exposes `create_task`, `get_tasks`, `get_task`, `update_task`, `delete_task`.
- All CRUD functions are synchronous but side-effectful (commit/refresh/delete).
- There is no conflicting async CRUD code.

### 2.8. Implement JWT Authentication (`auth.py`)

```python
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

SECRET_KEY = "your-secret-key-here-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


MOCK_USERS = {
    "demo@example.com": {
        "username": "demo@example.com",
        "email": "demo@example.com",
        "full_name": "Demo User",
        # password: password123
        "hashed_password": pwd_context.hash("password123"),
    },
    "admin@example.com": {
        "username": "admin@example.com",
        "email": "admin@example.com",
        "full_name": "Admin User",
        # password: admin123
        "hashed_password": pwd_context.hash("admin123"),
    },
}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(username: str, password: str):
    user = MOCK_USERS.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = MOCK_USERS.get(username)
    if user is None:
        raise credentials_exception
    return user
```

> The `MOCK_USERS` entries include a `username` field, and JWT tokens consistently use `sub = username`.

### 2.9. Implement FastAPI App and Async Endpoints (`app/main.py`)

```python
from datetime import timedelta
from typing import List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from . import models, schemas, crud
from .database import Base, engine, get_db
import sys
sys.path.append("..")
from auth import authenticate_user, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES


app = FastAPI(
    title="Task Manager API",
    description="FastAPI backend with JWT auth and async endpoints",
    version="1.0.0",
)


origins = [
    "http://localhost:4200",
    "http://localhost:4201",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]},
        expires_delta=access_token_expires,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "email": user["email"],
            "full_name": user["full_name"],
        },
    }


@app.get("/tasks", response_model=List[schemas.TaskRead])
async def list_tasks(db: Session = Depends(get_db)):
    return crud.get_tasks(db)


@app.post("/tasks", response_model=schemas.TaskRead, status_code=status.HTTP_201_CREATED)
async def create_task(task_in: schemas.TaskCreate, db: Session = Depends(get_db)):
    return crud.create_task(db, task_in)


@app.get("/tasks/{task_id}", response_model=schemas.TaskRead)
async def get_task(task_id: int, db: Session = Depends(get_db)):
    task = crud.get_task(db, task_id)
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
    return task


@app.put("/tasks/{task_id}", response_model=schemas.TaskRead)
async def update_task(task_id: int, task_in: schemas.TaskUpdate, db: Session = Depends(get_db)):
    task = crud.update_task(db, task_id, task_in)
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
    return task


@app.delete("/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_task(task_id: int, db: Session = Depends(get_db)):
    success = crud.delete_task(db, task_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
    return None
```

- This uses **async endpoints + sync CRUD**, with `TaskRead` as the response model.

**Checkpoint 4 (Backend API Surface):**
- `/token` issues JWTs for `demo@example.com` and `admin@example.com`.
- `/tasks` CRUD endpoints compile and import `models`, `schemas`, `crud`, and `get_db`.
- CORS allows `http://localhost:4200` and `4201` (ready for Angular).

### 2.10. Run and Test the Backend

```powershell
# From backend folder (with venv activated)
uvicorn app.main:app --reload --port 8000
```

- Open `http://localhost:8000/docs`.
- Test `/token` with:
  - `demo@example.com` / `password123`
- Authorize with the returned token and exercise the `/tasks` endpoints.

**Checkpoint 5 (Backend Functional):**
- You can obtain a JWT from `/token` using lab credentials.
- You can create, list, update, and delete tasks via Swagger.
- The `tasks.db` SQLite file is created in the `backend/` folder.

---

## 3. Frontend – Angular 20 (Incremental)

We now build the Angular frontend in the `frontend/` folder.

### 3.1. Create Angular App

```powershell
cd ..  # from backend back to task-manager-lab
cd frontend

ng new task-manager-frontend --routing=true --style=css --standalone
cd task-manager-frontend
```

### 3.2. Generate Components, Services, Guard, Interceptor

```powershell
ng generate component tasks --standalone
ng generate component task-detail --standalone
ng generate component login --standalone
ng generate component confirmation-modal --standalone
ng generate service task
ng generate service auth
ng generate guard auth
ng generate interceptor http-error

**Checkpoint 6 (Angular Scaffolding):**
- Angular workspace `task-manager-frontend/` builds without errors (`ng serve` works).
- Components, services, guard, and interceptor files exist under `src/app/`.
```

### 3.3. Implement Auth Service (`src/app/auth.service.ts`)

```typescript
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, tap } from 'rxjs';

interface LoginResponse {
  access_token: string;
  token_type: string;
  user: { email: string; full_name: string };
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private apiUrl = 'http://localhost:8000';
  private readonly TOKEN_KEY = 'auth_token';
  private readonly USER_KEY = 'auth_user';

  constructor(private http: HttpClient) {}

  login(email: string, password: string): Observable<LoginResponse> {
    const formData = new FormData();
    formData.append('username', email);
    formData.append('password', password);

    return this.http.post<LoginResponse>(`${this.apiUrl}/token`, formData).pipe(
      tap(response => {
        localStorage.setItem(this.TOKEN_KEY, response.access_token);
        localStorage.setItem(this.USER_KEY, JSON.stringify(response.user));
      })
    );
  }

  logout(): void {
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.USER_KEY);
  }

  getToken(): string | null {
    return localStorage.getItem(this.TOKEN_KEY);
  }

  isAuthenticated(): boolean {
    return !!this.getToken();
  }

  getCurrentUser(): any {
    const user = localStorage.getItem(this.USER_KEY);
    return user ? JSON.parse(user) : null;
  }
}
```

### 3.4. Implement Auth Guard (`src/app/auth.guard.ts`)

```typescript
import { inject } from '@angular/core';
import { Router, CanActivateFn } from '@angular/router';
import { AuthService } from './auth.service';

export const AuthGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.isAuthenticated()) {
    return true;
  }

  return router.createUrlTree(['/login']);
};
```

### 3.5. Implement HTTP Interceptor (`src/app/http-error.interceptor.ts`)

```typescript
import { Injectable } from '@angular/core';
import {
  HttpInterceptor,
  HttpRequest,
  HttpHandler,
  HttpErrorResponse,
} from '@angular/common/http';
import { catchError, throwError } from 'rxjs';
import { AuthService } from './auth.service';

@Injectable()
export class HttpErrorInterceptor implements HttpInterceptor {
  constructor(private authService: AuthService) {}

  intercept(request: HttpRequest<any>, next: HttpHandler) {
    const token = this.authService.getToken();
    if (token) {
      request = request.clone({
        setHeaders: { Authorization: `Bearer ${token}` },
      });
    }

    return next.handle(request).pipe(
      catchError((error: HttpErrorResponse) => {
        console.error('HTTP error', error);
        return throwError(() => error);
      })
    );
  }
}
```

### 3.6. Implement Task Service (`src/app/task.service.ts`)

```typescript
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface Task {
  id: number;
  title: string;
  description?: string;
  done: boolean;
  created_at: string;
}

@Injectable({ providedIn: 'root' })
export class TaskService {
  apiUrl = 'http://localhost:8000/tasks/';

  constructor(private http: HttpClient) {}

  getTasks(): Observable<Task[]> {
    return this.http.get<Task[]>(this.apiUrl);
  }

  getTask(id: number): Observable<Task> {
    return this.http.get<Task>(`${this.apiUrl}${id}`);
  }

  addTask(task: Partial<Task>): Observable<Task> {
    return this.http.post<Task>(this.apiUrl, task);
  }

  updateTask(task: Task): Observable<Task> {
    return this.http.put<Task>(`${this.apiUrl}${task.id}`, task);
  }

  deleteTask(id: number): Observable<any> {
    return this.http.delete(`${this.apiUrl}${id}`);
  }
}
```

### 3.7. Configure Routes (`src/app/app-routing.module.ts`)

```typescript
import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { TasksComponent } from './tasks/tasks.component';
import { TaskDetailComponent } from './task-detail/task-detail.component';
import { LoginComponent } from './login/login.component';
import { AuthGuard } from './auth.guard';

export const routes: Routes = [
  { path: '', redirectTo: '/login', pathMatch: 'full' },
  { path: 'login', component: LoginComponent },
  { path: 'tasks', component: TasksComponent, canActivate: [AuthGuard] },
  { path: 'tasks/:id', component: TaskDetailComponent, canActivate: [AuthGuard] },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
```

### 3.8. Wire Up Bootstrap (`src/main.ts`)

```typescript
import { bootstrapApplication } from '@angular/platform-browser';
import { provideRouter } from '@angular/router';
import { importProvidersFrom } from '@angular/core';
import {
  HttpClientModule,
  HTTP_INTERCEPTORS,
} from '@angular/common/http';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';

import { AppComponent } from './app/app.component';
import { routes } from './app/app-routing.module';
import { HttpErrorInterceptor } from './app/http-error.interceptor';

bootstrapApplication(AppComponent, {
  providers: [
    provideRouter(routes),
    importProvidersFrom(HttpClientModule, FormsModule, ReactiveFormsModule),
    {
      provide: HTTP_INTERCEPTORS,
      useClass: HttpErrorInterceptor,
      multi: true,
    },
  ],
}).catch(err => console.error(err));

**Checkpoint 7 (Frontend Infrastructure):**
- `AuthService`, `AuthGuard`, `HttpErrorInterceptor`, and `TaskService` compile.
- Routes protect `/tasks` and `/tasks/:id` using `AuthGuard`.
- Bootstrap in `main.ts` wires router + interceptor.
```

### 3.9. Implement Login & Task Components

#### 3.9.1. LoginComponent (reactive form + navigation)

The login page uses a reactive form and talks to `AuthService` to obtain a JWT from `/token`.

In `src/app/login/login.component.ts`, implement a standalone component that:

- Defines a reactive form group with `email` (required, email format) and `password` (required, min length 6).
- Calls `authService.login(email, password)` on submit and navigates to `/tasks` on success.
- Handles errors with a friendly message depending on the HTTP status.
- Supports a **Skip to Tasks** button and a dismissable error banner.
- Provides an expandable **Test Credentials** section showing the demo accounts.

You can use this implementation:

```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { AuthService } from '../auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  templateUrl: './login.component.html',
  imports: [CommonModule, ReactiveFormsModule, RouterModule],
})
export class LoginComponent {
  loginForm: FormGroup;
  isLoading = false;
  errorMessage = '';
  isCredentialsExpanded = false;

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router
  ) {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(6)]],
    });
  }

  toggleCredentials(): void {
    this.isCredentialsExpanded = !this.isCredentialsExpanded;
  }

  onLogin(): void {
    if (this.loginForm.invalid) {
      this.errorMessage = 'Please fill in all fields correctly.';
      return;
    }

    this.isLoading = true;
    this.errorMessage = '';

    const { email, password } = this.loginForm.value;

    this.authService.login(email, password).subscribe({
      next: () => {
        this.router.navigate(['/tasks']);
      },
      error: (error) => {
        if (error.status === 401) {
          this.errorMessage = 'Incorrect email or password. Please try again.';
        } else if (error.status === 0) {
          this.errorMessage = 'Cannot connect to server. Please check if the backend is running.';
        } else {
          this.errorMessage = 'An error occurred during login. Please try again.';
        }
        this.isLoading = false;
      },
    });
  }

  skipLogin(): void {
    this.router.navigate(['/tasks']);
  }

  dismissError(): void {
    this.errorMessage = '';
  }
}
```

In `src/app/login/login.component.html`, you can use this template:

```html
<div class="login-container">
  <div class="login-card">
    <div class="login-header">
      <h2>Task Manager</h2>
      <p class="subtitle">Sign in to continue</p>
    </div>

    <div class="error-banner" *ngIf="errorMessage">
      <span class="error-icon">⚠</span>
      <span class="error-text">{{ errorMessage }}</span>
      <button class="error-close" (click)="dismissError()" aria-label="Close">×</button>
    </div>

    <form [formGroup]="loginForm" (ngSubmit)="onLogin()" class="login-form">
      <div class="form-group">
        <label for="email">Email</label>
        <input
          type="email"
          id="email"
          formControlName="email"
          class="form-input"
          [class.invalid]="loginForm.get('email')?.invalid && loginForm.get('email')?.touched"
          placeholder="demo@example.com"
          [disabled]="isLoading"
        />
        <div class="error-message" *ngIf="loginForm.get('email')?.invalid && loginForm.get('email')?.touched">
          <span *ngIf="loginForm.get('email')?.errors?.['required']">Email is required</span>
          <span *ngIf="loginForm.get('email')?.errors?.['email']">Please enter a valid email</span>
        </div>
      </div>

      <div class="form-group">
        <label for="password">Password</label>
        <input
          type="password"
          id="password"
          formControlName="password"
          class="form-input"
          [class.invalid]="loginForm.get('password')?.invalid && loginForm.get('password')?.touched"
          placeholder="Enter your password"
          [disabled]="isLoading"
        />
        <div class="error-message" *ngIf="loginForm.get('password')?.invalid && loginForm.get('password')?.touched">
          <span *ngIf="loginForm.get('password')?.errors?.['required']">Password is required</span>
          <span *ngIf="loginForm.get('password')?.errors?.['minlength']">
            Password must be at least 6 characters
          </span>
        </div>
      </div>

      <div class="login-actions">
        <button type="submit" class="btn btn-primary" [disabled]="isLoading || loginForm.invalid">
          <span *ngIf="!isLoading">Sign In</span>
          <span *ngIf="isLoading" class="spinner"></span>
          <span *ngIf="isLoading">Signing in...</span>
        </button>

        <button type="button" class="btn btn-secondary" (click)="skipLogin()" [disabled]="isLoading">
          Skip to Tasks
        </button>
      </div>
    </form>

    <div class="login-info">
      <div class="info-box">
        <div class="info-header" (click)="toggleCredentials()">
          <span class="toggle-arrow" [class.expanded]="isCredentialsExpanded">▶</span>
          <span class="info-icon">ℹ️</span>
          <p class="info-title"><strong>Test Credentials</strong></p>
        </div>
        <div class="info-content" *ngIf="isCredentialsExpanded">
          <ul>
            <li>Email: <code>demo@example.com</code> / Password: <code>password123</code></li>
            <li>Email: <code>admin@example.com</code> / Password: <code>admin123</code></li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</div>
```

You can copy styles from the reference solution or keep the layout minimal; the important behavior is:

- Validating input before submit.
- Calling `AuthService.login(...)`.
- Handling error cases.
- Navigating to `/tasks` on success.

#### 3.9.2. TasksComponent (list, checkbox toggle, toaster, confirmation modal)

The tasks page (`/tasks`) is responsible for:

- Loading all tasks from `TaskService.getTasks()` on init.
- Letting the user **add** a new task (title + optional description).
- Letting the user **mark a task as done/undone** via a checkbox.
- Letting the user **delete** a task with a styled confirmation popup (no raw `confirm()` calls).
- Showing **loading** and **error** states.
- Showing small **toaster messages** for success, warning, and error events.

In `src/app/tasks/tasks.component.ts`, implement this standalone component:

```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { Task, TaskService } from '../task.service';
import { ConfirmationModalComponent } from '../confirmation-modal/confirmation-modal.component';

@Component({
  selector: 'app-tasks',
  templateUrl: './tasks.component.html',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule, ConfirmationModalComponent]
})
export class TasksComponent implements OnInit {
  tasks: Task[] = [];
  newTask: Partial<Task> = {};

  isLoading = false;
  errorMessage = '';

  showDeleteModal = false;
  taskToDelete: number | null = null;

  constructor(private taskService: TaskService) {}

  ngOnInit(): void {
    this.loadTasks();
  }

  loadTasks(): void {
    this.isLoading = true;
    this.errorMessage = '';

    this.taskService.getTasks().subscribe({
      next: (data) => {
        this.tasks = data;
        this.isLoading = false;
      },
      error: (error) => {
        this.errorMessage = 'Failed to load tasks. Please check if the backend is running.';
        this.showToaster('error', this.errorMessage);
        console.error('Error loading tasks:', error);
        this.isLoading = false;
      }
    });
  }

  addTask(): void {
    if (!this.newTask.title?.trim()) {
      this.showToaster('warning', 'Please enter a task title.');
      return;
    }

    if (this.isLoading) {
      return;
    }

    this.isLoading = true;
    this.errorMessage = '';

    this.taskService.addTask(this.newTask).subscribe({
      next: () => {
        this.showToaster('success', 'Task added successfully!');
        this.newTask = {};
        this.loadTasks();
        this.isLoading = false;
      },
      error: (error) => {
        this.errorMessage = 'Failed to add task. Please try again.';
        this.showToaster('error', this.errorMessage);
        console.error('Error adding task:', error);
        this.isLoading = false;
      }
    });
  }

  updateTask(task: Task): void {
    this.errorMessage = '';

    this.taskService.updateTask(task).subscribe({
      next: () => {
        const status = task.done ? 'completed' : 'reopened';
        this.showToaster('success', `Task marked as ${status}.`);
        this.loadTasks();
      },
      error: (error) => {
        this.errorMessage = 'Failed to update task. Please try again.';
        this.showToaster('error', this.errorMessage);
        console.error('Error updating task:', error);
        task.done = !task.done;
      }
    });
  }

  deleteTask(id: number): void {
    this.taskToDelete = id;
    this.showDeleteModal = true;
  }

  confirmDelete(): void {
    if (this.taskToDelete === null) return;

    this.errorMessage = '';

    this.taskService.deleteTask(this.taskToDelete).subscribe({
      next: () => {
        this.showToaster('success', 'Task deleted successfully.');
        this.loadTasks();
      },
      error: (error) => {
        this.errorMessage = 'Failed to delete task. Please try again.';
        this.showToaster('error', this.errorMessage);
        console.error('Error deleting task:', error);
      }
    });

    this.taskToDelete = null;
  }

  cancelDelete(): void {
    this.taskToDelete = null;
  }

  private showToaster(type: 'success' | 'error' | 'warning' | 'info', message: string): void {
    const container = this.getOrCreateToasterContainer();
    const toaster = document.createElement('div');
    toaster.className = `toaster ${type}`;

    const icons = {
      success: '✓',
      error: '✕',
      warning: '⚠',
      info: 'ℹ'
    };

    toaster.innerHTML = `
      <span class="toaster-icon">${icons[type]}</span>
      <span class="toaster-message">${message}</span>
      <button class="toaster-close" aria-label="Close">×</button>
    `;

    container.appendChild(toaster);

    const closeBtn = toaster.querySelector('.toaster-close');
    closeBtn?.addEventListener('click', () => this.removeToaster(toaster as HTMLElement));

    setTimeout(() => this.removeToaster(toaster as HTMLElement), 5000);
  }

  private getOrCreateToasterContainer(): HTMLElement {
    let container = document.querySelector('.toaster-container') as HTMLElement;
    if (!container) {
      container = document.createElement('div');
      container.className = 'toaster-container';
      document.body.appendChild(container);
    }
    return container;
  }

  private removeToaster(toaster: HTMLElement): void {
    toaster.style.animation = 'slideOut 0.3s ease-out';
    setTimeout(() => toaster.remove(), 300);
  }
}
```

The key behavior for the **checkbox** is:

- The `[checked]` state is bound to `task.done`.
- When the checkbox is toggled, `updateTask(task)` is called.
- If the backend call fails, `task.done` is flipped back so the UI stays consistent.

In `src/app/tasks/tasks.component.html`, you can use this template:

```html
<div class="tasks-container">
  <div *ngIf="errorMessage" class="error-banner">
    <span class="error-icon">⚠️</span>
    <span>{{ errorMessage }}</span>
    <button (click)="errorMessage = ''" class="error-close">×</button>
  </div>

  <div class="card add-task-card">
    <h2 class="card-title">
      <span class="icon">➕</span>
      Add New Task
    </h2>
    <form class="add-task-form" (submit)="addTask(); $event.preventDefault()">
      <div class="form-group">
        <label for="task-title">Title <span class="required">*</span></label>
        <input
          id="task-title"
          type="text"
          [(ngModel)]="newTask.title"
          name="title"
          placeholder="Enter task title"
          class="form-input"
          [disabled]="isLoading"
          required
        />
      </div>
      <div class="form-group">
        <label for="task-description">Description</label>
        <textarea
          id="task-description"
          [(ngModel)]="newTask.description"
          name="description"
          placeholder="Enter task description"
          class="form-input form-textarea"
          [disabled]="isLoading"
          rows="3"
        ></textarea>
      </div>
      <div class="form-legend">
        <span class="required">*</span> - fields are mandatory
      </div>
      <button type="submit" class="btn btn-primary" [disabled]="isLoading">
        <span *ngIf="!isLoading" class="btn-icon">✓</span>
        <span *ngIf="isLoading" class="spinner-small"></span>
        <span *ngIf="!isLoading">Add Task</span>
        <span *ngIf="isLoading">Adding...</span>
      </button>
    </form>
  </div>

  <div class="card tasks-list-card">
    <h2 class="card-title">
      <span class="icon">📋</span>
      Your Tasks
      <span class="task-count">{{ tasks.length }}</span>
    </h2>

    <div *ngIf="isLoading && tasks.length === 0" class="loading-container">
      <div class="spinner"></div>
      <p>Loading tasks...</p>
    </div>

    <div *ngIf="!isLoading && tasks.length === 0" class="empty-state">
      <div class="empty-icon">📝</div>
      <p>No tasks yet. Create your first task above!</p>
    </div>

    <ul class="tasks-list" *ngIf="tasks.length > 0">
      <li *ngFor="let task of tasks" class="task-item" [class.completed]="task.done">
        <div class="task-checkbox">
          <input
            type="checkbox"
            [id]="'task-' + task.id"
            [(ngModel)]="task.done"
            (change)="updateTask(task)"
            class="checkbox-input"
          />
          <label [for]="'task-' + task.id" class="checkbox-label"></label>
        </div>
        <div class="task-content">
          <h3 class="task-title">
            <a [routerLink]="['/tasks', task.id]" class="task-link">{{ task.title }}</a>
          </h3>
          <p class="task-description" *ngIf="task.description">{{ task.description }}</p>
        </div>
        <button
          (click)="deleteTask(task.id)"
          class="btn btn-danger btn-icon-only"
          aria-label="Delete task"
          title="Delete task"
        >
          <span class="btn-icon">🗑️</span>
        </button>
      </li>
    </ul>
  </div>
</div>

<app-confirmation-modal
  [(show)]="showDeleteModal"
  title="Delete Task"
  message="Are you sure you want to delete this task? This action cannot be undone."
  confirmText="Delete"
  cancelText="Cancel"
  (onConfirm)="confirmDelete()"
  (onCancel)="cancelDelete()">
</app-confirmation-modal>
```

#### 3.9.3. ConfirmationModalComponent (reusable confirmation popup)

The confirmation popup is a **reusable standalone component** used by `TasksComponent` when deleting a task.

In `src/app/confirmation-modal/confirmation-modal.component.ts`, you can use this implementation:

```typescript
import { Component, EventEmitter, Input, Output } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-confirmation-modal',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="modal-overlay" *ngIf="show" (click)="onCancelClick()">
      <div class="modal-content" (click)="$event.stopPropagation()">
        <div class="modal-header">
          <h3>{{ title }}</h3>
        </div>
        <div class="modal-body">
          <p>{{ message }}</p>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" (click)="onCancelClick()" type="button">
            {{ cancelText }}
          </button>
          <button class="btn btn-danger" (click)="onConfirmClick()" type="button" [autofocus]="true">
            {{ confirmText }}
          </button>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.5);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      animation: fadeIn 0.2s ease-out;
    }

    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }

    .modal-content {
      background: white;
      border-radius: 12px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
      max-width: 450px;
      width: 90%;
      animation: slideUp 0.2s ease-out;
    }

    @keyframes slideUp {
      from { transform: translateY(20px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }

    .modal-header {
      padding: 1.5rem;
      border-bottom: 1px solid #e5e7eb;
    }

    .modal-header h3 {
      margin: 0;
      color: #1f2937;
      font-size: 1.25rem;
      font-weight: 600;
    }

    .modal-body {
      padding: 1.5rem;
    }

    .modal-body p {
      margin: 0;
      color: #4b5563;
      line-height: 1.6;
    }

    .modal-footer {
      padding: 1rem 1.5rem;
      border-top: 1px solid #e5e7eb;
      display: flex;
      justify-content: flex-end;
      gap: 0.75rem;
    }

    .btn {
      padding: 0.625rem 1.25rem;
      border-radius: 8px;
      border: none;
      font-size: 0.875rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
    }

    .btn-secondary {
      background: #f3f4f6;
      color: #374151;
    }

    .btn-secondary:hover {
      background: #e5e7eb;
    }

    .btn-danger {
      background: #dc2626;
      color: white;
    }

    .btn-danger:hover {
      background: #b91c1c;
    }

    .btn:focus {
      outline: 2px solid #3b82f6;
      outline-offset: 2px;
    }
  `]
})
export class ConfirmationModalComponent {
  @Input() show = false;
  @Input() title = 'Confirm Action';
  @Input() message = 'Are you sure you want to proceed?';
  @Input() confirmText = 'OK';
  @Input() cancelText = 'Cancel';

  @Output() showChange = new EventEmitter<boolean>();
  @Output() onConfirm = new EventEmitter<void>();
  @Output() onCancel = new EventEmitter<void>();

  onConfirmClick(): void {
    this.show = false;
    this.showChange.emit(this.show);
    this.onConfirm.emit();
  }

  onCancelClick(): void {
    this.show = false;
    this.showChange.emit(this.show);
    this.onCancel.emit();
  }
}
```

#### 3.9.4. TaskDetailComponent (single task view with checkbox)

The task detail page (`/tasks/:id`) lets users edit a single task and also toggle its **done** checkbox.

In `src/app/task-detail/task-detail.component.ts`, you can use this implementation:

```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { Task, TaskService } from '../task.service';

@Component({
  selector: 'app-task-detail',
  templateUrl: './task-detail.component.html',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule]
})
export class TaskDetailComponent implements OnInit {
  taskForm!: FormGroup;
  isLoading = false;
  errorMessage = '';
  taskId: number | null = null;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private taskService: TaskService,
    private formBuilder: FormBuilder
  ) {}

  ngOnInit(): void {
    this.initializeForm();

    const id = this.route.snapshot.paramMap.get('id');
    if (id) {
      this.taskId = parseInt(id, 10);
      this.loadTask(this.taskId);
    } else {
      this.errorMessage = 'No task ID provided';
    }
  }

  private initializeForm(): void {
    this.taskForm = this.formBuilder.group({
      title: ['', [Validators.required, Validators.minLength(3)]],
      description: [''],
      done: [false]
    });
  }

  loadTask(id: number): void {
    this.isLoading = true;
    this.errorMessage = '';

    this.taskService.getTask(id).subscribe({
      next: (task: Task) => {
        this.taskForm.patchValue({
          title: task.title,
          description: task.description || '',
          done: task.done
        });
        this.isLoading = false;
      },
      error: (error) => {
        console.error('Error loading task:', error);
        this.errorMessage = 'Failed to load task. It may have been deleted.';
        this.isLoading = false;
      }
    });
  }

  onSubmit(): void {
    if (this.taskForm.invalid || !this.taskId) {
      return;
    }

    this.isLoading = true;
    this.errorMessage = '';

    const updatedTask: Task = {
      id: this.taskId,
      ...this.taskForm.value
    };

    this.taskService.updateTask(updatedTask).subscribe({
      next: () => {
        this.isLoading = false;
        this.router.navigate(['/tasks']);
      },
      error: (error) => {
        console.error('Error updating task:', error);
        this.errorMessage = 'Failed to update task. Please try again.';
        this.isLoading = false;
      }
    });
  }

  onDelete(): void {
    if (!this.taskId || !confirm('Are you sure you want to delete this task?')) {
      return;
    }

    this.isLoading = true;
    this.errorMessage = '';

    this.taskService.deleteTask(this.taskId).subscribe({
      next: () => {
        this.isLoading = false;
        this.router.navigate(['/tasks']);
      },
      error: (error) => {
        console.error('Error deleting task:', error);
        this.errorMessage = 'Failed to delete task. Please try again.';
        this.isLoading = false;
      }
    });
  }

  onCancel(): void {
    this.router.navigate(['/tasks']);
  }
}
```

In `src/app/task-detail/task-detail.component.html`, you can use this template:

```html
<div class="task-detail-container">
  <div class="breadcrumb">
    <a routerLink="/tasks" class="breadcrumb-link">← Back to Tasks</a>
  </div>

  <div class="detail-header">
    <h2>Edit Task</h2>
  </div>

  <div *ngIf="isLoading" class="loading-spinner">
    <div class="spinner"></div>
    <p>Loading task details...</p>
  </div>

  <div *ngIf="errorMessage" class="error-message">
    <span class="error-icon">⚠</span>
    <span>{{ errorMessage }}</span>
  </div>

  <form [formGroup]="taskForm" (ngSubmit)="onSubmit()" *ngIf="!isLoading && !errorMessage">
    <div class="form-group">
      <label for="title">Title *</label>
      <input
        id="title"
        type="text"
        formControlName="title"
        class="form-control"
        [class.invalid]="taskForm.get('title')?.invalid && taskForm.get('title')?.touched"
      />
      <div class="validation-error" *ngIf="taskForm.get('title')?.invalid && taskForm.get('title')?.touched">
        <span *ngIf="taskForm.get('title')?.errors?.['required']">Title is required</span>
        <span *ngIf="taskForm.get('title')?.errors?.['minlength']">Title must be at least 3 characters</span>
      </div>
    </div>

    <div class="form-group">
      <label for="description">Description</label>
      <textarea
        id="description"
        formControlName="description"
        class="form-control"
        rows="4"
      ></textarea>
    </div>

    <div class="form-group checkbox-group">
      <label>
        <input type="checkbox" formControlName="done" />
        <span>Mark as done</span>
      </label>
    </div>

    <div class="button-group">
      <button
        type="submit"
        class="btn btn-primary"
        [disabled]="taskForm.invalid || isLoading"
      >
        <span *ngIf="!isLoading">Save Changes</span>
        <span *ngIf="isLoading">Saving...</span>
      </button>

      <button
        type="button"
        class="btn btn-danger"
        (click)="onDelete()"
        [disabled]="isLoading"
      >
        Delete Task
      </button>

      <button
        type="button"
        class="btn btn-secondary"
        (click)="onCancel()"
        [disabled]="isLoading"
      >
        Cancel
      </button>
    </div>
  </form>
</div>
```

**Checkpoint 8 (UX & Flow):**
- Login page appears at `/login`.
- After successful login, navigation to `/tasks` works.
- `/tasks` shows a task list with add, checkbox toggle, toaster notifications, and a confirmation popup for delete.
- From `/tasks`, you can drill into `/tasks/:id`, edit a task (including its done status), and navigate back.

### 3.10. Run and Test the Frontend

```powershell
cd task-manager-frontend
npm install
npm start
```

- Open `http://localhost:4200`.
- Log in with `demo@example.com` / `password123`.
- Verify that `/tasks` is protected by the guard and that CRUD operations work end-to-end.

**Checkpoint 9 (Full-Stack Ready):**
- Unauthenticated access to `/tasks` redirects to `/login`.
- Authenticated users see task list and can create/edit/delete tasks.
- Network tab shows requests to `http://localhost:8000/tasks/` with `Authorization: Bearer ...` header.

---

## 4. Pattern Spotlight: Async Endpoints + Sync CRUD

- FastAPI endpoints are `async def`, giving you high concurrency and responsiveness.
- Database access uses synchronous SQLAlchemy, run in a thread pool by FastAPI.
- The schemas use `TaskRead` consistently as the response model.
- JWT tokens use `sub = user["username"]`, matching the mock user store.

This incremental lab walks you from an empty `task-manager-lab` folder to a working FastAPI + Angular task manager that demonstrates the core concepts:

- Build a modern async FastAPI backend with a JWT-based login endpoint.
- Use clean separation of concerns (models, schemas, CRUD, main app).
- Implement an Angular 20 frontend with route guards, interceptors, and reactive forms.
- Wire up a basic login experience and protected routes on the frontend.

The authentication pieces in this lab are intentionally minimal and focus on understanding the flow (issuing tokens, storing them, attaching them to requests, and guarding routes). In a production application, you can extend the same patterns to enforce authentication on all APIs, add user registration and identity management, and implement more advanced authorization rules.
