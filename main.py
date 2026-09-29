"""HTTP routes: authentication, owned projects, durable runs, and live updates."""

import asyncio
import hmac
import re
import secrets
import shutil
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Form, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from starlette.background import BackgroundTask
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import ROOT, settings
from .database import (
    Checkpoint,
    Event,
    GitCommit,
    Project,
    Run,
    SessionLocal,
    TestRun,
    User,
    init_db,
    utcnow,
)
from .graph import execute_run, resume_details
from .schemas import ChatRequest
from .security import hash_password, verify_password
from .services.shared_demo import initialize_shared_demo
from .services.demo_service import demos
from .services.events import bus, event_dict
from .services.git_service import GitService
from .services.project_export import build_project_zip
from .tools.runtime import WorkspaceTools

active_tasks: dict[int, asyncio.Task] = {}
login_attempts = defaultdict(deque)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.prepare()
    init_db()
    await initialize_shared_demo()
    await demos.recover()
    with SessionLocal() as db:
        for project in db.scalars(select(Project)):
            if project.active_run_id:
                run = db.get(Run, project.active_run_id)
                if run:
                    run.status = "interrupted"
                    run.error = "The server restarted during this run. Review saved work and submit a new request."
                    run.finished_at = utcnow()
                project.active_run_id = None
                project.status = "interrupted"
            project.demo_status = "stopped"
            project.demo_url = None
        db.commit()
    yield
    for task in list(active_tasks.values()):
        task.cancel()
    if active_tasks:
        await asyncio.gather(*list(active_tasks.values()), return_exceptions=True)
    await demos.stop_all()


async def csrf_guard(request: Request = None) -> None:
    # WebSockets enforce their own authenticated origin check below.
    if request is None:
        return
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    expected = request.session.get("csrf", "")
    token = request.headers.get("x-csrf-token", "")
    if not token and "application/json" not in request.headers.get("content-type", ""):
        token = str((await request.form()).get("csrf_token", ""))
    if not expected or not token or not hmac.compare_digest(expected, token):
        raise HTTPException(403, "Your session expired. Refresh the page and try again.")
    origin = request.headers.get("origin")
    if origin and urlparse(origin).netloc != request.headers.get("host"):
        raise HTTPException(403, "Cross-origin request rejected.")


app = FastAPI(title="ForgeFlow", lifespan=lifespan, dependencies=[Depends(csrf_guard)])
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key.get_secret_value() or "setup-required",
    session_cookie="forgeflow_session",
    https_only=settings.cookie_secure,
    same_site="strict",
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts.split(","))
app.mount("/static", StaticFiles(directory=ROOT / "app/static"), name="static")
templates = Jinja2Templates(directory=ROOT / "app/templates")


def db_session():
    with SessionLocal() as db:
        yield db


def current_user(request: Request, db=Depends(db_session)) -> User:
    user = db.get(User, request.session.get("user_id", -1))
    if not user:
        raise HTTPException(401, "Sign in to continue.")
    return user


def own_project(project_id: int, user: User, db) -> Project:
    project = db.get(Project, project_id)
    if not project or project.owner_id != user.id:
        raise HTTPException(404, "Project not found.")
    root = Path(project.workspace_path).resolve()
    if (
        not root.is_relative_to(settings.workspace_root.resolve())
        or root == settings.workspace_root.resolve()
    ):
        raise HTTPException(400, "Invalid project workspace.")
    return project


def render(request: Request, name: str, context: dict | None = None, status: int = 200):
    request.session.setdefault("csrf", secrets.token_urlsafe(32))
    return templates.TemplateResponse(
        request=request,
        name=name,
        context={
            "csrf": request.session["csrf"],
            "username": request.session.get("username"),
            "execution_mode": settings.execution_mode,
            **(context or {}),
        },
        status_code=status,
    )


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    if "text/html" in request.headers.get("accept", ""):
        if exc.status_code == 401:
            return RedirectResponse("/login", 303)
        return render(
            request,
            "error.html",
            {"error": exc.detail, "status_code": exc.status_code},
            exc.status_code,
        )
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.get("/health")
def health(db=Depends(db_session)):
    db.execute(select(1))
    return {
        "status": "ok",
        "database": "postgresql" if settings.database_url.startswith("postgresql") else "sqlite",
        "execution": settings.execution_mode,
    }


@app.get("/")
def home(request: Request):
    return RedirectResponse("/dashboard" if request.session.get("user_id") else "/login", 303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render(request, "login.html")


@app.post("/register")
def register(
    request: Request, username: str = Form(...), password: str = Form(...), db=Depends(db_session)
):
    username = username.strip().lower()
    if not re.fullmatch("[a-z0-9][a-z0-9-]{2,39}", username) or not 10 <= len(password) <= 200:
        return render(
            request,
            "login.html",
            {
                "error": "Use a 3â€“40 character username (letters, numbers, hyphens) and a password of at least 10 characters."
            },
            400,
        )
    user = User(username=username, password_hash=hash_password(password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return render(request, "login.html", {"error": "That username is already taken."}, 400)
    request.session.clear()
    request.session.update(user_id=user.id, username=user.username, csrf=secrets.token_urlsafe(32))
    return RedirectResponse("/dashboard", 303)


@app.post("/login")
def login(
    request: Request, username: str = Form(...), password: str = Form(...), db=Depends(db_session)
):
    username = username.strip().lower()
    identity = (request.client.host if request.client else "local", username)
    attempts = login_attempts[identity]
    now = time.monotonic()
    while attempts and attempts[0] < now - 60:
        attempts.popleft()
    if len(attempts) >= 8:
        return render(
            request, "login.html", {"error": "Too many attempts. Try again in a minute."}, 429
        )
    attempts.append(now)
    user = db.scalar(select(User).where(User.username == username))
    if not user or len(password) > 200 or not verify_password(password, user.password_hash):
        return render(request, "login.html", {"error": "Username or password is incorrect."}, 400)
    attempts.clear()
    request.session.clear()
    request.session.update(user_id=user.id, username=user.username, csrf=secrets.token_urlsafe(32))
    return RedirectResponse("/dashboard", 303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", 303)


@app.get("/dashboard")
@app.get("/projects")
def dashboard(request: Request, user=Depends(current_user), db=Depends(db_session)):
    projects = list(
        db.scalars(select(Project).where(Project.owner_id == user.id).order_by(Project.id.desc()))
    )
    return render(
        request,
        "dashboard.html",
        {
            "projects": projects,
            "model": settings.llm_model,
            "key_configured": bool(
                settings.llm_api_key.get_secret_value()
                or settings.openrouter_api_key.get_secret_value()
            ),
        },
    )


@app.get("/guide")
def guide(request: Request, user=Depends(current_user)):
    return render(request, "guide.html")


@app.get("/settings")
def configuration(request: Request, user=Depends(current_user)):
    values = [
        ("Provider", settings.llm_provider),
        ("Model", settings.llm_model),
        (
            "Primary credential",
            "Configured"
            if settings.llm_api_key.get_secret_value()
            or settings.openrouter_api_key.get_secret_value()
            else "Missing",
        ),
        (
            "Backup credential",
            "Configured"
            if settings.llm_backup_api_key.get_secret_value()
            or settings.openrouter_backup_api_key.get_secret_value()
            else "Not configured",
        ),
        ("Execution", settings.execution_mode),
        (
            "Maximum repair attempts",
            "Unlimited" if settings.max_iterations == -1 else settings.max_iterations,
        ),
        (
            "Maximum developer steps",
            "Unlimited" if settings.max_agent_steps == -1 else settings.max_agent_steps,
        ),
        (
            "Maximum model calls per run",
            "Unlimited"
            if settings.max_model_calls_per_run == -1
            else settings.max_model_calls_per_run,
        ),
        (
            "Maximum tokens per run",
            "Unlimited" if settings.max_tokens_per_run == -1 else settings.max_tokens_per_run,
        ),
        (
            "Response token limit",
            "Provider default" if settings.llm_max_tokens == -1 else settings.llm_max_tokens,
        ),
        (
            "Maximum run time",
            "Unlimited"
            if settings.max_run_seconds == -1
            else str(settings.max_run_seconds // 60) + " minutes",
        ),
        (
            "Git destination",
            "GitHub (configured)" if settings.git_remote_url else "Local Git mirror",
        ),
        ("Database", "PostgreSQL" if settings.database_url.startswith("postgresql") else "SQLite"),
    ]
    return render(request, "settings.html", {"configuration": values})


@app.post("/projects")
async def create_project(
    request: Request, name: str = Form(...), user=Depends(current_user), db=Depends(db_session)
):
    name = name.strip()
    if not 1 <= len(name) <= 120:
        raise HTTPException(422, "Project name must contain 1 to 120 characters.")
    slug = re.sub("[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "project"
    slug += "-" + secrets.token_hex(4)
    path = settings.workspace_root / slug
    path.mkdir(parents=True)
    branch = "user/" + user.username
    try:
        remote = await GitService().prepare(path, branch, settings.git_remote_url)
    except Exception as exc:
        raise HTTPException(503, f"Git setup failed: {str(exc)[:300]}") from exc
    project = Project(
        owner_id=user.id,
        name=name,
        slug=slug,
        workspace_path=str(path),
        branch=branch,
        remote_url=remote,
    )
    db.add(project)
    db.commit()
    return RedirectResponse(f"/projects/{project.id}", 303)


@app.get("/projects/{project_id}")
def project_page(
    project_id: int, request: Request, user=Depends(current_user), db=Depends(db_session)
):
    project = own_project(project_id, user, db)
    return render(request, "project.html", {"project": project})


@app.post("/projects/{project_id}/chat")
@app.post("/projects/{project_id}/run")
async def chat(
    project_id: int, body: ChatRequest, user=Depends(current_user), db=Depends(db_session)
):
    project = own_project(project_id, user, db)
    message = body.message.strip()
    if not message:
        raise HTTPException(422, "Enter a requirement.")
    run = Run(project_id=project.id, request=message)
    db.add(run)
    db.flush()
    updated = db.execute(
        update(Project)
        .where(Project.id == project_id, Project.active_run_id.is_(None))
        .values(active_run_id=run.id, status="queued", current_task=message)
    )
    if updated.rowcount != 1:
        db.rollback()
        raise HTTPException(409, "This project already has a run in progress.")
    db.commit()
    await bus.emit(project_id, "You", "requirement", message, run.id)
    task = asyncio.create_task(execute_run(project_id, run.id))
    active_tasks[run.id] = task
    task.add_done_callback(lambda finished, rid=run.id: active_tasks.pop(rid, None))
    return {"accepted": True, "run_id": run.id}


@app.post("/projects/{project_id}/cancel")
def cancel(project_id: int, user=Depends(current_user), db=Depends(db_session)):
    project = own_project(project_id, user, db)
    if project.active_run_id:
        db.get(Run, project.active_run_id).cancel_requested = True
        db.commit()
    return {"status": "stop_requested"}


def can_resume_verification(run: Run | None) -> bool:
    return resume_details(run) is not None


@app.post("/projects/{project_id}/resume-verification")
@app.post("/projects/{project_id}/resume")
async def resume_verification(project_id: int, user=Depends(current_user), db=Depends(db_session)):
    project = own_project(project_id, user, db)
    previous = db.scalar(select(Run).where(Run.project_id == project_id).order_by(Run.id.desc()))
    if not can_resume_verification(previous):
        raise HTTPException(409, "No saved work is available to resume.")
    if WorkspaceTools(Path(project.workspace_path)).digest() != resume_details(previous)[1]:
        raise HTTPException(
            409, "Source changed since verification. Submit a new request to test the changes."
        )
    run = Run(project_id=project_id, request=previous.request, state={"resume_from": previous.id})
    db.add(run)
    db.flush()
    updated = db.execute(
        update(Project)
        .where(Project.id == project_id, Project.active_run_id.is_(None))
        .values(active_run_id=run.id, status="queued", current_task=run.request)
    )
    if updated.rowcount != 1:
        db.rollback()
        raise HTTPException(409, "This project already has a run in progress.")
    db.commit()
    task = asyncio.create_task(execute_run(project_id, run.id))
    active_tasks[run.id] = task
    task.add_done_callback(lambda finished, rid=run.id: active_tasks.pop(rid, None))
    return {"accepted": True, "run_id": run.id}


def run_dict(run: Run) -> dict:
    state = run.state or {}
    return {
        "id": run.id,
        "request": run.request,
        "status": run.status,
        "agent": run.current_agent,
        "iteration": run.iteration,
        "summary": run.summary,
        "error": run.error,
        "plan": state.get("plan"),
        "changes": state.get("changes", []),
        "model_usage": state.get("model_usage", {}),
        "browser_results": state.get("browser_results"),
        "created_at": run.created_at.isoformat(),
    }


@app.get("/projects/{project_id}/api/state")
async def state(project_id: int, user=Depends(current_user), db=Depends(db_session)):
    project = own_project(project_id, user, db)
    runs = list(
        db.scalars(
            select(Run).where(Run.project_id == project_id).order_by(Run.id.desc()).limit(20)
        )
    )
    tests = list(
        db.scalars(
            select(TestRun)
            .where(TestRun.project_id == project_id)
            .order_by(TestRun.id.desc())
            .limit(15)
        )
    )
    checkpoints = list(
        db.scalars(
            select(Checkpoint)
            .where(Checkpoint.project_id == project_id)
            .order_by(Checkpoint.id.desc())
            .limit(30)
        )
    )
    healthy = await demos.healthy(project_id)
    completed = completed_checkpoint(db, project_id)
    return {
        "id": project.id,
        "name": project.name,
        "status": project.status,
        "current_task": project.current_task,
        "branch": project.branch,
        "active_run_id": project.active_run_id,
        "workspace_path": project.workspace_path,
        "demo_url": project.demo_url if healthy else None,
        "demo_status": "running" if healthy else "stopped",
        "download_url": f"/projects/{project_id}/download" if completed else None,
        "can_resume_verification": not project.active_run_id
        and can_resume_verification(runs[0] if runs else None),
        "runs": [run_dict(r) for r in runs],
        "tests": [
            {
                "id": t.id,
                "run_id": t.run_id,
                "phase": t.phase,
                "status": t.status,
                "total": t.total,
                "passed": t.passed,
                "failed": t.failed,
                "skipped": t.skipped,
                "cases": t.cases,
                "output": t.output,
            }
            for t in tests
        ],
        "checkpoints": [
            {
                "id": c.id,
                "run_id": c.run_id,
                "description": c.description,
                "commit": c.commit_hash,
                "branch": c.branch,
                "test_count": c.test_count,
                "pushed": c.pushed,
                "created_at": c.created_at.isoformat(),
            }
            for c in checkpoints
        ],
        "git": [
            {"commit": c.commit_hash, "push_status": c.push_status, "error": c.error}
            for c in db.scalars(
                select(GitCommit)
                .where(GitCommit.project_id == project_id)
                .order_by(GitCommit.id.desc())
                .limit(30)
            )
        ],
    }


def completed_checkpoint(db, project_id: int):
    return db.scalar(
        select(Checkpoint)
        .join(Run, Checkpoint.run_id == Run.id)
        .where(
            Checkpoint.project_id == project_id,
            Run.status == "completed",
            Checkpoint.status == "validated",
            Checkpoint.failed_tests == 0,
            Checkpoint.test_count > 0,
            Checkpoint.passed_tests == Checkpoint.test_count,
        )
        .order_by(Checkpoint.id.desc())
        .limit(1)
    )


@app.get("/projects/{project_id}/download")
async def download_project(project_id: int, user=Depends(current_user), db=Depends(db_session)):
    project = own_project(project_id, user, db)
    checkpoint = completed_checkpoint(db, project_id)
    if not checkpoint:
        raise HTTPException(409, "Complete a validated project before downloading its ZIP.")
    try:
        archive, temporary = await build_project_zip(
            Path(project.workspace_path), checkpoint.commit_hash, project.slug
        )
    except (RuntimeError, ValueError, OSError) as exc:
        raise HTTPException(503, "Could not export this checkpoint. Please try again.") from exc
    return FileResponse(
        archive,
        media_type="application/zip",
        filename=archive.name,
        headers={"Cache-Control": "private, no-store"},
        background=BackgroundTask(shutil.rmtree, temporary),
    )


@app.get("/projects/{project_id}/events")
def events(project_id: int, after: int = 0, user=Depends(current_user), db=Depends(db_session)):
    own_project(project_id, user, db)
    return [
        event_dict(e)
        for e in db.scalars(
            select(Event)
            .where(Event.project_id == project_id, Event.id > after)
            .order_by(Event.id)
            .limit(200)
        )
    ]


@app.get("/projects/{project_id}/files")
def files(project_id: int, path: str = "", user=Depends(current_user), db=Depends(db_session)):
    project = own_project(project_id, user, db)
    tools = WorkspaceTools(Path(project.workspace_path))
    if not path:
        return {"files": tools.list_files()}
    try:
        return {"path": path, "content": tools.read_file(path)}
    except (ValueError, OSError, UnicodeError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/projects/{project_id}/report/{run_id}")
def report(project_id: int, run_id: int, user=Depends(current_user), db=Depends(db_session)):
    own_project(project_id, user, db)
    run = db.get(Run, run_id)
    if not run or run.project_id != project_id:
        raise HTTPException(404, "Run not found.")
    evidence = run_dict(run)
    evidence["test_runs"] = [
        {
            "phase": test.phase,
            "status": test.status,
            "total": test.total,
            "passed": test.passed,
            "failed": test.failed,
            "skipped": test.skipped,
            "cases": test.cases,
            "output": test.output,
        }
        for test in db.scalars(select(TestRun).where(TestRun.run_id == run_id).order_by(TestRun.id))
    ]
    evidence["checkpoints"] = [
        {
            "id": checkpoint.id,
            "commit": checkpoint.commit_hash,
            "branch": checkpoint.branch,
            "pushed": checkpoint.pushed,
        }
        for checkpoint in db.scalars(select(Checkpoint).where(Checkpoint.run_id == run_id))
    ]
    return JSONResponse(
        evidence,
        headers={"Content-Disposition": f'attachment; filename="forgeflow-run-{run_id}.json"'},
    )


@app.get("/projects/{project_id}/tests")
@app.get("/projects/{project_id}/checkpoints")
@app.get("/projects/{project_id}/logs")
def section_page(
    project_id: int, request: Request, user=Depends(current_user), db=Depends(db_session)
):
    project = own_project(project_id, user, db)
    return render(request, "project.html", {"project": project})


@app.post("/projects/{project_id}/demo/stop")
async def stop_demo(project_id: int, user=Depends(current_user), db=Depends(db_session)):
    project = own_project(project_id, user, db)
    if project.active_run_id:
        raise HTTPException(409, "Wait for the active run before stopping the preview.")
    await demos.stop(project_id)
    project.demo_status, project.demo_url = "stopped", None
    db.commit()
    return {"status": "stopped"}


@app.post("/projects/{project_id}/demo/start")
async def start_demo(project_id: int, user=Depends(current_user), db=Depends(db_session)):
    project = own_project(project_id, user, db)
    if project.active_run_id:
        raise HTTPException(409, "A run is in progress.")
    checkpoint = db.scalar(
        select(Checkpoint).where(Checkpoint.project_id == project_id).order_by(Checkpoint.id.desc())
    )
    if not checkpoint:
        raise HTTPException(409, "Complete a validated run before launching a preview.")
    # A manual edit after validation must be tested in a new run.
    run = db.get(Run, checkpoint.run_id)
    if WorkspaceTools(Path(project.workspace_path)).digest() != run.state.get("validated_digest"):
        raise HTTPException(
            409, "Files changed since validation. Submit a new request to test them."
        )
    try:
        project.demo_url = await demos.start(project_id, Path(project.workspace_path))
    except Exception as exc:
        raise HTTPException(503, str(exc)[:1000]) from exc
    project.demo_status = "running"
    db.commit()
    return {"url": project.demo_url}


@app.get("/projects/{project_id}/demo/logs")
async def demo_logs(project_id: int, user=Depends(current_user), db=Depends(db_session)):
    own_project(project_id, user, db)
    return {"output": await demos.logs(project_id)}


@app.websocket("/ws/projects/{project_id}")
async def websocket(project_id: int, ws: WebSocket):
    with SessionLocal() as db:
        user = db.get(User, ws.session.get("user_id", -1))
        project = db.get(Project, project_id)
        origin = ws.headers.get("origin")
        if (
            not user
            or not project
            or project.owner_id != user.id
            or (origin and urlparse(origin).netloc != ws.headers.get("host"))
        ):
            await ws.close(code=1008)
            return
    await ws.accept()
    bus.clients[project_id].add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        bus.clients[project_id].discard(ws)
