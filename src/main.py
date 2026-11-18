
import os
import hmac
import sqlite3
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.retrieval import search_policies
from src.auth.users import register_user, authenticate_user
from src.auth.sessions import create_session, revoke_session
from src.auth.permissions import require_role
from src.auth.ownership import get_owned_record
from src.auth.web import (
    SESSION_COOKIE_NAME,
    CSRF_COOKIE_NAME,
    get_current_user,
    create_csrf_token,
    validate_csrf_token,
    set_csrf_cookie,
    set_session_cookie,
    clear_session_cookie,
    clear_csrf_cookie,
)


# Find the main project folder.
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


# Configure Jinja2 templates.
templates = Jinja2Templates(
    directory=str(BASE_DIR / "src" / "templates")
)

# Create the FastAPI application.
app = FastAPI()

# Serve CSS and other static files.
app.mount(
    "/static",
    StaticFiles(directory=str(BASE_DIR / "static")),
    name="static",
)


# Add Content-Security-Policy security header.
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://unpkg.com; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'"
    )

    return response


# Display the registration page.
@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):

    csrf_token = create_csrf_token()

    response = templates.TemplateResponse(
        request=request,
        name="register.html",
        context={
            "request": request,
            "csrf_token": csrf_token,
            "error": None,
        },
    )

    set_csrf_cookie(response, csrf_token)

    return response


# Receive and validate a new user registration.
@app.post("/register", response_class=HTMLResponse)
async def register(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
):

    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)

    if not validate_csrf_token(csrf_token, cookie_token):
        return HTMLResponse(
            "Invalid or expired security token. Refresh the page.",
            status_code=403,
        )

    try:
        register_user(email, password)

    except ValueError as error:
        message = str(error)

    except sqlite3.IntegrityError:
        message = "An account with this email already exists."

    else:
        return RedirectResponse(
            url="/login",
            status_code=303,
        )

    # Generate a fresh CSRF token when showing the error.
    new_csrf_token = create_csrf_token()

    response = templates.TemplateResponse(
        request=request,
        name="register.html",
        context={
            "request": request,
            "csrf_token": new_csrf_token,
            "error": message,
        },
        status_code=400,
    )

    set_csrf_cookie(response, new_csrf_token)

    return response


# Display the login page.
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):

    csrf_token = create_csrf_token()

    response = templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "request": request,
            "csrf_token": csrf_token,
            "error": None,
        },
    )

    set_csrf_cookie(response, csrf_token)

    return response


# Authenticate a user and create a server-side session.
@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
):

    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)

    if not validate_csrf_token(csrf_token, cookie_token):
        return HTMLResponse(
            "Invalid or expired security token. Refresh the page.",
            status_code=403,
        )

    user = authenticate_user(email, password)

    if user is None:
        new_csrf_token = create_csrf_token()

        response = templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "request": request,
                "csrf_token": new_csrf_token,
                "error": "Invalid email or password. Please try again.",
            },
            status_code=401,
        )

        set_csrf_cookie(response, new_csrf_token)

        return response

    # Create a new server-side session.
    session_token, expires_at = create_session(user["id"])

    response = RedirectResponse(
        url="/",
        status_code=303,
    )

    # Set the login cookie and rotate the CSRF token.
    set_session_cookie(response, session_token, expires_at)

    new_csrf_token = create_csrf_token()
    set_csrf_cookie(response, new_csrf_token)

    return response


# Display the Knowledge Assistant homepage.
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):

    user = get_current_user(request)

    # Require login before showing the Knowledge Assistant.
    if user is None:
        return RedirectResponse(
            url="/login",
            status_code=303,
        )

    csrf_token = create_csrf_token()

    response = templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "user": user,
            "csrf_token": csrf_token,
        },
    )

    set_csrf_cookie(response, csrf_token)

    return response


# Receive a question and validate authentication and CSRF protection.
@app.post("/ask", response_class=HTMLResponse)
async def ask(
    request: Request,
    question: str = Form(...),
    csrf_token: str = Form(...),
):

    user = get_current_user(request)

    if user is None:
        return HTMLResponse(
            "Please log in before asking a question.",
            status_code=401,
        )

    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)

    if not validate_csrf_token(csrf_token, cookie_token):
        return templates.TemplateResponse(
            request=request,
            name="partials/error.html",
            context={
                "request": request,
                "message": "Your security token is invalid or expired.",
                "action": "Refresh the page and submit your question again.",
            },
            status_code=403,
        )

    # Reject questions that contain only spaces.
    if not question.strip():
        return templates.TemplateResponse(
            request=request,
            name="partials/error.html",
            context={
                "request": request,
                "message": "Your question is empty.",
                "action": "Enter a question before clicking Ask.",
            },
            status_code=422,
        )

    # Search the policy documents for the user's question.
    matches = search_policies(question)

    # Prepare the answer and its source citation.
    if matches:
        answer = matches[0]["content"]

        sources = [
            {"source": matches[0]["source"]}
        ]
    else:
        answer = (
            "I couldn't find information about this question "
            "in the available policy documents. "
            "Try asking about leave, attendance, travel, "
            "or other company policies."
        )

        sources = []

    return templates.TemplateResponse(
        request=request,
        name="partials/answer.html",
        context={
            "request": request,
            "question": question,
            "answer": answer,
            "sources": sources,
        },
    )


# Log out and invalidate the server-side session.
@app.post("/logout")
async def logout(
    request: Request,
    csrf_token: str = Form(...),
):

    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)

    if not validate_csrf_token(csrf_token, cookie_token):
        return HTMLResponse(
            "Invalid or expired security token. Refresh the page.",
            status_code=403,
        )

    session_token = request.cookies.get(SESSION_COOKIE_NAME)

    if session_token:
        revoke_session(session_token)

    response = RedirectResponse(
        url="/login",
        status_code=303,
    )

    clear_session_cookie(response)
    clear_csrf_cookie(response)

    return response

# Allow access only to administrators.
@app.get("/admin")
async def admin_dashboard(request: Request):

    # Check whether the user is logged in.
    user = get_current_user(request)

    if user is None:
        return HTMLResponse(
            "Please log in first.",
            status_code=401,
        )

    # Check whether the logged-in user has the admin role.
    if not require_role(user, "admin"):
        return HTMLResponse(
            "Access denied. Administrator permission required.",
            status_code=403,
        )

    return HTMLResponse(
        "<h1>Admin Dashboard</h1>"
        "<p>Welcome, administrator.</p>"
    )

# Return a record only when the logged-in user owns it.
@app.get("/records/{record_id}")
async def read_record(record_id: int, request: Request):

    # Check whether the user is logged in.
    user = get_current_user(request)

    if user is None:
        return HTMLResponse(
            "Please log in first.",
            status_code=401,
        )

    # Retrieve the record only if the user owns it.
    record = get_owned_record(record_id, user)

    if record is None:
        return HTMLResponse(
            "Record not found.",
            status_code=404,
        )

    return {
        "id": record["id"],
        "title": record["title"],
        "content": record["content"],
    }
