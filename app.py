import time
import secrets
from datetime import datetime, timedelta
from collections import defaultdict

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    make_response,
    flash,
    g,
)
from markupsafe import Markup, escape
import bleach


app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=4)

SECURITY_LEVELS = ("low", "medium", "high")
VALID_USER = {"username": "student", "password": "letmein123"}
stored_comments = []
ip_login_attempts = defaultdict(list)
csrf_demo_state = {"password": "opensesame"}


def current_level() -> str:
    return session.get("security_level", "low")


def record_attempt(container: list[float]):
    now = time.time()
    container.append(now)
    
    cutoff = now - 60
    while container and container[0] < cutoff:
        container.pop(0)


def is_rate_limited(level: str, identifier: str) -> bool:
    if level == "low":
        return False

    session_attempts = session.setdefault("login_attempts", [])
    record_attempt(session_attempts)
    attempt_window = [ts for ts in session_attempts if ts >= time.time() - 60]
    session["login_attempts"] = attempt_window
    if len(attempt_window) >= 5:
        return True

    if level == "high":
        record_attempt(ip_login_attempts[identifier])
        filtered = [
            ts for ts in ip_login_attempts[identifier] if ts >= time.time() - 60
        ]
        ip_login_attempts[identifier] = filtered
        return len(filtered) >= 8

    return False


def ensure_captcha():
    if "captcha" not in session or current_level() == "low":
        a = secrets.randbelow(8) + 2
        b = secrets.randbelow(8) + 1
        session["captcha"] = {"question": f"{a} + {b}", "answer": str(a + b)}


def generate_csrf_token() -> str:
    token = secrets.token_urlsafe(16)
    session["csrf_token"] = token
    session["csrf_created_at"] = time.time()
    return token


def validate_csrf_token(submitted: str) -> bool:
    token = session.get("csrf_token")
    created = session.get("csrf_created_at", 0)
    if not token or not submitted:
        return False
    if time.time() - created > 600:
        return False
    return secrets.compare_digest(token, submitted)


@app.before_request
def set_defaults():
    if "security_level" not in session:
        session["security_level"] = "low"
    ensure_captcha()
    level = current_level()
    if level == "high":
        app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    elif level == "medium":
        app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    else:
        app.config["SESSION_COOKIE_SAMESITE"] = None


@app.after_request
def attach_security_headers(response):
    level = current_level()
    if request.path.startswith("/xss-reflected") and level != "low":
        nonce = getattr(g, "csp_nonce", secrets.token_hex(8))
        response.headers[
            "Content-Security-Policy"
        ] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "0"
    if request.path.startswith("/xss-stored") and level != "low":
        response.headers[
            "Content-Security-Policy"
        ] = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'"
    if request.path.startswith("/csrf-demo") and level != "low":
        response.headers["Referrer-Policy"] = "same-origin"
    return response


@app.route("/", methods=["GET"])
def index():
    return render_template(
        "home.html",
        level=current_level(),
        labs=get_labs(),
    )


def get_labs():
    return [
        {
            "title": "Lab 03 — Brute Force & Rate Limiting",
            "endpoint": "lab_login",
            "id": "CSET365_Lab3",
        },
        {
            "title": "Lab 04 — Reflected XSS",
            "endpoint": "xss_reflected",
            "id": "CSET365_Lab4",
        },
        {
            "title": "Lab 05 — Stored XSS",
            "endpoint": "xss_stored",
            "id": "CSET365_Lab5",
        },
        {
            "title": "Lab 07 — CSRF",
            "endpoint": "csrf_demo",
            "id": "CSET365_Lab7",
        },
    ]


@app.context_processor
def inject_nav():
    return {
        "nav_labs": get_labs(),
    }


@app.post("/set-level")
def set_level():
    level = request.form.get("level", "low").lower()
    if level not in SECURITY_LEVELS:
        flash("Unknown level requested", "error")
        return redirect(url_for("index"))
    session["security_level"] = level
    session.pop("login_attempts", None)
    ensure_captcha()
    flash(f"Security level set to {level.title()}", "success")
    return redirect(request.referrer or url_for("index"))


@app.route("/lab-03", methods=["GET", "POST"])
def lab_login():
    level = current_level()
    message = None
    success = False
    status_code = 200
    captcha_error = None
    throttled = False

    if request.method == "POST":
        if level != "low":
            expected = session.get("captcha", {}).get("answer", "")
            provided = request.form.get("captcha_answer", "")
            if expected != provided:
                captcha_error = "Captcha incorrect"
        if captcha_error:
            message = "Login failed."
        else:
            identifier = request.remote_addr or "unknown"
            throttled = is_rate_limited(level, identifier)
            if throttled:
                message = "Too many attempts. Try again later."
                status_code = 429
            else:
                username = request.form.get("username", "")
                password = request.form.get("password", "")
                if (
                    username == VALID_USER["username"]
                    and password == VALID_USER["password"]
                ):
                    success = True
                    message = "Welcome back!"
                else:
                    message = (
                        "Username or password invalid."
                        if level == "low"
                        else "Login failed."
                    )
        ensure_captcha()

    response = make_response(
        render_template(
            "lab_login.html",
            level=level,
            message=message,
            success=success,
            captcha=session.get("captcha"),
            throttled=throttled,
            attempts=session.get("login_attempts", []),
        ),
        status_code,
    )
    if level == "low" and success:
        response.headers["Content-Length"] = "1234"
    return response


@app.route("/xss-reflected")
def xss_reflected():
    level = current_level()
    payload = request.args.get("message", "")
    raw_payload = payload if payload else ""
    rendered_payload = ""
    nonce = None

    if level == "low":
        rendered_payload = Markup(raw_payload)
    else:
        nonce = secrets.token_hex(8)
        g.csp_nonce = nonce
        rendered_payload = escape(raw_payload)

    return render_template(
        "xss_reflected.html",
        level=level,
        payload=rendered_payload,
        raw=raw_payload,
        csp_nonce=nonce,
    )


@app.route("/xss-stored", methods=["GET", "POST"])
def xss_stored():
    level = current_level()
    if request.method == "POST":
        content = request.form.get("comment", "")
        author = request.form.get("author", "anonymous")
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        entry = {"author": author, "timestamp": timestamp}
        if level == "low":
            entry["content"] = content
        else:
            cleaned = bleach.clean(content, strip=True)
            entry["content"] = cleaned
        stored_comments.append(entry)
        flash("Comment saved!", "success")
        return redirect(url_for("xss_stored"))

    comments = []
    for c in stored_comments:
        display = c.copy()
        if level == "low":
            display["content"] = Markup(display["content"])
        else:
            display["content"] = escape(display["content"])
        comments.append(display)
    return render_template("xss_stored.html", level=level, comments=comments)


def origin_allowed(req) -> bool:
    origin = req.headers.get("Origin")
    referer = req.headers.get("Referer")
    base = req.host_url.rstrip("/")
    for header in (origin, referer):
        if header and not header.startswith(base):
            return False
    return True


@app.route("/csrf-demo", methods=["GET", "POST"])
def csrf_demo():
    level = current_level()
    error = None
    success = None
    csrf_token = session.get("csrf_token")

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        submitted_token = request.form.get("csrf_token")
        if level == "low":
            csrf_demo_state["password"] = new_password
            success = "Password updated (vulnerable flow)."
        else:
            if not origin_allowed(request):
                error = "Origin/Referer validation failed."
            elif not submitted_token or not validate_csrf_token(submitted_token):
                error = "CSRF token invalid or missing."
            else:
                csrf_demo_state["password"] = new_password
                success = "Password updated with CSRF defenses."
        if not error and not success:
            error = "Password change denied."

    if level != "low" and (csrf_token is None or request.method == "POST"):
        csrf_token = generate_csrf_token()

    return render_template(
        "csrf_demo.html",
        level=level,
        current_password=csrf_demo_state["password"],
        csrf_token=csrf_token,
        error=error,
        success=success,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

