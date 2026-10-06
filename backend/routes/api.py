"""
REST API.

Privacy rules enforced here:
  * the password arrives in the JSON BODY (never the URL / query string);
  * it is processed in memory and never logged, stored or echoed back;
  * error messages are generic and never include request data.
"""
from flask import Blueprint, current_app, jsonify, request

from backend.config import default_policy
from backend.models import database
from backend.services.password_analyzer import analyze_password
from backend.services.password_generator import MAX_LENGTH, MIN_LENGTH, generate_password
from backend.services.policy_checker import evaluate_policy

api = Blueprint("api", __name__, url_prefix="/api")
CONTEXT_FIELDS = ("first_name", "birth_year", "organization")


def _error(message: str, status: int):
    return jsonify({"error": message}), status


def _clean_context(raw):
    """Keep only the three expected string fields, each capped in length."""
    if not isinstance(raw, dict):
        return {}
    return {k: str(raw.get(k, ""))[:64] for k in CONTEXT_FIELDS if raw.get(k)}


@api.before_request
def rate_limit():
    limiter = current_app.extensions["limiter"]
    if request.method == "POST" and not limiter.allow(request.remote_addr or "unknown"):
        response = jsonify({"error": "Too many requests. Please slow down."})
        response.status_code = 429
        response.headers["Retry-After"] = "60"
        return response


@api.post("/analyze")
def analyze():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _error("Request body must be a JSON object.", 400)
    password = body.get("password")
    if not isinstance(password, str):
        return _error("Field 'password' is required and must be a string.", 400)
    max_len = current_app.config["MAX_PASSWORD_LENGTH"]
    if len(password) > max_len:
        return _error(f"Password exceeds the maximum supported length of {max_len} characters.", 400)

    result = analyze_password(password, _clean_context(body.get("context")))
    result["policy"] = evaluate_policy(password, result, {"maximum_length": max_len}) if password else None

    # Optional: store safe aggregate metadata only (password is NOT passed to the database layer).
    result["recorded"] = False
    if body.get("record") is True and password and current_app.config["ANALYTICS_ENABLED"]:
        database.save_analysis(current_app.config["DATABASE_PATH"], result)
        result["recorded"] = True
    return jsonify(result), 200


@api.get("/dashboard/stats")
def dashboard_stats():
    return jsonify(database.get_stats(current_app.config["DATABASE_PATH"]))


@api.get("/analytics/weaknesses")
def weaknesses():
    return jsonify({"weaknesses": database.get_weakness_stats(current_app.config["DATABASE_PATH"])})


@api.post("/generate-password")
def generate():
    body = request.get_json(silent=True) or {}
    try:
        password = generate_password(
            length=body.get("length", 20), upper=bool(body.get("upper", True)), lower=bool(body.get("lower", True)),
            digits=bool(body.get("digits", True)), symbols=bool(body.get("symbols", True)))
    except ValueError as exc:  # messages here are fixed strings, never user data
        return _error(str(exc), 400)
    return jsonify({"password": password, "note": "Generated locally. Not stored or logged. Copy it into a password manager."})


@api.get("/policy")
def policy():
    return jsonify({**default_policy(), "min_generator_length": MIN_LENGTH, "max_generator_length": MAX_LENGTH})


@api.get("/health")
def health():
    return jsonify({"status": "ok"})
