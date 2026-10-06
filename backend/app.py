"""
Flask application factory.

Run from the project root:
    python -m backend.app
"""
import logging

from flask import Flask, jsonify, send_from_directory

from backend.config import FRONTEND_DIR, Config
from backend.models import database
from backend.routes.api import api
from backend.utils.logging_setup import configure_logging
from backend.utils.rate_limiter import SlidingWindowLimiter

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)

    configure_logging()
    database.init_db(app.config["DATABASE_PATH"])
    app.extensions["limiter"] = SlidingWindowLimiter(app.config["RATE_LIMIT_PER_MINUTE"])
    app.register_blueprint(api)

    @app.get("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        if response.mimetype in ("application/json", "text/html"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # Generic error pages: never include request data (it may contain a password).
    for code, message in {400: "Bad request.", 404: "Not found.", 405: "Method not allowed.",
                          413: "Request too large.", 429: "Too many requests."}.items():
        app.register_error_handler(code, lambda e, m=message, c=code: (jsonify({"error": m}), c))

    @app.errorhandler(Exception)
    def unexpected(error):
        logging.getLogger(__name__).error("Unhandled %s", type(error).__name__)  # type only, no details
        return jsonify({"error": "Internal server error."}), 500

    return app


if __name__ == "__main__":
    application = create_app()
    # debug=False on purpose: the debugger can display request data in tracebacks.
    application.run(host=Config.HOST, port=Config.PORT, debug=False)
