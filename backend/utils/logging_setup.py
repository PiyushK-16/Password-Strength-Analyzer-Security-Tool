"""
Logging configuration with a safety net.

Rule #1 of this project: passwords are never logged. The code never passes the
password to a logger. As defence in depth, this filter drops any log record that
looks like it contains a password field.
"""
import logging


class NoSecretsFilter(logging.Filter):
    BLOCKED_MARKERS = ("password=", '"password"', "'password'")

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage().lower()
        except Exception:  # pragma: no cover
            return False
        return not any(marker in message for marker in self.BLOCKED_MARKERS)


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    for handler in logging.getLogger().handlers:
        handler.addFilter(NoSecretsFilter())
