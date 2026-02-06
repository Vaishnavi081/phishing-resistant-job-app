from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach

csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)

def setup_security(app):
    csrf.init_app(app)
    limiter.init_app(app)
    return app

def sanitize_input(text):
    if not text:
        return ""
    return bleach.clean(text, strip=True)

# Rate limits
job_limit = limiter.limit("5 per hour")
report_limit = limiter.limit("10 per day")