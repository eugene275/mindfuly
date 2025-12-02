import os
import re
import pathlib
import pytest

# --- Configuration: adjust if you want different sensitivity or to whitelist files ---
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
EXCLUDE_DIRS = {'.git', '__pycache__', 'venv', '.venv', 'node_modules', '.github'}
SENSITIVE_PATH_KEYWORDS = ('/admin', '/users', '/settings', '/journal', '/analytics', '/admin/', '/users/')
# Minimum secret length considered suspicious for literal string checks
MIN_SUSPICIOUS_SECRET_LEN = 6

# --- Helpers -------------------------------------------------------------------
def is_text_file(path: pathlib.Path) -> bool:
    try:
        # quick heuristic: attempt to decode
        with open(path, 'r', encoding='utf-8') as f:
            f.read(1024)
        return True
    except Exception:
        return False

def iter_repo_files():
    for root, dirs, files in os.walk(REPO_ROOT):
        # filter dirs in-place to skip excluded dirs
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for fn in files:
            full = pathlib.Path(root) / fn
            # skip files inside .git etc
            if any(part in EXCLUDE_DIRS for part in full.parts):
                continue
            yield full

def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return ''

# --- 1) Hard-coded secrets and .env scanning ----------------------------------
@pytest.mark.security
def test_no_hardcoded_secrets_or_env_files():
    """
    Flags:
      - Files named exactly .env or .env.* (committed env files).
      - Simple assignments like SECRET_KEY = "...." or API_KEY = '...' in code.
      - Common suspicious env var names assigned literal values in code.
    """
    secret_patterns = [
        re.compile(r'\b(?:SECRET|SECRET_KEY|API_KEY|API-KEY|APIKEY|TOKEN|ACCESS_TOKEN|AUTH_TOKEN|PASSWORD|PASS|DB_PASS|DB_PASSWORD|PRIVATE_TOKEN)\b', re.IGNORECASE),
    ]
    literal_assignment_re = re.compile(
        r'\b(?P<name>[A-Z0-9_]*(?:SECRET|API|TOKEN|PASSWORD|PASS|KEY|DB)[A-Z0-9_]*)\b\s*[:=]\s*[\'"](?P<val>[^\'"]{'+str(MIN_SUSPICIOUS_SECRET_LEN)+',})[\'"]',
        re.IGNORECASE
    )
    committed_env_files = []
    literal_secrets = []

    for f in iter_repo_files():
        # detect committed .env files
        if f.name.startswith('.env'):
            # skip obvious sample files but flag them if contain non-empty keys
            text = read_text(f)
            if text.strip():
                committed_env_files.append((str(f.relative_to(REPO_ROOT)), text.splitlines()[:8]))
            continue

        if not is_text_file(f):
            continue
        text = read_text(f)

        # quick pre-filter
        if any(p.search(text) for p in secret_patterns):
            # look for assignments with literal strings
            for m in literal_assignment_re.finditer(text):
                name = m.group('name')
                val = m.group('val')
                # don't flag obvious test placeholders like "changeme"
                if re.search(r'change|example|your-|xxx|test', val, re.IGNORECASE):
                    continue
                literal_secrets.append((str(f.relative_to(REPO_ROOT)), name, val[:80]))

    msgs = []
    if committed_env_files:
        msgs.append("Committed .env file(s) detected: " + ", ".join(p for p, _ in committed_env_files))
    if literal_secrets:
        msgs.append("Hard-coded secrets / sensitive literal assignments found:\n" + "\n".join(
            f" - {path}: {name} = \"{snippet}...\"" for path, name, snippet in literal_secrets
        ))
    if msgs:
        pytest.fail("\n".join(msgs))


# --- 2) DB credentials embedded in source ------------------------------------
@pytest.mark.security
def test_no_embedded_database_credentials():
    """
    Look for database-like connection strings in code (postgres, mysql, mongodb, redis)
    and also for DATABASE_URL style assignments with embedded credentials.
    """
    db_uri_re = re.compile(
        r'\b(?:postgresql?|mysql|mongodb|redis|mssql)://[^\'"\s]+', re.IGNORECASE
    )
    creds_found = []

    for f in iter_repo_files():
        if not is_text_file(f):
            continue
        text = read_text(f)
        for m in db_uri_re.finditer(text):
            candidate = m.group(0)
            # detect presence of username:password@ (common embedded credential form)
            if re.search(r'//[^:/@]+:[^@/]+@', candidate):
                creds_found.append((str(f.relative_to(REPO_ROOT)), candidate[:200]))
        # also check for DATABASE_URL = "postgres://user:pass@..."
        m2 = re.search(r'\bDATABASE_URL\b\s*[:=]\s*[\'"]([^\'"]+)[\'"]', text, re.IGNORECASE)
        if m2:
            candidate = m2.group(1)
            if re.search(r'//[^:/@]+:[^@/]+@', candidate):
                creds_found.append((str(f.relative_to(REPO_ROOT)), candidate[:200]))

    if creds_found:
        pytest.fail("Embedded database credentials/URIs found:\n" + "\n".join(
            f" - {p}: {snippet}" for p, snippet in creds_found
        ))


# --- 3) Private keys pushed to repo ------------------------------------------
@pytest.mark.security
def test_no_private_keys_in_repo():
    """
    Detect PEM/SSH private keys or private-key file names (id_rsa, *private*.pem)
    """
    pem_headers = [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
    ]
    suspicious_files = []
    for f in iter_repo_files():
        if not is_text_file(f):
            continue
        name = f.name.lower()
        if name in ('id_rsa', 'id_dsa') or name.endswith('.pem') or name.endswith('.key'):
            # check contents for private key header
            text = read_text(f)
            if any(h in text for h in pem_headers):
                suspicious_files.append((str(f.relative_to(REPO_ROOT)), 'contains PEM private key header'))
            # also flag if filename itself is obviously private
            elif re.search(r'private', name):
                suspicious_files.append((str(f.relative_to(REPO_ROOT)), 'filename contains "private" or looks like a key file'))

        else:
            text = read_text(f)
            if any(h in text for h in pem_headers):
                suspicious_files.append((str(f.relative_to(REPO_ROOT)), 'embedded PEM private key header found'))

    if suspicious_files:
        pytest.fail("Private key material appears to be committed:\n" + "\n".join(
            f" - {p}: {reason}" for p, reason in suspicious_files
        ))


# --- 4) Sensitive endpoints must require auth ---------------------------------
@pytest.mark.security
def test_sensitive_endpoints_require_auth():
    """
    Heuristic static check:
    - Find ui.page("/some/path") or app.get/post decorators and check
      the following function body (a short region) for presence of authentication checks:
      look for 'require_auth(' or 'verify_token' or 'Depends(get_current_user' or similar.
    - If a path appears sensitive (contains /admin, /users, /settings, /journal...), but
      no auth check is found in the body snippet, fail and list the endpoint.
    """
    decorator_re = re.compile(r'@(?:ui|app)\.(?:page|get|post|put|delete)\s*\(\s*["\'](?P<path>[^"\']+)["\']\s*\)')
    # auth indicators: add more tokens if your project uses a different pattern
    auth_indicators = re.compile(r'\b(require_auth|verify_token|verify_auth|Depends\(\s*get_current_user|Depends\(\s*get_current_active_user|login_required|@login_required)\b', re.IGNORECASE)

    missing_auth = []

    for f in iter_repo_files():
        if not is_text_file(f):
            continue
        text = read_text(f)
        for dm in decorator_re.finditer(text):
            path = dm.group('path')
            # only focus on potentially sensitive paths
            if not any(k in path for k in SENSITIVE_PATH_KEYWORDS):
                continue
            # capture a region after decorator to look into the function
            start_idx = dm.end()
            region = text[start_idx:start_idx + 4000]  # inspect next chars (function body)
            # look for auth indicators
            if not auth_indicators.search(region):
                # Provide context: function name if possible
                fn_match = re.search(r'def\s+([a-zA-Z0-9_]+)\s*\(', region)
                fn_name = fn_match.group(1) if fn_match else "<unknown>"
                missing_auth.append((str(f.relative_to(REPO_ROOT)), path, fn_name))

    if missing_auth:
        msgs = ["Sensitive endpoints without obvious auth checks found:"]
        for p, path, fn in missing_auth:
            msgs.append(f" - {p} -> {path} (function: {fn}) - no 'require_auth/verify_token/Depends(get_current_user)' detected in the nearby function body.")
        msgs.append("\nThis is a heuristic check — review listed functions and add authentication/authorization checks where appropriate.")
        pytest.fail("\n".join(msgs))
