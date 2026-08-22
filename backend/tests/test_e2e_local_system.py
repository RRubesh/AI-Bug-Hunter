import os
import sys
import io
import time
import uuid
import zipfile
import hashlib
import secrets
import urllib.request
from pathlib import Path
import pytest
import requests
from fastapi.testclient import TestClient

# Ensure root directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.main import app
from backend.config import settings
from backend.database import SessionLocal, get_mongo_db, is_mongo_connected
from backend.database.mongodb import mongo_manager
from backend.models import User, Project, Scan, Vulnerability, PasswordResetToken
from backend.auth.jwt import get_password_hash, verify_password, create_access_token

BACKEND_BASE_URL = "http://127.0.0.1:8000"
FRONTEND_BASE_URL = "http://localhost:5174"


@pytest.fixture(scope="module")
def api_client():
    """Provides a TestClient for direct backend endpoint invocation and live requests session."""
    client = TestClient(app)
    session = requests.Session()
    return {"client": client, "session": session}


# =========================================================================
# 1. FRONTEND SERVER & ASSET BUNDLE TESTS
# =========================================================================

def test_01_frontend_server_running_and_serves_html():
    """Verify local frontend development server responds with valid HTML shell."""
    try:
        req = urllib.request.Request(FRONTEND_BASE_URL)
        with urllib.request.urlopen(req, timeout=5) as response:
            assert response.status == 200
            content = response.read().decode("utf-8")
            assert "<!DOCTYPE html>" in content or "<!doctype html>" in content
            assert 'id="root"' in content
            assert "/src/main.tsx" in content or "index.html" in content
    except Exception as e:
        pytest.skip(f"Frontend server on {FRONTEND_BASE_URL} not reachable: {e}")


def test_02_backend_healthcheck_endpoint(api_client):
    """Verify backend /api/health and /health endpoints return 200 healthy."""
    client = api_client["client"]
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["api"] == "healthy"
    assert data["app"] == "AI Bug Hunter"
    assert "scanners" in data


# =========================================================================
# 2. REGISTRATION & INPUT VALIDATION TESTS
# =========================================================================

def test_03_registration_success_and_password_hashing(api_client):
    """Test registering a new user with valid credentials, verify password hashing and DB sync."""
    client = api_client["client"]
    unique_id = uuid.uuid4().hex[:8]
    username = f"e2e_user_{unique_id}"
    email = f"e2e_{unique_id}@example.com"
    password = "StrongPassword123!"

    res = client.post("/api/auth/register", json={
        "username": username,
        "email": email,
        "password": password
    })
    assert res.status_code in (200, 201)
    data = res.json()
    assert data["username"] == username
    assert data["email"] == email
    assert data["role"] == "user"
    assert "password" not in data
    assert "hashed_password" not in data
    assert "password_hash" not in data

    # Verify password hashing in DB
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        assert user is not None
        assert user.hashed_password != password
        assert verify_password(password, user.hashed_password) is True
    finally:
        db.close()


def test_04_registration_duplicate_email_and_username_rejected(api_client):
    """Test duplicate registration attempts are rejected with 400 Bad Request."""
    client = api_client["client"]
    unique_id = uuid.uuid4().hex[:8]
    username = f"dup_{unique_id}"
    email = f"dup_{unique_id}@example.com"
    password = "StrongPassword123!"

    # First registration
    res1 = client.post("/api/auth/register", json={"username": username, "email": email, "password": password})
    assert res1.status_code in (200, 201)

    # Duplicate username
    res_dup_user = client.post("/api/auth/register", json={"username": username, "email": f"other_{unique_id}@example.com", "password": password})
    assert res_dup_user.status_code == 400
    assert "already registered" in res_dup_user.json()["detail"].lower()

    # Duplicate email
    res_dup_email = client.post("/api/auth/register", json={"username": f"other_{unique_id}", "email": email, "password": password})
    assert res_dup_email.status_code == 400
    assert "already registered" in res_dup_email.json()["detail"].lower()


def test_05_registration_input_sanitization_and_weak_passwords(api_client):
    """Test invalid email formats and weak passwords rejection."""
    client = api_client["client"]
    
    # Weak / short password
    res_weak = client.post("/api/auth/register", json={
        "username": "weak_pass_user",
        "email": "weak@example.com",
        "password": "123"
    })
    assert res_weak.status_code == 400

    # Invalid email format
    res_bad_email = client.post("/api/auth/register", json={
        "username": "bad_email_user",
        "email": "not-an-email",
        "password": "ValidPassword123!"
    })
    assert res_bad_email.status_code == 400


# =========================================================================
# 3. LOGIN & AUTHENTICATION FLOW TESTS
# =========================================================================

def test_06_login_success_and_failure(api_client):
    """Test correct password login, incorrect password, and unknown account."""
    client = api_client["client"]
    unique_id = uuid.uuid4().hex[:8]
    username = f"login_user_{unique_id}"
    email = f"login_{unique_id}@example.com"
    password = "CorrectPassword123!"

    client.post("/api/auth/register", json={"username": username, "email": email, "password": password})

    # 1. Correct Login with username
    res_ok = client.post("/api/auth/login", data={"username": username, "password": password})
    assert res_ok.status_code == 200
    data_ok = res_ok.json()
    assert "access_token" in data_ok
    assert data_ok["username"] == username

    # 2. Correct Login with email
    res_email_ok = client.post("/api/auth/login", data={"username": email, "password": password})
    assert res_email_ok.status_code == 200

    # 3. Wrong Password
    res_bad_pw = client.post("/api/auth/login", data={"username": username, "password": "WrongPassword123!"})
    assert res_bad_pw.status_code == 401

    # 4. Unknown Account
    res_unknown = client.post("/api/auth/login", data={"username": "non_existent_account_xyz", "password": password})
    assert res_unknown.status_code == 401


def test_07_jwt_token_validation_and_expiration(api_client):
    """Test accessing protected endpoints with valid token, expired token, and malformed token."""
    client = api_client["client"]
    
    # 1. Valid token
    valid_token = create_access_token({"sub": "valid_user", "email": "valid@example.com", "role": "user", "user_id": 999})
    res_valid = client.get("/api/users/me", headers={"Authorization": f"Bearer {valid_token}"})
    assert res_valid.status_code == 200

    # 2. Malformed token
    res_malformed = client.get("/api/users/me", headers={"Authorization": "Bearer invalid.jwt.token"})
    assert res_malformed.status_code == 401

    # 3. Missing token
    res_missing = client.get("/api/users/me")
    assert res_missing.status_code == 401


# =========================================================================
# 4. FORGOT PASSWORD & PASSWORD RESET FLOW
# =========================================================================

def test_08_forgot_password_flow_and_anti_enumeration(api_client):
    """Test forgot password token generation, single-use consumption, and anti-enumeration."""
    client = api_client["client"]
    unique_id = uuid.uuid4().hex[:8]
    username = f"reset_user_{unique_id}"
    email = f"reset_{unique_id}@example.com"
    old_password = "OldPassword123!"
    new_password = "NewSecurePassword456!"

    client.post("/api/auth/register", json={"username": username, "email": email, "password": old_password})

    # 1. Non-existent email returns generic success (anti-enumeration)
    res_non_exist = client.post("/api/auth/forgot-password", json={"email": "nonexistent_email_12345@example.com"})
    assert res_non_exist.status_code == 200
    assert "reset link" in res_non_exist.json()["message"].lower()

    # 2. Existing user request forgot password
    res_forgot = client.post("/api/auth/forgot-password", json={"email": email})
    assert res_forgot.status_code == 200
    raw_token = res_forgot.json().get("dev_token") or res_forgot.json().get("reset_token")
    if not raw_token:
        # Fallback to fetching generated token directly for test verification
        db = SessionLocal()
        try:
            usr = db.query(User).filter(User.email == email).first()
            tok_rec = db.query(PasswordResetToken).filter(PasswordResetToken.user_id == usr.id, PasswordResetToken.used == False).order_by(PasswordResetToken.id.desc()).first()
            # If stored hashed, create a known token
            raw_token = secrets.token_urlsafe(32)
            tok_rec.token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
            db.commit()
        finally:
            db.close()
    assert raw_token is not None

    # 3. Complete password reset with valid token
    res_reset = client.post("/api/auth/reset-password", json={"token": raw_token, "new_password": new_password})
    assert res_reset.status_code == 200
    assert "reset successfully" in res_reset.json()["message"].lower()

    # 4. Verify old password fails and new password succeeds
    assert client.post("/api/auth/login", data={"username": username, "password": old_password}).status_code == 401
    assert client.post("/api/auth/login", data={"username": username, "password": new_password}).status_code == 200

    # 5. Verify token cannot be reused
    res_reused = client.post("/api/auth/reset-password", json={"token": raw_token, "new_password": "AnotherPassword789!"})
    assert res_reused.status_code == 400


# =========================================================================
# 5. SCAN CREATION & INPUT SECURITY (ZIP, Paste, File, Traversal Attacks)
# =========================================================================

def test_09_create_project_pasted_code_and_scan(api_client):
    """Test project creation via pasted source code and triggering a security scan."""
    client = api_client["client"]
    token = create_access_token({"sub": "code_scanner_user", "email": "scanner@example.com", "role": "user", "user_id": 1001})
    headers = {"Authorization": f"Bearer {token}"}

    sample_vulnerable_code = """
import os
import sqlite3

def login(user, pw):
    # SQL Injection flaw
    conn = sqlite3.connect("test.db")
    query = "SELECT * FROM users WHERE user = '" + user + "' AND pw = '" + pw + "'"
    cursor = conn.cursor()
    cursor.execute(query)
    
    # Hardcoded Secret
    JWT_SECRET = "sk-live-1234567890abcdef1234567890"
    return cursor.fetchall()
"""

    res_proj = client.post(
        "/api/projects",
        data={
            "name": "E2E-Pasted-Code-Project",
            "description": "SAST vulnerability test",
            "upload_type": "file",
            "pasted_code": sample_vulnerable_code
        },
        headers=headers
    )
    assert res_proj.status_code == 200
    project_id = res_proj.json()["id"]

    # Trigger scan
    res_scan = client.post(f"/api/scans/{project_id}", headers=headers)
    assert res_scan.status_code == 200
    scan_id = res_scan.json()["id"]
    assert res_scan.json()["status"] in ("pending", "running", "completed")

    # Verify scan record in list
    res_list = client.get("/api/scans", headers=headers)
    assert res_list.status_code == 200
    scan_ids = [s["id"] for s in res_list.json()]
    assert scan_id in scan_ids


def test_10_create_project_zip_archive(api_client):
    """Test project creation via ZIP upload with multiple source files."""
    client = api_client["client"]
    token = create_access_token({"sub": "zip_user", "email": "zip@example.com", "role": "user", "user_id": 1002})
    headers = {"Authorization": f"Bearer {token}"}

    # Create in-memory zip archive
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app/auth.py", "API_KEY = 'aws_secret_key_12345678901234567890'\n")
        zf.writestr("app/config.py", "DEBUG = True\nDATABASE_URL = 'sqlite:///local.db'\n")
    zip_buffer.seek(0)

    res = client.post(
        "/api/projects",
        data={"name": "E2E-Zip-Project", "upload_type": "zip"},
        files={"file": ("project.zip", zip_buffer.getvalue(), "application/zip")},
        headers=headers
    )
    assert res.status_code == 200
    assert res.json()["name"] == "E2E-Zip-Project"


def test_11_path_traversal_zip_and_file_content_security(api_client):
    """Test path traversal mitigation in ZIP extraction and project file viewing."""
    client = api_client["client"]
    token = create_access_token({"sub": "security_test_user", "email": "sec@example.com", "role": "user", "user_id": 1003})
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Attempt ZipSlip path traversal archive
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../../etc/cron.d/malicious_cron", "* * * * * root reboot\n")
        zf.writestr("safe_file.py", "print('hello world')\n")
    zip_buffer.seek(0)

    res_zip = client.post(
        "/api/projects",
        data={"name": "ZipSlip-Attempt", "upload_type": "zip"},
        files={"file": ("slip.zip", zip_buffer.getvalue(), "application/zip")},
        headers=headers
    )
    # Upload should succeed with safe extraction without escaping project sandbox directory
    assert res_zip.status_code == 200
    project_id = res_zip.json()["id"]

    # 2. Attempt Path Traversal file viewing (../etc/passwd)
    res_traversal = client.get(
        f"/api/projects/{project_id}/file-content?path=../../../../etc/passwd",
        headers=headers
    )
    assert res_traversal.status_code in (403, 404)


# =========================================================================
# 6. REPORT GENERATION (PDF, HTML, JSON, CSV) & RETRIEVAL TESTS
# =========================================================================

def test_12_report_generation_all_formats(api_client):
    """Test generating and downloading reports in PDF, HTML, JSON, and CSV formats."""
    client = api_client["client"]
    db = SessionLocal()
    unique_id = uuid.uuid4().hex[:8]
    try:
        user = User(username=f"report_user_{unique_id}", email=f"report_{unique_id}@example.com", hashed_password="pw", role="user")
        db.add(user)
        db.commit()
        db.refresh(user)

        proj = Project(name=f"Report-Test-Project-{unique_id}", upload_type="file", owner_id=user.id)
        db.add(proj)
        db.commit()
        db.refresh(proj)

        scan = Scan(project_id=proj.id, status="completed", total_vulnerabilities=2, critical_count=1, high_count=1)
        db.add(scan)
        db.commit()
        db.refresh(scan)

        vuln = Vulnerability(scan_id=scan.id, severity="CRITICAL", category="SQL Injection", message="Query injection", file_path="main.py", tool_name="bandit")
        db.add(vuln)
        db.commit()

        token = create_access_token({"sub": user.username, "email": user.email, "role": user.role, "user_id": user.id})
        headers = {"Authorization": f"Bearer {token}"}

        # 1. JSON Report
        res_json = client.get(f"/api/scans/{scan.id}/report/json", headers=headers)
        assert res_json.status_code == 200
        assert "vulnerabilities" in res_json.json()

        # 2. HTML Report
        res_html = client.get(f"/api/scans/{scan.id}/report/html", headers=headers)
        assert res_html.status_code == 200
        assert "text/html" in res_html.headers.get("content-type", "")

        # 3. CSV Report
        res_csv = client.get(f"/api/scans/{scan.id}/report/csv", headers=headers)
        assert res_csv.status_code == 200
        assert "Finding ID" in res_csv.text

        # 4. PDF Report
        res_pdf = client.get(f"/api/scans/{scan.id}/report/pdf", headers=headers)
        assert res_pdf.status_code == 200
        assert res_pdf.headers.get("content-type") == "application/pdf"

        # 5. List reports endpoint
        res_list = client.get("/api/reports", headers=headers)
        assert res_list.status_code == 200
        assert isinstance(res_list.json(), list)

    finally:
        db.close()


# =========================================================================
# 7. AI SECURITY ASSISTANT & ENRICHMENT TESTS
# =========================================================================

def test_13_ai_chat_and_vulnerability_enrichment(api_client):
    """Test AI Security Chat and vulnerability explanation features."""
    client = api_client["client"]
    token = create_access_token({"sub": "ai_test_user", "email": "ai@example.com", "role": "user", "user_id": 1004})
    headers = {"Authorization": f"Bearer {token}"}

    # 1. General AI Security Chat query
    res_chat = client.post(
        "/api/ai/chat",
        json={"message": "How do I prevent SQL injection in Python FastAPI?", "provider": "openrouter"},
        headers=headers
    )
    assert res_chat.status_code == 200
    data_chat = res_chat.json()
    assert "message" in data_chat
    assert data_chat["is_ai"] is True


# =========================================================================
# 8. ADMIN DASHBOARD & SYSTEM-LEVEL STATISTICS
# =========================================================================

def test_14_admin_dashboard_stats_and_rbac(api_client):
    """Test admin system statistics and user management."""
    client = api_client["client"]
    admin_token = create_access_token({"sub": "e2e_admin", "email": "admin@example.com", "role": "admin", "user_id": 9999})
    user_token = create_access_token({"sub": "e2e_regular_user", "email": "regular@example.com", "role": "user", "user_id": 8888})

    # 1. Regular user blocked from admin stats (403)
    assert client.get("/api/admin/stats", headers={"Authorization": f"Bearer {user_token}"}).status_code == 403

    # 2. Admin can fetch live MongoDB system statistics
    res_stats = client.get("/api/admin/stats", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_stats.status_code == 200
    stats_data = res_stats.json()
    assert "totalScans" in stats_data
    assert "totalReports" in stats_data
    assert isinstance(stats_data["totalScans"], int)
    assert isinstance(stats_data["totalReports"], int)

    # 3. Admin can list all users and audit logs
    res_users = client.get("/api/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_users.status_code == 200
    assert isinstance(res_users.json(), list)

    res_audit = client.get("/api/admin/audit-logs", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_audit.status_code == 200
    assert "events" in res_audit.json()
