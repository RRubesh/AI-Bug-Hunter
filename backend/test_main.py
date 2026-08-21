import os
import shutil
import pytest
import io
import zipfile
from unittest.mock import AsyncMock
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base
import backend.database as database_module
from backend.models import User, Project, Scan, Vulnerability, PasswordResetToken
from backend.scanner.gitleaks_runner import GitleaksRunner
from backend.scanner.bandit_runner import BanditRunner
from backend.scanner.semgrep_runner import SemgrepRunner
from backend.scanner.dependency_runner import DependencyRunner
from backend.reports.pdf_gen import generate_pdf_report
from backend.reports.html_gen import generate_html_report
import backend.scanner.engine as scanner_engine
from backend.auth.jwt import get_password_hash

# Setup In-Memory SQLite Test Database
TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DATABASE_URL, 
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

def test_user_creation(db_session):
    user = User(
        username="test_admin", 
        email="test_admin@aibughunter.local",
        hashed_password=get_password_hash("ValidPass123!"), 
        role="admin"
    )
    db_session.add(user)
    db_session.commit()
    
    saved_user = db_session.query(User).filter(User.username == "test_admin").first()
    assert saved_user is not None
    assert saved_user.email == "test_admin@aibughunter.local"
    assert saved_user.role == "admin"

def test_secret_scanner():
    runner = GitleaksRunner()
    temp_dir = "./temp_test_secret"
    os.makedirs(temp_dir, exist_ok=True)
    temp_file = os.path.join(temp_dir, "test.py")
    with open(temp_file, "w") as f:
        f.write("aws_secret = 'aws_secret_access_key=\"aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ABCD\"'")
        
    try:
        findings = runner.scan(temp_dir)
        assert len(findings) > 0
        assert findings[0]["category"] == "Hardcoded Secret"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_bandit_ast_scanner():
    runner = BanditRunner()
    temp_dir = "./temp_test_ast"
    os.makedirs(temp_dir, exist_ok=True)
    temp_file = os.path.join(temp_dir, "test.py")
    with open(temp_file, "w") as f:
        f.write("query = 'SELECT * FROM users WHERE name = ' + user_input\ncursor.execute(query)\neval('print(123)')\n")
        
    try:
        findings = runner.scan(temp_dir)
        categories = [item["category"] for item in findings]
        assert "SQL Injection" in categories
        assert "Code Injection" in categories
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_dependency_analyzer():
    runner = DependencyRunner()
    temp_dir = "./temp_test_deps"
    os.makedirs(temp_dir, exist_ok=True)
    temp_file = os.path.join(temp_dir, "requirements.txt")
    with open(temp_file, "w") as f:
        f.write("django==3.2.1\nrequests==2.10.0\n")
        
    try:
        findings = runner.scan(temp_dir)
        assert len(findings) >= 2
        categories = [item["category"] for item in findings]
        assert "Vulnerable Dependency" in categories
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_reports_generation(db_session):
    user = User(username="test_user", email="user@aibughunter.local", hashed_password="pwd", role="user")
    db_session.add(user)
    db_session.commit()
    
    project = Project(name="TestProj", upload_type="file", owner_id=user.id)
    db_session.add(project)
    db_session.commit()
    
    scan = Scan(project_id=project.id, status="completed", total_vulnerabilities=1)
    db_session.add(scan)
    db_session.commit()
    
    vuln = Vulnerability(
        scan_id=scan.id,
        file_path="main.py",
        line_number=10,
        severity="HIGH",
        category="SQL Injection",
        message="Concat query execution found",
        tool_name="Bandit AST"
    )
    db_session.add(vuln)
    db_session.commit()
    
    pdf_path = "./test_report.pdf"
    generate_pdf_report(scan, project, [vuln], pdf_path)
    assert os.path.exists(pdf_path)
    os.remove(pdf_path)

    html_path = "./test_report.html"
    generate_html_report(scan, project, [vuln], html_path)
    assert os.path.exists(html_path)
    os.remove(html_path)

def test_execute_scan_task_completes_when_mongodb_is_unavailable(db_session, monkeypatch):
    user = User(username="scan_user", email="scan_user@aibughunter.local", hashed_password="pwd", role="user")
    db_session.add(user)
    db_session.commit()

    project = Project(name="scan_task_project", upload_type="folder", owner_id=user.id)
    db_session.add(project)
    db_session.commit()

    scan = Scan(project_id=project.id, status="pending", progress=0)
    db_session.add(scan)
    db_session.commit()
    scan_id = scan.id

    temp_dir = "./temp_test_scan_engine"
    os.makedirs(temp_dir, exist_ok=True)
    sample_file = os.path.join(temp_dir, "app.py")
    with open(sample_file, "w") as f:
        f.write("import subprocess\nsubprocess.run(['echo', 'hello'])\n")

    try:
        monkeypatch.setattr(GitleaksRunner, "scan", lambda self, path: [])
        monkeypatch.setattr(BanditRunner, "scan", lambda self, path: [{
            "file_path": "app.py",
            "line_number": 2,
            "category": "Command Injection",
            "severity": "HIGH",
            "message": "subprocess execution found",
            "tool_name": "Bandit AST",
            "code_snippet": "subprocess.run(['echo', 'hello'])",
            "remediation": "Validate command inputs"
        }])
        monkeypatch.setattr(SemgrepRunner, "scan", lambda self, path: [])
        monkeypatch.setattr(DependencyRunner, "scan", lambda self, path: [])
        monkeypatch.setattr(database_module, "is_mongo_connected", lambda: False)
        monkeypatch.setattr(database_module, "get_mongo_db", lambda: None)
        monkeypatch.setattr(scanner_engine.openrouter_client, "explain_vulnerability_sync", lambda *args, **kwargs: {"explanation": "Test explanation", "fix": "Use safer APIs"})

        scanner_engine.execute_scan_task(lambda: db_session, scan_id, temp_dir)

        fresh_session = TestingSessionLocal()
        try:
            refreshed = fresh_session.query(Scan).filter(Scan.id == scan_id).one()
            assert refreshed.status == "completed"
            assert refreshed.total_vulnerabilities == 1
            assert refreshed.high_count == 1
        finally:
            fresh_session.close()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_auth_registration_and_validation(db_session):
    from fastapi.testclient import TestClient
    from backend.main import app
    from backend.database import get_db

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    try:
        # 1. First user registration automatically becomes admin
        res = client.post("/api/auth/register", json={
            "username": "superadmin",
            "email": "admin@company.com",
            "password": "StrongPassword123!"
        })
        assert res.status_code == 201
        admin_data = res.json()
        assert admin_data["role"] == "admin"
        assert admin_data["email"] == "admin@company.com"

        # 2. Subsequent registration creates normal USER
        res = client.post("/api/auth/register", json={
            "username": "regular_user",
            "email": "user@company.com",
            "password": "SecureUserPass456!"
        })
        assert res.status_code == 201
        user_data = res.json()
        assert user_data["role"] == "user"
        assert user_data["email"] == "user@company.com"

        # 3. Invalid email format rejected
        res = client.post("/api/auth/register", json={
            "username": "bad_email_user",
            "email": "not-an-email",
            "password": "SecureUserPass456!"
        })
        assert res.status_code == 400
        assert "valid email" in res.json()["detail"].lower()

        # 4. Weak password rejected
        res = client.post("/api/auth/register", json={
            "username": "weak_pwd_user",
            "email": "weak@company.com",
            "password": "short"
        })
        assert res.status_code == 400
        assert "at least 8 characters" in res.json()["detail"]

        # 5. Duplicate username / email rejected
        res = client.post("/api/auth/register", json={
            "username": "regular_user",
            "email": "another@company.com",
            "password": "SecureUserPass456!"
        })
        assert res.status_code == 400

        res = client.post("/api/auth/register", json={
            "username": "brand_new_user",
            "email": "user@company.com",
            "password": "SecureUserPass456!"
        })
        assert res.status_code == 400
    finally:
        app.dependency_overrides.clear()

def test_forgot_password_and_crypto_reset_token(db_session):
    from fastapi.testclient import TestClient
    from backend.main import app
    from backend.database import get_db

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    try:
        # Create user
        user = User(
            username="recovery_user",
            email="recovery@aibughunter.com",
            hashed_password=get_password_hash("OldPassword123!"),
            role="user"
        )
        db_session.add(user)
        db_session.commit()

        # 1. Non-existent email returns generic message (no user enumeration)
        res = client.post("/api/auth/forgot-password", json={"email": "nonexistent@company.com"})
        assert res.status_code == 200
        assert "If an account exists" in res.json()["message"]

        # 2. Existing email generates reset token record
        res = client.post("/api/auth/forgot-password", json={"email": "recovery@aibughunter.com"})
        assert res.status_code == 200
        assert "If an account exists" in res.json()["message"]
        
        # Verify token in DB
        token_record = db_session.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used == False
        ).first()
        assert token_record is not None

        # 3. If dev_token is present in response, test password reset
        dev_token = res.json().get("dev_token")
        if dev_token:
            # Bad token attempt
            bad_res = client.post("/api/auth/reset-password", json={
                "token": "completely_invalid_token",
                "new_password": "NewSecurePassword789!"
            })
            assert bad_res.status_code == 400

            # Valid token attempt with 'password' field name
            good_res = client.post("/api/auth/reset-password", json={
                "token": dev_token,
                "password": "NewSecurePassword789!"
            })
            assert good_res.status_code == 200
            assert "successfully" in good_res.json()["message"]

            # Token should now be marked as used (cannot reuse)
            reuse_res = client.post("/api/auth/reset-password", json={
                "token": dev_token,
                "new_password": "AnotherPassword999!"
            })
            assert reuse_res.status_code == 400

            # Old password MUST NOT work
            old_login_res = client.post("/api/auth/login", data={
                "username": "recovery_user",
                "password": "OldPassword123!"
            })
            assert old_login_res.status_code == 401

            # New password MUST work
            login_res = client.post("/api/auth/login", data={
                "username": "recovery_user",
                "password": "NewSecurePassword789!"
            })
            assert login_res.status_code == 200
            assert "access_token" in login_res.json()
    finally:
        app.dependency_overrides.clear()

def test_strict_data_isolation_between_users(db_session):
    from fastapi.testclient import TestClient
    from backend.main import app
    from backend.database import get_db

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    try:
        # Create User A, User B, Admin
        user_a = User(username="alice", email="alice@corp.com", hashed_password=get_password_hash("AlicePass123!"), role="user")
        user_b = User(username="bob", email="bob@corp.com", hashed_password=get_password_hash("BobPass123!"), role="user")
        admin = User(username="admin_boss", email="boss@corp.com", hashed_password=get_password_hash("AdminPass123!"), role="admin")
        db_session.add_all([user_a, user_b, admin])
        db_session.commit()

        # Alice's Project, Scan, Vuln
        proj_a = Project(name="Alice Project", upload_type="file", owner_id=user_a.id)
        db_session.add(proj_a)
        db_session.commit()

        scan_a = Scan(project_id=proj_a.id, status="completed", total_vulnerabilities=1)
        db_session.add(scan_a)
        db_session.commit()

        vuln_a = Vulnerability(
            scan_id=scan_a.id,
            file_path="alice_secrets.py",
            severity="CRITICAL",
            category="Hardcoded Secret",
            message="Leaked AWS token in Alice's project",
            tool_name="Gitleaks"
        )
        db_session.add(vuln_a)
        db_session.commit()

        # Login Alice, Bob, Admin
        res_a = client.post("/api/auth/login", data={"username": "alice", "password": "AlicePass123!"})
        token_a = res_a.json()["access_token"]

        res_b = client.post("/api/auth/login", data={"username": "bob", "password": "BobPass123!"})
        token_b = res_b.json()["access_token"]

        res_admin = client.post("/api/auth/login", data={"username": "admin_boss", "password": "AdminPass123!"})
        token_admin = res_admin.json()["access_token"]

        # 1. Alice can view her project
        res = client.get(f"/api/projects/{proj_a.id}", headers={"Authorization": f"Bearer {token_a}"})
        assert res.status_code == 200

        # 2. Bob CANNOT view Alice's project (403 Forbidden)
        res = client.get(f"/api/projects/{proj_a.id}", headers={"Authorization": f"Bearer {token_b}"})
        assert res.status_code == 403

        # 3. Bob CANNOT view Alice's scan (403 Forbidden)
        res = client.get(f"/api/scans/{scan_a.id}", headers={"Authorization": f"Bearer {token_b}"})
        assert res.status_code == 403

        # 4. Bob CANNOT delete Alice's project (403 Forbidden)
        res = client.delete(f"/api/projects/{proj_a.id}", headers={"Authorization": f"Bearer {token_b}"})
        assert res.status_code == 403

        # 5. Bob's project list only shows his own projects
        res = client.get("/api/projects", headers={"Authorization": f"Bearer {token_b}"})
        assert res.status_code == 200
        assert len(res.json()) == 0

        # 6. Admin can view Alice's project
        res = client.get(f"/api/projects/{proj_a.id}", headers={"Authorization": f"Bearer {token_admin}"})
        assert res.status_code == 200

        # 7. Admin sees all projects in project list
        res = client.get("/api/projects", headers={"Authorization": f"Bearer {token_admin}"})
        assert res.status_code == 200
        assert len(res.json()) == 1
    finally:
        app.dependency_overrides.clear()

def test_admin_user_management_and_rbac(db_session):
    from fastapi.testclient import TestClient
    from backend.main import app
    from backend.database import get_db

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    try:
        admin_user = User(username="admin_manage", email="admin_manage@corp.com", hashed_password=get_password_hash("AdminPass123!"), role="admin")
        standard_user = User(username="standard_manage", email="standard_manage@corp.com", hashed_password=get_password_hash("UserPass123!"), role="user")
        db_session.add_all([admin_user, standard_user])
        db_session.commit()

        # Login
        admin_res = client.post("/api/auth/login", data={"username": "admin_manage", "password": "AdminPass123!"})
        admin_token = admin_res.json()["access_token"]

        user_res = client.post("/api/auth/login", data={"username": "standard_manage", "password": "UserPass123!"})
        user_token = user_res.json()["access_token"]

        # 1. Standard user blocked from /api/admin/users (403)
        res = client.get("/api/admin/users", headers={"Authorization": f"Bearer {user_token}"})
        assert res.status_code == 403

        # 2. Admin can list users
        res = client.get("/api/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
        assert res.status_code == 200
        assert len(res.json()) == 2

        # 3. Admin creates user with valid role "user"
        res = client.post(
            "/api/admin/users",
            json={"username": "created_by_admin", "email": "created@corp.com", "password": "Pass12345!", "role": "user"},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert res.status_code == 201
        created_user_id = res.json()["id"]

        # 4. Admin rejects deprecated "developer" role
        res = client.post(
            "/api/admin/users",
            json={"username": "bad_role_user", "email": "badrole@corp.com", "password": "Pass12345!", "role": "developer"},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert res.status_code == 400
        assert "allowed roles" in res.json()["detail"].lower()

        # 5. Admin promotes user to admin
        res = client.post(
            f"/api/admin/users/{created_user_id}/role",
            json={"role": "admin"},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert res.status_code == 200

        # 6. Admin cannot delete own account
        res = client.delete(f"/api/admin/users/{admin_user.id}", headers={"Authorization": f"Bearer {admin_token}"})
        assert res.status_code == 400
        assert "cannot delete" in res.json()["detail"].lower()

        # 7. Admin can access audit logs
        res = client.get("/api/admin/audit-logs", headers={"Authorization": f"Bearer {admin_token}"})
        assert res.status_code == 200
        assert "events" in res.json()
    finally:
        app.dependency_overrides.clear()

def test_settings_endpoints(db_session):
    from fastapi.testclient import TestClient
    from backend.main import app
    from backend.database import get_db
    from backend.config import settings
    from backend.api.router import save_settings_to_env

    original_url = settings.OPENROUTER_API_BASE_URL
    original_model = settings.DEFAULT_LLM_MODEL

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    user = User(username="settings_user", email="settings@corp.com", hashed_password=get_password_hash("Pass12345!"), role="user")
    db_session.add(user)
    db_session.commit()

    res = client.post("/api/auth/login", data={"username": "settings_user", "password": "Pass12345!"})
    token = res.json()["access_token"]

    try:
        # 1. Unauthenticated settings update fails
        res = client.post("/api/settings", json={"openrouter_api_url": "https://custom-router.ai/v1", "default_model": "test-model"})
        assert res.status_code == 401

        # 2. Authenticated settings update succeeds
        res = client.post(
            "/api/settings",
            json={"openrouter_api_url": "https://custom-router.ai/v1", "default_model": "test-model"},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert res.status_code == 200
        assert res.json()["openrouter_api_url"] == "https://custom-router.ai/v1"
    finally:
        save_settings_to_env(openrouter_api_url=original_url, default_model=original_model)
        app.dependency_overrides.clear()

def test_create_project_zip(db_session):
    from fastapi.testclient import TestClient
    from backend.main import app
    from backend.database import get_db

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    user = User(username="zip_user", email="zip_user@corp.com", hashed_password=get_password_hash("Pass12345!"), role="user")
    db_session.add(user)
    db_session.commit()

    res = client.post("/api/auth/login", data={"username": "zip_user", "password": "Pass12345!"})
    token = res.json()["access_token"]

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("main.py", "print('hello secure world')")
    zip_buffer.seek(0)

    try:
        res = client.post(
            "/api/projects",
            data={
                "name": "ZIP Enterprise Project",
                "description": "A secure project uploaded via ZIP archive",
                "upload_type": "zip"
            },
            files={"file": ("upload.zip", zip_buffer, "application/zip")},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["name"] == "ZIP Enterprise Project"
        assert data["upload_type"] == "zip"

        project = db_session.query(Project).filter(Project.name == "ZIP Enterprise Project").first()
        assert project is not None
        project_dir = Path(project.file_path)
        assert project_dir.exists()
        shutil.rmtree(project_dir, ignore_errors=True)
    finally:
        app.dependency_overrides.clear()
