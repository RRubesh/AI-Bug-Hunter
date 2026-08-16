import os
import shutil
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.database import Base
from backend.database import is_mongo_connected as database_is_mongo_connected
from backend.database import get_mongo_db as database_get_mongo_db
from backend.models import User, Project, Scan, Vulnerability
from backend.scanner.gitleaks_runner import GitleaksRunner
from backend.scanner.bandit_runner import BanditRunner
from backend.scanner.semgrep_runner import SemgrepRunner
from backend.scanner.dependency_runner import DependencyRunner
from backend.scanner.engine import detect_language
from backend.reports.pdf_gen import generate_pdf_report
from backend.reports.html_gen import generate_html_report
import backend.database as database_module
import backend.scanner.engine as scanner_engine

# Setup Test Database (in-memory SQLite)
from sqlalchemy.pool import StaticPool
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
    user = User(username="test_admin", hashed_password="hashed_password_123", role="admin")
    db_session.add(user)
    db_session.commit()
    
    saved_user = db_session.query(User).filter(User.username == "test_admin").first()
    assert saved_user is not None
    assert saved_user.role == "admin"

def test_secret_scanner():
    runner = GitleaksRunner()
    
    # Create temp file with fake secret
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
        shutil.rmtree(temp_dir)

def test_bandit_ast_scanner():
    runner = BanditRunner()
    
    # Create temp file with vulnerable python code
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
        shutil.rmtree(temp_dir)

def test_dependency_analyzer():
    runner = DependencyRunner()
    
    # Create temp file with vulnerable requirements
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
        shutil.rmtree(temp_dir)

def test_reports_generation(db_session):
    # Setup mock project and scan records
    user = User(username="test_dev", hashed_password="hashed_pwd", role="developer")
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
        tool_name="Bandit Test"
    )
    db_session.add(vuln)
    db_session.commit()
    
    # Verify PDF report generation
    pdf_path = "./test_report.pdf"
    generate_pdf_report(scan, project, [vuln], pdf_path)
    assert os.path.exists(pdf_path)
    os.remove(pdf_path)

    # Verify HTML report generation
    html_path = "./test_report.html"
    generate_html_report(scan, project, [vuln], html_path)
    assert os.path.exists(html_path)
    os.remove(html_path)


def test_execute_scan_task_completes_when_mongodb_is_unavailable(db_session, monkeypatch):
    user = User(username="scan_task_user", hashed_password="hashed_pwd", role="developer")
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
            "tool_name": "Bandit",
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


def test_admin_endpoints(db_session):
    from fastapi.testclient import TestClient
    from backend.main import app
    from backend.database import get_db
    
    # Override get_db
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    
    # Create test users
    from backend.auth.jwt import get_password_hash
    admin_user = User(username="admin_test", hashed_password=get_password_hash("adminpass"), role="admin")
    dev_user = User(username="dev_test", hashed_password=get_password_hash("devpass"), role="developer")
    db_session.add(admin_user)
    db_session.add(dev_user)
    db_session.commit()
    
    client = TestClient(app)
    
    # 1. Login as admin to get token
    res = client.post("/api/auth/login", data={"username": "admin_test", "password": "adminpass"})
    assert res.status_code == 200
    admin_token = res.json()["access_token"]
    
    # 2. Login as dev to get token
    res = client.post("/api/auth/login", data={"username": "dev_test", "password": "devpass"})
    assert res.status_code == 200
    dev_token = res.json()["access_token"]
    
    # 3. Try to list users as dev (should fail 403)
    res = client.get("/api/admin/users", headers={"Authorization": f"Bearer {dev_token}"})
    assert res.status_code == 403
    
    # 4. List users as admin (should succeed 200)
    res = client.get("/api/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    users_list = res.json()
    assert len(users_list) == 2
    
    # 5. Create user as admin (should succeed 201)
    res = client.post(
        "/api/admin/users?role=developer", 
        json={"username": "new_dev", "password": "newpassword123"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res.status_code == 201
    assert res.json()["username"] == "new_dev"
    assert res.json()["role"] == "developer"
    
    # Verify user created in DB
    new_user = db_session.query(User).filter(User.username == "new_dev").first()
    assert new_user is not None
    
    # 6. Create user as dev (should fail 403)
    res = client.post(
        "/api/admin/users?role=developer", 
        json={"username": "new_dev_2", "password": "newpassword123"},
        headers={"Authorization": f"Bearer {dev_token}"}
    )
    assert res.status_code == 403
    
    # 7. Delete user as dev (should fail 403)
    res = client.delete(f"/api/admin/users/{new_user.id}", headers={"Authorization": f"Bearer {dev_token}"})
    assert res.status_code == 403
    
    # 8. Delete user as admin (should succeed 200)
    res = client.delete(f"/api/admin/users/{new_user.id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    assert db_session.query(User).filter(User.username == "new_dev").first() is None
    
    # Clean up overrides
    app.dependency_overrides.clear()

def test_settings_endpoints(db_session):
    from fastapi.testclient import TestClient
    from backend.main import app
    from backend.database import get_db
    from backend.config import settings
    from backend.api.router import save_settings_to_env
    
    # Save original configurations to restore later
    original_url = settings.OPENROUTER_API_BASE_URL
    original_model = settings.DEFAULT_LLM_MODEL
    
    # Override get_db
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    
    client = TestClient(app)
    
    # Create test user
    from backend.auth.jwt import get_password_hash
    user = User(username="settings_dev", hashed_password=get_password_hash("password123"), role="developer")
    db_session.add(user)
    db_session.commit()
    
    # Get auth token
    res = client.post("/api/auth/login", data={"username": "settings_dev", "password": "password123"})
    assert res.status_code == 200
    token = res.json()["access_token"]
    
    try:
        # 1. Get settings
        res = client.get("/api/settings")
        assert res.status_code == 200
        data = res.json()
        assert "openrouter_api_url" in data
        assert "default_model" in data
        
        # 2. Update settings (without auth - should fail 401)
        res = client.post("/api/settings", json={"openrouter_api_url": "https://custom-router.ai/v1", "default_model": "test-model"})
        assert res.status_code == 401
        
        # 3. Update settings (with auth - should succeed)
        res = client.post(
            "/api/settings",
            json={"openrouter_api_url": "https://custom-router.ai/v1", "default_model": "test-model"},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["openrouter_api_url"] == "https://custom-router.ai/v1"
        assert data["default_model"] == "test-model"
    finally:
        # Restore original settings
        save_settings_to_env(openrouter_api_url=original_url, default_model=original_model)
        # Clean up overrides
        app.dependency_overrides.clear()


def test_create_project_zip(db_session):
    from fastapi.testclient import TestClient
    from backend.main import app
    from backend.database import get_db
    from pathlib import Path
    import io
    import zipfile
    
    # Override get_db
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    
    client = TestClient(app)
    
    # Create test user
    from backend.auth.jwt import get_password_hash
    user = User(username="zip_dev", hashed_password=get_password_hash("password123"), role="developer")
    db_session.add(user)
    db_session.commit()
    
    # Get auth token
    res = client.post("/api/auth/login", data={"username": "zip_dev", "password": "password123"})
    assert res.status_code == 200
    token = res.json()["access_token"]
    
    # Create dummy zip file in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("main.py", "print('hello world')")
    zip_buffer.seek(0)
    
    try:
        # Create project with ZIP upload
        res = client.post(
            "/api/projects",
            data={
                "name": "ZIP Test Project",
                "description": "A test project uploaded via ZIP archive",
                "upload_type": "zip"
            },
            files={"file": ("upload.zip", zip_buffer, "application/zip")},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["name"] == "ZIP Test Project"
        assert data["upload_type"] == "zip"
        
        # Verify project exists in DB and files were extracted
        project = db_session.query(Project).filter(Project.name == "ZIP Test Project").first()
        assert project is not None
        
        project_dir = Path(project.file_path)
        assert project_dir.exists()
        extracted_file = project_dir / "main.py"
        assert extracted_file.exists()
        with open(extracted_file, "r") as f:
            assert f.read() == "print('hello world')"
            
        # Clean up files created
        shutil.rmtree(project_dir)
        
    finally:
        # Clean up overrides
        app.dependency_overrides.clear()


def test_ai_endpoint_restrictions(db_session):
    from fastapi.testclient import TestClient
    from backend.main import app
    from backend.database import get_db
    from unittest.mock import AsyncMock
    from backend.ai.openrouter_client import openrouter_client
    from backend.auth.jwt import get_password_hash

    # Override get_db
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    
    client = TestClient(app)
    
    # Mock LLM calls
    original_chat = openrouter_client.chat_about_scan
    original_enrich = openrouter_client.explain_vulnerability
    openrouter_client.chat_about_scan = AsyncMock(return_value="Mocked AI response")
    openrouter_client.explain_vulnerability = AsyncMock(return_value={"explanation": "Mocked explanation", "fix": "Mocked fix"})
    
    try:
        # Create users
        admin = User(username="admin_ai", hashed_password=get_password_hash("pass"), role="admin")
        paid = User(username="paid_ai", hashed_password=get_password_hash("pass"), role="paid")
        free = User(username="free_ai", hashed_password=get_password_hash("pass"), role="developer")
        db_session.add(admin)
        db_session.add(paid)
        db_session.add(free)
        db_session.commit()
        
        # Logins
        res = client.post("/api/auth/login", data={"username": "admin_ai", "password": "pass"})
        admin_token = res.json()["access_token"]
        
        res = client.post("/api/auth/login", data={"username": "paid_ai", "password": "pass"})
        paid_token = res.json()["access_token"]
        
        res = client.post("/api/auth/login", data={"username": "free_ai", "password": "pass"})
        free_token = res.json()["access_token"]
        
        # Create project, scan, and vulnerability
        proj = Project(name="AI Test Proj", upload_type="file", owner_id=free.id)
        db_session.add(proj)
        db_session.commit()
        
        scan = Scan(project_id=proj.id, status="completed")
        db_session.add(scan)
        db_session.commit()
        
        vuln = Vulnerability(
            scan_id=scan.id,
            file_path="main.py",
            severity="HIGH",
            category="SQLi",
            message="vuln msg",
            tool_name="Bandit"
        )
        db_session.add(vuln)
        db_session.commit()
        
        # 1. Test chat restriction for FREE user (should fail 403)
        res = client.post(
            f"/api/ai/chat/{scan.id}",
            json={"message": "hello"},
            headers={"Authorization": f"Bearer {free_token}"}
        )
        assert res.status_code == 403
        assert "upgrade your plan" in res.json()["detail"]
        
        # 2. Test enrich restriction for FREE user (should fail 403)
        res = client.post(
            f"/api/ai/enrich/{vuln.id}",
            headers={"Authorization": f"Bearer {free_token}"}
        )
        assert res.status_code == 403
        
        # 3. Test chat for PAID user (should succeed 200 or 403 if project ownership is checked)
        # Note: project owner is 'free.id', but let's make PAID user the owner or admin
        # Let's change the project owner to 'paid.id' first to check paid authorization
        proj.owner_id = paid.id
        db_session.commit()
        
        res = client.post(
            f"/api/ai/chat/{scan.id}",
            json={"message": "hello"},
            headers={"Authorization": f"Bearer {paid_token}"}
        )
        assert res.status_code == 200
        assert res.json()["message"] == "Mocked AI response"
        
        res = client.post(
            f"/api/ai/enrich/{vuln.id}",
            headers={"Authorization": f"Bearer {paid_token}"}
        )
        assert res.status_code == 200
        
        # 4. Test admin authorization (regardless of ownership)
        res = client.post(
            f"/api/ai/chat/{scan.id}",
            json={"message": "hello"},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert res.status_code == 200
        
    finally:
        # Restore mock objects
        openrouter_client.chat_about_scan = original_chat
        openrouter_client.explain_vulnerability = original_enrich
        # Clean up overrides
        app.dependency_overrides.clear()



