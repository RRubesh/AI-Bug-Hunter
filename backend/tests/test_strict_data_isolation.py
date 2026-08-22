import os
import sys
import uuid
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.main import app
from backend.database import get_db, SessionLocal, engine, Base
from backend.models import User, Project, Scan, Vulnerability
from backend.auth.jwt import get_password_hash, create_access_token

@pytest.fixture(scope="module")
def isolation_environment():
    """
    Sets up 4 distinct accounts (User A, User B, Admin A, Admin B)
    and populates projects, scans, and vulnerabilities to test strict data isolation.
    """
    Base.metadata.create_all(bind=engine)
    db: Session = SessionLocal()

    # Clean prior test users
    db.query(User).filter(User.email.in_([
        "user_a@isolation.test", "user_b@isolation.test", 
        "admin_a@isolation.test", "admin_b@isolation.test"
    ])).delete(synchronize_session=False)
    db.commit()

    # 1. Create User A
    user_a = User(
        username="user_a_iso",
        email="user_a@isolation.test",
        hashed_password=get_password_hash("UserAPass123!"),
        role="user",
        is_active=True
    )
    # 2. Create User B
    user_b = User(
        username="user_b_iso",
        email="user_b@isolation.test",
        hashed_password=get_password_hash("UserBPass123!"),
        role="user",
        is_active=True
    )
    # 3. Create Admin A
    admin_a = User(
        username="admin_a_iso",
        email="admin_a@isolation.test",
        hashed_password=get_password_hash("AdminAPass123!"),
        role="admin",
        is_active=True
    )
    # 4. Create Admin B
    admin_b = User(
        username="admin_b_iso",
        email="admin_b@isolation.test",
        hashed_password=get_password_hash("AdminBPass123!"),
        role="admin",
        is_active=True
    )
    db.add_all([user_a, user_b, admin_a, admin_b])
    db.commit()
    db.refresh(user_a)
    db.refresh(user_b)
    db.refresh(admin_a)
    db.refresh(admin_b)

    # User A Project & Scan
    proj_a = Project(name="Project-User-A", upload_type="file", owner_id=user_a.id)
    db.add(proj_a)
    db.commit()
    db.refresh(proj_a)

    scan_a = Scan(
        project_id=proj_a.id, 
        status="completed", 
        critical_count=1, 
        high_count=2, 
        medium_count=0, 
        low_count=0,
        total_vulnerabilities=3
    )
    db.add(scan_a)
    db.commit()
    db.refresh(scan_a)

    vuln_a = Vulnerability(
        scan_id=scan_a.id,
        severity="CRITICAL",
        category="Hardcoded Secret",
        message="User A Private Key detected",
        file_path="src/secrets.py",
        tool_name="gitleaks"
    )
    db.add(vuln_a)
    db.commit()
    db.refresh(vuln_a)

    # User B Project & Scan
    proj_b = Project(name="Project-User-B", upload_type="file", owner_id=user_b.id)
    db.add(proj_b)
    db.commit()
    db.refresh(proj_b)

    scan_b = Scan(
        project_id=proj_b.id, 
        status="completed", 
        critical_count=5, 
        high_count=4, 
        medium_count=3, 
        low_count=2,
        total_vulnerabilities=14
    )
    db.add(scan_b)
    db.commit()
    db.refresh(scan_b)

    vuln_b = Vulnerability(
        scan_id=scan_b.id,
        severity="HIGH",
        category="SQL Injection",
        message="User B SQL injection flaw in billing",
        file_path="src/billing.py",
        tool_name="bandit"
    )
    db.add(vuln_b)
    db.commit()
    db.refresh(vuln_b)

    # Generate Auth JWT Tokens
    token_a = create_access_token({"sub": user_a.username, "email": user_a.email, "role": user_a.role, "user_id": user_a.id})
    token_b = create_access_token({"sub": user_b.username, "email": user_b.email, "role": user_b.role, "user_id": user_b.id})
    token_admin_a = create_access_token({"sub": admin_a.username, "email": admin_a.email, "role": admin_a.role, "user_id": admin_a.id})
    token_admin_b = create_access_token({"sub": admin_b.username, "email": admin_b.email, "role": admin_b.role, "user_id": admin_b.id})

    client = TestClient(app)

    yield {
        "client": client,
        "db": db,
        "user_a": user_a,
        "user_b": user_b,
        "admin_a": admin_a,
        "admin_b": admin_b,
        "proj_a": proj_a,
        "proj_b": proj_b,
        "scan_a": scan_a,
        "scan_b": scan_b,
        "vuln_a": vuln_a,
        "vuln_b": vuln_b,
        "token_a": token_a,
        "token_b": token_b,
        "token_admin_a": token_admin_a,
        "token_admin_b": token_admin_b
    }

    # Teardown
    try:
        db.delete(vuln_a)
        db.delete(vuln_b)
        db.delete(scan_a)
        db.delete(scan_b)
        db.delete(proj_a)
        db.delete(proj_b)
        db.delete(user_a)
        db.delete(user_b)
        db.delete(admin_a)
        db.delete(admin_b)
        db.commit()
    except Exception:
        pass
    db.close()


def test_01_user_a_can_access_own_data(isolation_environment):
    """User A should be able to view their own projects, scans, and vulnerabilities."""
    env = isolation_environment
    client = env["client"]
    headers = {"Authorization": f"Bearer {env['token_a']}"}

    # 1. Projects
    res = client.get("/api/projects", headers=headers)
    assert res.status_code == 200
    project_ids = [p["id"] for p in res.json()]
    assert env["proj_a"].id in project_ids
    assert env["proj_b"].id not in project_ids

    # 2. Scans
    res = client.get("/api/scans", headers=headers)
    assert res.status_code == 200
    scan_ids = [s["id"] for s in res.json()]
    assert env["scan_a"].id in scan_ids
    assert env["scan_b"].id not in scan_ids

    # 3. Vulnerabilities
    res = client.get("/api/vulnerabilities", headers=headers)
    assert res.status_code == 200
    vuln_ids = [v["id"] for v in res.json()]
    assert env["vuln_a"].id in vuln_ids
    assert env["vuln_b"].id not in vuln_ids


def test_02_user_b_can_access_own_data(isolation_environment):
    """User B should be able to view their own data and none of User A's data."""
    env = isolation_environment
    client = env["client"]
    headers = {"Authorization": f"Bearer {env['token_b']}"}

    # 1. Projects
    res = client.get("/api/projects", headers=headers)
    assert res.status_code == 200
    project_ids = [p["id"] for p in res.json()]
    assert env["proj_b"].id in project_ids
    assert env["proj_a"].id not in project_ids

    # 2. Scans
    res = client.get("/api/scans", headers=headers)
    assert res.status_code == 200
    scan_ids = [s["id"] for s in res.json()]
    assert env["scan_b"].id in scan_ids
    assert env["scan_a"].id not in scan_ids


def test_03_idor_attack_on_scans_blocked(isolation_environment):
    """User A attempts to access User B's scan details by ID (BOLA/IDOR) -> 403 Forbidden."""
    env = isolation_environment
    client = env["client"]
    headers = {"Authorization": f"Bearer {env['token_a']}"}

    # User A accesses User B's scan
    res = client.get(f"/api/scans/{env['scan_b'].id}", headers=headers)
    assert res.status_code == 403
    assert "not authorized" in res.json()["detail"].lower()

    # User A attempts to cancel User B's scan
    res = client.post(f"/api/scans/{env['scan_b'].id}/cancel", headers=headers)
    assert res.status_code == 403

    # User A attempts to delete User B's scan
    res = client.delete(f"/api/scans/{env['scan_b'].id}", headers=headers)
    assert res.status_code == 403


def test_04_idor_attack_on_projects_blocked(isolation_environment):
    """User A attempts to access or delete User B's project by ID -> 403 Forbidden."""
    env = isolation_environment
    client = env["client"]
    headers = {"Authorization": f"Bearer {env['token_a']}"}

    # User A accesses User B's project
    res = client.get(f"/api/projects/{env['proj_b'].id}", headers=headers)
    assert res.status_code == 403

    # User A deletes User B's project
    res = client.delete(f"/api/projects/{env['proj_b'].id}", headers=headers)
    assert res.status_code == 403

    # User A triggers scan on User B's project
    res = client.post(f"/api/scans/{env['proj_b'].id}", headers=headers)
    assert res.status_code == 403


def test_05_idor_attack_on_vulnerabilities_blocked(isolation_environment):
    """User A attempts to read or mutate User B's vulnerability findings -> 403 Forbidden."""
    env = isolation_environment
    client = env["client"]
    headers = {"Authorization": f"Bearer {env['token_a']}"}

    # User A reads User B's vulnerability
    res = client.get(f"/api/vulnerabilities/{env['vuln_b'].id}", headers=headers)
    assert res.status_code == 403

    # User A updates status on User B's vulnerability
    res = client.patch(
        f"/api/vulnerabilities/{env['vuln_b'].id}",
        json={"status": "false_positive"},
        headers=headers
    )
    assert res.status_code == 403


def test_06_idor_attack_on_reports_blocked(isolation_environment):
    """User A attempts to download User B's report -> 403 Forbidden."""
    env = isolation_environment
    client = env["client"]
    headers = {"Authorization": f"Bearer {env['token_a']}"}

    # User A requests User B's PDF report
    res = client.get(f"/api/scans/{env['scan_b'].id}/report/pdf", headers=headers)
    assert res.status_code == 403

    # User A requests User B's JSON report
    res = client.get(f"/api/scans/{env['scan_b'].id}/report/json", headers=headers)
    assert res.status_code == 403

    # User A requests User B's report detail
    res = client.get(f"/api/reports/{env['scan_b'].id}", headers=headers)
    assert res.status_code == 403


def test_07_idor_attack_on_ai_chat_and_analysis_blocked(isolation_environment):
    """User A attempts to interact with AI analysis or chat for User B's scan -> 403 Forbidden."""
    env = isolation_environment
    client = env["client"]
    headers = {"Authorization": f"Bearer {env['token_a']}"}

    # User A chats about User B's scan
    res = client.post(
        f"/api/ai/chat/{env['scan_b'].id}",
        json={"message": "Explain vulnerabilities in this project"},
        headers=headers
    )
    assert res.status_code == 403

    # User A requests AI explanation for User B's vulnerability
    res = client.post(f"/api/ai/enrich/{env['vuln_b'].id}", headers=headers)
    assert res.status_code == 403


def test_08_user_dashboard_statistics_scoping(isolation_environment):
    """User A's dashboard summary and stats must calculate ONLY from User A's data."""
    env = isolation_environment
    client = env["client"]
    headers = {"Authorization": f"Bearer {env['token_a']}"}

    res = client.get("/api/dashboard/summary", headers=headers)
    assert res.status_code == 200
    data = res.json()

    # User A has 1 completed scan with 1 critical, 2 high (total 3 findings)
    # User B has 1 completed scan with 5 critical, 4 high, 3 medium, 2 low (total 14 findings)
    assert data["total_scans"] == 1
    assert data["critical"] == 1
    assert data["high"] == 2
    assert data["total_vulnerabilities"] == 3
    # Security score penalty for User A: 1*15 + 2*8 = 31 -> score = 69
    assert data["security_score"] == 69


def test_09_user_profile_isolation_and_secret_protection(isolation_environment):
    """User can view ONLY their own profile and cannot scrape other users."""
    env = isolation_environment
    client = env["client"]
    headers_a = {"Authorization": f"Bearer {env['token_a']}"}

    # 1. User A views own profile
    res = client.get("/api/users/me", headers=headers_a)
    assert res.status_code == 200
    user_data = res.json()
    assert user_data["username"] == "user_a_iso"
    assert user_data["email"] == "user_a@isolation.test"
    # Secrets & password hashes must never be exposed
    assert "password_hash" not in user_data
    assert "hashed_password" not in user_data

    # 2. User A attempts to view User B's profile by ID -> 403 Forbidden
    res_other = client.get(f"/api/users/{env['user_b'].id}", headers=headers_a)
    assert res_other.status_code == 403


def test_10_normal_users_blocked_from_admin_routes(isolation_environment):
    """Normal User A and User B must receive 403 Forbidden on all admin endpoints."""
    env = isolation_environment
    client = env["client"]
    headers_a = {"Authorization": f"Bearer {env['token_a']}"}
    headers_b = {"Authorization": f"Bearer {env['token_b']}"}

    # User A blocked from admin endpoints
    assert client.get("/api/admin/users", headers=headers_a).status_code == 403
    assert client.get("/api/admin/audit-logs", headers=headers_a).status_code == 403
    assert client.get("/api/admin/stats", headers=headers_a).status_code == 403

    # User B blocked from admin endpoints
    assert client.get("/api/admin/users", headers=headers_b).status_code == 403
    assert client.get("/api/admin/audit-logs", headers=headers_b).status_code == 403
    assert client.get("/api/admin/stats", headers=headers_b).status_code == 403


def test_11_admin_system_level_statistics_and_access(isolation_environment):
    """Both Admin A and Admin B can access system-level statistics (Total Scans & Total Reports)."""
    env = isolation_environment
    client = env["client"]
    headers_admin_a = {"Authorization": f"Bearer {env['token_admin_a']}"}
    headers_admin_b = {"Authorization": f"Bearer {env['token_admin_b']}"}

    # Admin A
    res_a = client.get("/api/admin/stats", headers=headers_admin_a)
    assert res_a.status_code == 200
    stats_a = res_a.json()
    assert "totalScans" in stats_a
    assert "totalReports" in stats_a
    assert stats_a["totalScans"] >= 2

    # Admin B
    res_b = client.get("/api/admin/stats", headers=headers_admin_b)
    assert res_b.status_code == 200
    stats_b = res_b.json()
    assert stats_b["totalScans"] == stats_a["totalScans"]


def test_12_admin_identity_privacy_between_admins(isolation_environment):
    """Admin A cannot view Admin B's private profile via standard user profile routes."""
    env = isolation_environment
    client = env["client"]
    headers_admin_a = {"Authorization": f"Bearer {env['token_admin_a']}"}

    # Admin A viewing own profile
    res_self = client.get("/api/users/me", headers=headers_admin_a)
    assert res_self.status_code == 200
    assert res_self.json()["username"] == "admin_a_iso"

    # Admin A attempting to access Admin B's private profile via /api/users/{admin_b_id} -> 403 Restricted
    res_other_admin = client.get(f"/api/users/{env['admin_b'].id}", headers=headers_admin_a)
    assert res_other_admin.status_code == 403
    assert "restricted" in res_other_admin.json()["detail"].lower()
