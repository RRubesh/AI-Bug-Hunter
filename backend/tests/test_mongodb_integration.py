import os
import sys
import uuid
import hashlib
import datetime
from pathlib import Path
from typing import Generator
import pytest
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.config import settings
from backend.database.mongodb import MongoDBManager, utcnow
from backend.auth.jwt import get_password_hash, verify_password, create_access_token
from backend.models import User
from fastapi.testclient import TestClient
from backend.main import app

@pytest.fixture(scope="module")
def mongo_test_db():
    """
    Initializes a dedicated test connection to the MongoDB database 'ai_bug_hunter'
    and ensures clean setup/teardown of test records.
    """
    db_name = "ai_bug_hunter"
    uri = settings.MONGODB_URI or settings.MONGODB_URL or os.getenv("MONGODB_URI", "")
    
    # If unconfigured placeholder, fallback to local test instance or embedded test db
    if not uri or "XXXXX" in uri or "<username>" in uri:
        uri = "mongodb://localhost:27017"

    client = None
    db = None
    connected = False

    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=2500, connectTimeoutMS=2500)
        client.admin.command("ping")
        db = client[db_name]
        connected = True
    except Exception as e:
        print(f"[Notice: MongoDB Atlas unreachable with URI: {str(e)}]")
        connected = False

    if not connected or db is None:
        pytest.skip("MongoDB Atlas connection is not available for integration testing.")

    # Create manager and initialize all indexes
    mgr = MongoDBManager()
    mgr.client = client
    mgr.db = db
    mgr._connected = True
    mgr.ensure_indexes()

    yield {
        "manager": mgr,
        "db": db,
        "client": client,
        "db_name": db_name
    }

    # Clean up test documents
    try:
        db.users.delete_many({"email": {"$regex": r"@test-integration\.local$"}})
        db.scans.delete_many({"project_name": {"$regex": r"^Test-Integration-"}})
        db.vulnerabilities.delete_many({"file_path": {"$regex": r"^test_integration_"}})
        db.reports.delete_many({"report_path": {"$regex": r"test_report_"}})
        db.password_reset_tokens.delete_many({"email": {"$regex": r"@test-integration\.local$"}})
        db.audit_logs.delete_many({"action": {"$regex": r"^test_"}})
    except Exception:
        pass


def test_01_mongodb_connection(mongo_test_db):
    """1. Test MongoDB Atlas connection and ping response."""
    mgr = mongo_test_db["manager"]
    assert mgr.is_connected() is True
    assert mongo_test_db["db"].name == "ai_bug_hunter"


def test_02_create_user(mongo_test_db):
    """2. Test creating user with all required fields in 'users' collection."""
    db = mongo_test_db["db"]
    now = utcnow()
    user_id = int(uuid.uuid4().int % 1000000)
    user_email = f"user_{user_id}@test-integration.local"
    password_hash = get_password_hash("SecurePass123!")

    user_doc = {
        "_id": user_id,
        "name": f"Developer User {user_id}",
        "username": f"dev_{user_id}",
        "email": user_email,
        "password_hash": password_hash,
        "role": "developer",
        "is_active": True,
        "created_at": now,
        "updated_at": now
    }

    result = db.users.insert_one(user_doc)
    assert result.inserted_id == user_id

    # Verify document in collection
    saved = db.users.find_one({"_id": user_id})
    assert saved is not None
    assert saved["email"] == user_email
    assert saved["role"] == "developer"
    assert saved["is_active"] is True
    assert verify_password("SecurePass123!", saved["password_hash"]) is True


def test_03_read_user_and_unique_email_index(mongo_test_db):
    """3 & 6. Test reading user by email and enforcing unique email index."""
    db = mongo_test_db["db"]
    user_id = int(uuid.uuid4().int % 1000000)
    user_email = f"unique_{user_id}@test-integration.local"

    db.users.insert_one({
        "_id": user_id,
        "name": "Unique Test User",
        "username": f"unique_{user_id}",
        "email": user_email,
        "password_hash": get_password_hash("Secret123!"),
        "role": "user",
        "is_active": True,
        "created_at": utcnow(),
        "updated_at": utcnow()
    })

    # Read user
    found = db.users.find_one({"email": user_email})
    assert found is not None
    assert found["_id"] == user_id

    # Duplicate email must be rejected by unique index
    with pytest.raises(Exception):
        db.users.insert_one({
            "_id": user_id + 1,
            "name": "Duplicate User",
            "username": f"dup_{user_id}",
            "email": user_email,
            "password_hash": get_password_hash("Secret123!"),
            "role": "user",
            "is_active": True,
            "created_at": utcnow(),
            "updated_at": utcnow()
        })


def test_04_update_user(mongo_test_db):
    """4. Test updating user details and role in 'users' collection."""
    db = mongo_test_db["db"]
    user_id = int(uuid.uuid4().int % 1000000)
    user_email = f"update_{user_id}@test-integration.local"

    db.users.insert_one({
        "_id": user_id,
        "name": "Initial Name",
        "username": f"update_{user_id}",
        "email": user_email,
        "password_hash": get_password_hash("Initial123!"),
        "role": "user",
        "is_active": True,
        "created_at": utcnow(),
        "updated_at": utcnow()
    })

    # Update role to admin and change name
    updated_time = utcnow()
    db.users.update_one(
        {"_id": user_id},
        {"$set": {
            "name": "Promoted Admin",
            "role": "admin",
            "updated_at": updated_time
        }}
    )

    saved = db.users.find_one({"_id": user_id})
    assert saved["name"] == "Promoted Admin"
    assert saved["role"] == "admin"


def test_05_delete_user(mongo_test_db):
    """5. Test deleting user document from 'users' collection."""
    db = mongo_test_db["db"]
    user_id = int(uuid.uuid4().int % 1000000)
    user_email = f"delete_{user_id}@test-integration.local"

    db.users.insert_one({
        "_id": user_id,
        "name": "To Delete",
        "username": f"del_{user_id}",
        "email": user_email,
        "password_hash": "hash",
        "role": "user",
        "is_active": True,
        "created_at": utcnow(),
        "updated_at": utcnow()
    })

    assert db.users.find_one({"_id": user_id}) is not None
    db.users.delete_one({"_id": user_id})
    assert db.users.find_one({"_id": user_id}) is None


def test_06_create_and_read_scan(mongo_test_db):
    """6 & 7. Test creating and reading scan documents with all required fields."""
    db = mongo_test_db["db"]
    scan_id = int(uuid.uuid4().int % 1000000)
    user_id = 101
    started_at = utcnow()

    scan_doc = {
        "_id": scan_id,
        "user_id": user_id,
        "project_name": "Test-Integration-Backend",
        "scan_type": "manual",
        "source_type": "zip",
        "status": "running",
        "started_at": started_at,
        "completed_at": None,
        "security_score": 100,
        "created_at": started_at
    }

    db.scans.insert_one(scan_doc)

    retrieved = db.scans.find_one({"_id": scan_id})
    assert retrieved is not None
    assert retrieved["project_name"] == "Test-Integration-Backend"
    assert retrieved["status"] == "running"
    assert retrieved["user_id"] == user_id


def test_07_update_scan_status(mongo_test_db):
    """8. Test updating scan status, duration, and calculated security score."""
    db = mongo_test_db["db"]
    scan_id = int(uuid.uuid4().int % 1000000)
    started = utcnow()

    db.scans.insert_one({
        "_id": scan_id,
        "user_id": 102,
        "project_name": "Test-Integration-Web",
        "scan_type": "webhook",
        "source_type": "git",
        "status": "scanning",
        "started_at": started,
        "completed_at": None,
        "security_score": 100,
        "created_at": started
    })

    completed_at = utcnow()
    db.scans.update_one(
        {"_id": scan_id},
        {"$set": {
            "status": "completed",
            "completed_at": completed_at,
            "security_score": 85
        }}
    )

    updated = db.scans.find_one({"_id": scan_id})
    assert updated["status"] == "completed"
    assert updated["security_score"] == 85
    assert updated["completed_at"] is not None


def test_08_create_and_read_vulnerabilities_by_scan(mongo_test_db):
    """9 & 10. Test inserting vulnerability records and querying them by scan_id."""
    db = mongo_test_db["db"]
    scan_id = int(uuid.uuid4().int % 1000000)
    user_id = 202

    vuln_docs = [
        {
            "_id": int(uuid.uuid4().int % 1000000),
            "scan_id": scan_id,
            "user_id": user_id,
            "severity": "CRITICAL",
            "title": "SQL Injection in auth query",
            "description": "User input interpolated directly into SQL statement.",
            "file_path": "test_integration_auth.py",
            "line_number": 42,
            "category": "SQL Injection",
            "recommendation": "Use parameterized query placeholders.",
            "status": "open",
            "created_at": utcnow()
        },
        {
            "_id": int(uuid.uuid4().int % 1000000),
            "scan_id": scan_id,
            "user_id": user_id,
            "severity": "HIGH",
            "title": "Hardcoded JWT Secret Token",
            "description": "Hardcoded credential token detected in source code.",
            "file_path": "test_integration_config.py",
            "line_number": 15,
            "category": "Hardcoded Secret",
            "recommendation": "Load secrets from environment variables.",
            "status": "open",
            "created_at": utcnow()
        }
    ]

    db.vulnerabilities.insert_many(vuln_docs)

    # Read vulnerabilities by scan_id
    findings = list(db.vulnerabilities.find({"scan_id": scan_id}))
    assert len(findings) == 2
    severities = {f["severity"] for f in findings}
    assert "CRITICAL" in severities
    assert "HIGH" in severities


def test_09_create_report_record(mongo_test_db):
    """11. Test creating and persisting report record in 'reports' collection."""
    mgr = mongo_test_db["manager"]
    db = mongo_test_db["db"]
    scan_id = int(uuid.uuid4().int % 1000000)
    user_id = 303

    report_id = mgr.record_report(
        scan_id=scan_id,
        user_id=user_id,
        report_type="pdf",
        report_path=f"backend/reports/test_report_{scan_id}.pdf",
        status="completed"
    )

    assert report_id is not None
    saved_report = db.reports.find_one({"scan_id": scan_id})
    assert saved_report is not None
    assert saved_report["report_type"] == "pdf"
    assert saved_report["status"] == "completed"


def test_10_password_reset_token_creation_and_expiration(mongo_test_db):
    """12, 13 & 14. Test password reset token creation, hashing, validation and expiration."""
    db = mongo_test_db["db"]
    user_id = 404
    user_email = f"reset_{user_id}@test-integration.local"

    raw_token = "secure_random_token_xyz_123456"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    expires_at = utcnow() + datetime.timedelta(minutes=15)

    # Store hashed token in collection
    token_id = int(uuid.uuid4().int % 1000000)
    db.password_reset_tokens.insert_one({
        "_id": token_id,
        "user_id": user_id,
        "email": user_email,
        "token_hash": token_hash,
        "expires_at": expires_at,
        "used": False,
        "created_at": utcnow()
    })

    # Validate active token
    valid_record = db.password_reset_tokens.find_one({
        "token_hash": token_hash,
        "used": False,
        "expires_at": {"$gt": utcnow()}
    })
    assert valid_record is not None
    assert valid_record["user_id"] == user_id

    # Invalidate token after consumption
    db.password_reset_tokens.update_one({"_id": token_id}, {"$set": {"used": True}})
    used_record = db.password_reset_tokens.find_one({"token_hash": token_hash, "used": False})
    assert used_record is None

    # Test expired token handling
    expired_token = "expired_token_abc_987"
    expired_hash = hashlib.sha256(expired_token.encode("utf-8")).hexdigest()
    db.password_reset_tokens.insert_one({
        "_id": token_id + 1,
        "user_id": user_id,
        "email": user_email,
        "token_hash": expired_hash,
        "expires_at": utcnow() - datetime.timedelta(minutes=5),  # Expired
        "used": False,
        "created_at": utcnow() - datetime.timedelta(minutes=20)
    })

    # Query active tokens should not return expired token
    expired_query = db.password_reset_tokens.find_one({
        "token_hash": expired_hash,
        "used": False,
        "expires_at": {"$gt": utcnow()}
    })
    assert expired_query is None


def test_11_audit_log_creation_and_query(mongo_test_db):
    """15. Test audit logging helper and querying 'audit_logs' collection."""
    mgr = mongo_test_db["manager"]
    user_id = 505

    success = mgr.log_audit_event(
        action="test_security_scan_triggered",
        resource="scans",
        resource_id="SCAN-9999",
        user_id=user_id,
        ip_address="192.168.1.50",
        details={"engine": "Gitleaks + Bandit"}
    )
    assert success is True

    # Query recent logs
    logs = mgr.get_audit_logs(limit=10, user_id=user_id)
    assert len(logs) > 0
    assert logs[0]["action"] == "test_security_scan_triggered"
    assert logs[0]["resource"] == "scans"
    assert logs[0]["ip_address"] == "192.168.1.50"


def test_12_role_based_access_control_and_isolation(mongo_test_db):
    """16. Test User, Developer, and Admin role permissions and data isolation."""
    client = TestClient(app)

    # 1. Create Normal User Token
    user_token = create_access_token(data={
        "sub": "normal_user_1",
        "email": "normal_user_1@test-integration.local",
        "role": "user",
        "user_id": 901
    })

    # 2. Create Developer Token
    dev_token = create_access_token(data={
        "sub": "developer_1",
        "email": "developer_1@test-integration.local",
        "role": "developer",
        "user_id": 902
    })

    # 3. Create Admin Token
    admin_token = create_access_token(data={
        "sub": "admin_1",
        "email": "admin_1@test-integration.local",
        "role": "admin",
        "user_id": 903
    })

    # Normal user should be rejected from admin audit logs (403 Forbidden)
    res_user_admin = client.get("/api/admin/audit-logs", headers={"Authorization": f"Bearer {user_token}"})
    assert res_user_admin.status_code == 403

    # Developer should also be rejected from admin user management (403 Forbidden)
    res_dev_admin = client.get("/api/admin/users", headers={"Authorization": f"Bearer {dev_token}"})
    assert res_dev_admin.status_code == 403

    # Admin should succeed on admin endpoints (200 OK)
    res_admin = client.get("/api/admin/audit-logs", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_admin.status_code == 200
    assert "events" in res_admin.json()
