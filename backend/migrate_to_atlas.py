import os
import sys
import datetime
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pymongo import MongoClient, ASCENDING, DESCENDING
from backend.config import settings
from backend.database import SessionLocal
from backend.models import User, Project, Scan, Vulnerability, ChatMessage

def migrate_to_atlas(target_uri: str = None, target_db_name: str = "ai_bug_hunter"):
    """
    Migrates all Users, Projects, Scans, Vulnerabilities, and Chat Messages
    from local SQLite/MongoDB to MongoDB Atlas.
    """
    if not target_uri:
        target_uri = settings.MONGODB_URL or os.getenv("MONGODB_URI", "")

    print("=" * 65)
    print("      Data Transfer & Migration Engine ➔ MongoDB Atlas")
    print("=" * 65)

    if not target_uri or "XXXXX" in target_uri or "<username>" in target_uri:
        print("\n[!] Error: Invalid MongoDB Atlas URI.")
        print("Please provide a valid connection string:")
        print("  python backend/migrate_to_atlas.py \"mongodb+srv://user:pass@cluster0.abcde.mongodb.net/?retryWrites=true&w=majority\"")
        print("=" * 65)
        return False

    print(f"\n[*] Connecting to MongoDB Atlas ({target_db_name})...")
    try:
        client = MongoClient(target_uri, serverSelectionTimeoutMS=8000)
        client.admin.command('ping')
        db = client[target_db_name]
        print("[✓] Connected successfully to MongoDB Atlas!")
    except Exception as e:
        print(f"[!] Failed to connect to MongoDB Atlas: {str(e)}")
        return False

    # Read from local SQLite database
    sqlite_session = SessionLocal()
    try:
        print("\n[*] Exporting local records from SQLite...")
        users = sqlite_session.query(User).all()
        projects = sqlite_session.query(Project).all()
        scans = sqlite_session.query(Scan).all()
        vulns = sqlite_session.query(Vulnerability).all()
        chat_msgs = sqlite_session.query(ChatMessage).all()

        print(f"    - Users: {len(users)}")
        print(f"    - Projects: {len(projects)}")
        print(f"    - Scans: {len(scans)}")
        print(f"    - Vulnerabilities: {len(vulns)}")
        print(f"    - Chat Messages: {len(chat_msgs)}")

        print("\n[*] Transferring records into MongoDB Atlas...")

        # 1. Users
        if users:
            user_docs = [{
                "_id": u.id,
                "id": u.id,
                "username": u.username,
                "hashed_password": u.hashed_password,
                "role": u.role or "developer",
                "created_at": u.created_at or datetime.datetime.now()
            } for u in users]
            for doc in user_docs:
                db.users.replace_one({"_id": doc["_id"]}, doc, upsert=True)
            print(f"[✓] Migrated {len(user_docs)} users to Atlas.")

        # 2. Projects
        if projects:
            proj_docs = [{
                "_id": p.id,
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "file_path": p.file_path,
                "upload_type": p.upload_type,
                "language_detected": p.language_detected,
                "owner_id": p.owner_id,
                "created_at": p.created_at or datetime.datetime.now(),
                "updated_at": p.updated_at or datetime.datetime.now()
            } for p in projects]
            for doc in proj_docs:
                db.projects.replace_one({"_id": doc["_id"]}, doc, upsert=True)
            print(f"[✓] Migrated {len(proj_docs)} projects to Atlas.")

        # 3. Scans
        if scans:
            scan_docs = [{
                "_id": s.id,
                "id": s.id,
                "project_id": s.project_id,
                "status": s.status,
                "progress": s.progress,
                "trigger_type": s.trigger_type or "manual",
                "total_vulnerabilities": s.total_vulnerabilities,
                "critical_count": s.critical_count,
                "high_count": s.high_count,
                "medium_count": s.medium_count,
                "low_count": s.low_count,
                "created_at": s.created_at or datetime.datetime.now(),
                "finished_at": s.finished_at
            } for s in scans]
            for doc in scan_docs:
                db.scans.replace_one({"_id": doc["_id"]}, doc, upsert=True)
            print(f"[✓] Migrated {len(scan_docs)} scans to Atlas.")

        # 4. Vulnerabilities
        if vulns:
            vuln_docs = [{
                "_id": v.id,
                "id": v.id,
                "scan_id": v.scan_id,
                "file_path": v.file_path,
                "line_number": v.line_number,
                "code_snippet": v.code_snippet,
                "severity": v.severity,
                "category": v.category,
                "message": v.message,
                "tool_name": v.tool_name,
                "remediation": v.remediation,
                "ai_explanation": v.ai_explanation,
                "ai_fix": v.ai_fix,
                "status": v.status or "open",
                "created_at": v.created_at or datetime.datetime.now()
            } for v in vulns]
            for doc in vuln_docs:
                db.vulnerabilities.replace_one({"_id": doc["_id"]}, doc, upsert=True)
            print(f"[✓] Migrated {len(vuln_docs)} vulnerabilities to Atlas.")

        # 5. Chat Messages
        if chat_msgs:
            msg_docs = [{
                "_id": m.id,
                "id": m.id,
                "scan_id": m.scan_id,
                "user_id": m.user_id,
                "message": m.message,
                "is_ai": m.is_ai,
                "created_at": m.created_at or datetime.datetime.now()
            } for m in chat_msgs]
            for doc in msg_docs:
                db.chat_messages.replace_one({"_id": doc["_id"]}, doc, upsert=True)
            print(f"[✓] Migrated {len(msg_docs)} chat messages to Atlas.")

        print("\n" + "=" * 65)
        print(" [SUCCESS] All application data successfully transferred to MongoDB Atlas!")
        print("=" * 65)
        return True
    finally:
        sqlite_session.close()

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    migrate_to_atlas(target)
