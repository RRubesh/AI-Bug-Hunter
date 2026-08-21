import os
import sys
import datetime
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pymongo import MongoClient
from backend.config import settings
from backend.database import SessionLocal
from backend.models import User, Project, Scan, Vulnerability, ChatMessage

def migrate_to_atlas(target_uri: str = None, target_db_name: str = "aibughunter"):
    """
    Transfers and syncs all collections directly from local MongoDB Compass (localhost:27017/aibughunter)
    and SQLite into MongoDB Atlas.
    """
    if not target_uri:
        target_uri = settings.MONGODB_URL or os.getenv("MONGODB_URI", "")

    print("=" * 70)
    print("      MongoDB Compass ➔ MongoDB Atlas Bridge & Sync Engine")
    print("=" * 70)

    if not target_uri or "XXXXX" in target_uri or "<username>" in target_uri or target_uri.startswith("mongodb://localhost"):
        print("\n[!] Atlas Destination URI not provided in arguments.")
        print("To sync to Atlas, provide your Atlas URI:")
        print("  python backend/migrate_to_atlas.py \"mongodb+srv://rubeshr000_db_user:1KltGvo6Qa1O1kP9@YOUR_CLUSTER.mongodb.net/?retryWrites=true&w=majority\"")
        print("=" * 70)
        return False

    print(f"\n[*] Connecting to destination MongoDB Atlas ({target_db_name})...")
    try:
        atlas_client = MongoClient(target_uri, serverSelectionTimeoutMS=8000)
        atlas_client.admin.command('ping')
        atlas_db = atlas_client[target_db_name]
        print("[✓] Connected successfully to MongoDB Atlas Cloud!")
    except Exception as e:
        print(f"[!] Failed to connect to MongoDB Atlas: {str(e)}")
        return False

    # 1. Read from local MongoDB Compass (localhost:27017 / aibughunter)
    local_mongo_uri = "mongodb://localhost:27017"
    local_db_name = "aibughunter"
    migrated_from_compass = False

    try:
        local_client = MongoClient(local_mongo_uri, serverSelectionTimeoutMS=3000)
        local_client.admin.command('ping')
        local_db = local_client[local_db_name]
        collection_names = local_db.list_collection_names()
        
        if collection_names:
            print(f"\n[*] Found {len(collection_names)} collections in local MongoDB Compass ({local_db_name}):")
            for col_name in collection_names:
                count = local_db[col_name].count_documents({})
                print(f"    - {col_name}: {count} documents")
                if count > 0:
                    docs = list(local_db[col_name].find({}))
                    for doc in docs:
                        atlas_db[col_name].replace_one({"_id": doc["_id"]}, doc, upsert=True)
                    print(f"      [✓] Synced {len(docs)} documents to Atlas collection '{col_name}'.")
            migrated_from_compass = True
    except Exception as e:
        print(f"[*] Note: Local MongoDB Compass sync skipped ({str(e)}). Falling back to SQLite migration...")

    # 2. Read from local SQLite database as fallback or additional sync
    sqlite_session = SessionLocal()
    try:
        print("\n[*] Synchronizing SQLite records...")
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
                "email": getattr(u, "email", None) or f"{u.username}@aibughunter.local",
                "hashed_password": u.hashed_password,
                "role": "admin" if u.role == "admin" else "user",
                "created_at": u.created_at or datetime.datetime.now()
            } for u in users]
            for doc in user_docs:
                atlas_db.users.replace_one({"_id": doc["_id"]}, doc, upsert=True)
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
                atlas_db.projects.replace_one({"_id": doc["_id"]}, doc, upsert=True)
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
                atlas_db.scans.replace_one({"_id": doc["_id"]}, doc, upsert=True)
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
            } for v in vuln_docs]
            for doc in vuln_docs:
                atlas_db.vulnerabilities.replace_one({"_id": doc["_id"]}, doc, upsert=True)
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
                atlas_db.chat_messages.replace_one({"_id": doc["_id"]}, doc, upsert=True)
            print(f"[✓] Migrated {len(msg_docs)} chat messages to Atlas.")

        print("\n" + "=" * 70)
        print(" [SUCCESS] All MongoDB Compass & Local collections synced to MongoDB Atlas!")
        print("=" * 70)
        return True
    finally:
        sqlite_session.close()

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    migrate_to_atlas(target)
