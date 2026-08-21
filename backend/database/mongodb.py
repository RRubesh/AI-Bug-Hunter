import os
import datetime
from typing import Optional, Dict, Any, List
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import PyMongoError
from backend.config import settings

def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

class MongoDBManager:
    """
    Production-ready MongoDB Atlas database manager for AI Bug Hunter.
    Handles connection lifecycle, indexes, collection access, and security event logging.
    """
    def __init__(self):
        self.client: Optional[MongoClient] = None
        self.db = None
        self._connected = False

    def get_uri(self) -> str:
        return settings.MONGODB_URL or os.getenv("MONGODB_URI", "")

    def get_db_name(self) -> str:
        return settings.MONGODB_DB_NAME or os.getenv("MONGODB_DATABASE", "ai_bug_hunter")

    def connect(self) -> bool:
        uri = self.get_uri()
        if not uri or "<username>" in uri or "<password>" in uri or "XXXXX" in uri or "example.mongodb.net" in uri:
            self._connected = False
            return False

        try:
            self.client = MongoClient(
                uri,
                serverSelectionTimeoutMS=5000,
                maxPoolSize=50,
                minPoolSize=5,
                retryWrites=True
            )
            db_name = self.get_db_name()
            self.db = self.client[db_name]
            # Verify connectivity
            self.client.admin.command('ping')
            self._connected = True
            self.ensure_indexes()
            print(f"[MongoDB Atlas]: Connected successfully to database '{db_name}'.")
            return True
        except Exception as e:
            self._connected = False
            print(f"[MongoDB Atlas Warning]: Connection failed: {str(e)}")
            return False

    def is_connected(self) -> bool:
        if not self._connected or self.client is None:
            return False
        try:
            self.client.admin.command('ping')
            return True
        except Exception:
            self._connected = False
            return False

    def disconnect(self):
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None
            self.db = None
            self._connected = False
            print("[MongoDB Atlas]: Connection closed.")

    def ensure_indexes(self):
        """Build required indexes for all 9 collections."""
        if self.db is None:
            return

        try:
            # 1. users: unique indexes on username and email
            self.db.users.create_index([("username", ASCENDING)], unique=True)
            self.db.users.create_index([("email", ASCENDING)], sparse=True)

            # 2. projects: index on user_id
            self.db.projects.create_index([("user_id", ASCENDING)])
            self.db.projects.create_index([("created_at", DESCENDING)])

            # 3. scans: indexes on project_id, user_id, status, started_at
            self.db.scans.create_index([("project_id", ASCENDING)])
            self.db.scans.create_index([("user_id", ASCENDING)])
            self.db.scans.create_index([("status", ASCENDING)])
            self.db.scans.create_index([("started_at", DESCENDING)])

            # 4. vulnerabilities: indexes on scan_id, project_id, severity, status
            self.db.vulnerabilities.create_index([("scan_id", ASCENDING)])
            self.db.vulnerabilities.create_index([("project_id", ASCENDING)])
            self.db.vulnerabilities.create_index([("severity", ASCENDING)])
            self.db.vulnerabilities.create_index([("status", ASCENDING)])

            # 5. dependencies: index on scan_id
            self.db.dependencies.create_index([("scan_id", ASCENDING)])
            self.db.dependencies.create_index([("project_id", ASCENDING)])

            # 6. scanner_results: index on scan_id, scanner
            self.db.scanner_results.create_index([("scan_id", ASCENDING)])
            self.db.scanner_results.create_index([("scanner", ASCENDING)])

            # 7. ai_analysis: index on scan_id, vulnerability_id
            self.db.ai_analysis.create_index([("scan_id", ASCENDING)])
            self.db.ai_analysis.create_index([("vulnerability_id", ASCENDING)])

            # 8. reports: index on scan_id, user_id
            self.db.reports.create_index([("scan_id", ASCENDING)])
            self.db.reports.create_index([("user_id", ASCENDING)])

            # 9. security_events: index on user_id, event_type, created_at
            self.db.security_events.create_index([("user_id", ASCENDING)])
            self.db.security_events.create_index([("event_type", ASCENDING)])
            self.db.security_events.create_index([("created_at", DESCENDING)])

            # 10. system_settings: index on updated_at
            self.db.system_settings.create_index([("updated_at", DESCENDING)])

            # 11. password_reset_tokens: index on token_hash, expires_at
            self.db.password_reset_tokens.create_index([("token_hash", ASCENDING)])
            self.db.password_reset_tokens.create_index([("expires_at", ASCENDING)])

            # Migrate legacy roles (developer, paid) to user
            self.db.users.update_many(
                {"role": {"$in": ["developer", "paid", "free"]}},
                {"$set": {"role": "user"}}
            )

            print("[MongoDB Atlas]: Collection indexes initialized and legacy roles migrated.")
        except Exception as e:
            print(f"[MongoDB Atlas Warning]: Index initialization failed: {str(e)}")

    def log_security_event(self, event_type: str, description: str, user_id: Optional[int] = None, ip_address: Optional[str] = None, user_agent: Optional[str] = None):
        """Audit logging helper for platform security events."""
        if not self.is_connected() or self.db is None:
            return
        try:
            event_doc = {
                "user_id": user_id,
                "event_type": event_type,
                "description": description,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "created_at": utcnow()
            }
            self.db.security_events.insert_one(event_doc)
        except Exception as e:
            print(f"[MongoDB Security Event Notice]: {str(e)}")

    def get_security_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve sanitized security audit logs for administrators."""
        if not self.is_connected() or self.db is None:
            return []
        try:
            cursor = self.db.security_events.find({}, {"_id": 0}).sort("created_at", DESCENDING).limit(limit)
            return list(cursor)
        except Exception as e:
            print(f"[MongoDB Audit Log Retrieval Notice]: {str(e)}")
            return []

    def sync_system_settings(self, settings_dict: Dict[str, Any]):
        """Persist platform and AI settings snapshot to MongoDB Atlas system_settings collection."""
        if not self.is_connected() or self.db is None:
            return
        try:
            doc = {
                "config_key": "global_settings",
                "settings": settings_dict,
                "updated_at": utcnow()
            }
            self.db.system_settings.update_one(
                {"config_key": "global_settings"},
                {"$set": doc},
                upsert=True
            )
        except Exception as e:
            print(f"[MongoDB System Settings Notice]: {str(e)}")

# Singleton instance
mongo_manager = MongoDBManager()
