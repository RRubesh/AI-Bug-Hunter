import os
import re
import datetime
from typing import Optional, Dict, Any, List, Union
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError
from backend.config import settings

def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

def mask_uri(uri: str) -> str:
    """Mask credentials in MongoDB connection string for secure logging."""
    if not uri:
        return ""
    if "@" in uri:
        try:
            prefix, rest = uri.split("@", 1)
            if "://" in prefix:
                scheme, auth = prefix.split("://", 1)
                if ":" in auth:
                    user, _ = auth.split(":", 1)
                    return f"{scheme}://{user}:****@{rest}"
            return f"****@{rest}"
        except Exception:
            return "mongodb+srv://****:****@masked"
    return uri

class MongoDBManager:
    """
    Production-ready MongoDB Atlas database manager for AI Bug Hunter.
    Handles connection lifecycle, indexes, collection schema compliance,
    audit logging, and data operations across all 6 core collections:
      1. users
      2. scans
      3. vulnerabilities
      4. reports
      5. password_reset_tokens
      6. audit_logs
    """
    def __init__(self):
        self.client: Optional[MongoClient] = None
        self.db = None
        self._connected = False

    def get_uri(self) -> str:
        return settings.MONGODB_URI or settings.MONGODB_URL or os.getenv("MONGODB_URI", "")

    def get_db_name(self) -> str:
        return settings.MONGODB_DATABASE or settings.MONGODB_DB_NAME or os.getenv("MONGODB_DATABASE", "ai_bug_hunter")

    def connect(self, custom_uri: Optional[str] = None, custom_db_name: Optional[str] = None) -> bool:
        """
        Initializes reusable MongoDB client with connection pooling, timeouts,
        index initialization, and sanitized error reporting.
        """
        uri = custom_uri or self.get_uri()
        db_name = custom_db_name or self.get_db_name()

        if not uri or "<username>" in uri or "<password>" in uri or "XXXXX" in uri or "example.mongodb.net" in uri:
            self._connected = False
            return False

        try:
            # Reusable client with connection pooling and timeouts
            self.client = MongoClient(
                uri,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
                socketTimeoutMS=10000,
                maxPoolSize=50,
                minPoolSize=5,
                retryWrites=True
            )
            self.db = self.client[db_name]
            
            # Verify connectivity with ping command
            self.client.admin.command('ping')
            self._connected = True
            
            # Initialize collection indexes
            self.ensure_indexes()
            print(f"[MongoDB Atlas]: Connected successfully to database '{db_name}' ({mask_uri(uri)}).")
            return True
        except (PyMongoError, ServerSelectionTimeoutError, Exception) as e:
            self._connected = False
            # Safely log error without leaking credentials
            print(f"[MongoDB Atlas Warning]: Connection failed: {type(e).__name__} - {str(e)}")
            return False

    def is_connected(self) -> bool:
        """Check if active connection to MongoDB Atlas exists."""
        if not self._connected or self.client is None or self.db is None:
            return False
        try:
            self.client.admin.command('ping')
            return True
        except Exception:
            self._connected = False
            return False

    def disconnect(self):
        """Gracefully close MongoDB client connection."""
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None
            self.db = None
            self._connected = False
            print("[MongoDB Atlas]: Connection closed cleanly.")

    def ensure_indexes(self):
        """
        Create all required indexes across all 6 core collections:
          1. users.email unique index & users.username unique index
          2. scans.user_id index & scans.created_at index
          3. vulnerabilities.scan_id index & vulnerabilities.user_id index
          4. reports.scan_id index & reports.user_id index
          5. password_reset_tokens.token_hash index & password_reset_tokens.expires_at index
          6. audit_logs.user_id index & audit_logs.created_at index
        """
        if self.db is None:
            return

        try:
            # 1. users collection indexes
            self.db.users.create_index([("email", ASCENDING)], unique=True, sparse=True)
            self.db.users.create_index([("username", ASCENDING)], unique=True, sparse=True)
            self.db.users.create_index([("role", ASCENDING)])

            # 2. scans collection indexes
            self.db.scans.create_index([("user_id", ASCENDING)])
            self.db.scans.create_index([("created_at", DESCENDING)])
            self.db.scans.create_index([("status", ASCENDING)])
            self.db.scans.create_index([("project_name", ASCENDING)])

            # 3. vulnerabilities collection indexes
            self.db.vulnerabilities.create_index([("scan_id", ASCENDING)])
            self.db.vulnerabilities.create_index([("user_id", ASCENDING)])
            self.db.vulnerabilities.create_index([("severity", ASCENDING)])
            self.db.vulnerabilities.create_index([("status", ASCENDING)])

            # 4. reports collection indexes
            self.db.reports.create_index([("scan_id", ASCENDING)])
            self.db.reports.create_index([("user_id", ASCENDING)])
            self.db.reports.create_index([("created_at", DESCENDING)])

            # 5. password_reset_tokens collection indexes
            self.db.password_reset_tokens.create_index([("token_hash", ASCENDING)])
            self.db.password_reset_tokens.create_index([("expires_at", ASCENDING)])
            self.db.password_reset_tokens.create_index([("user_id", ASCENDING)])

            # 6. audit_logs collection indexes
            self.db.audit_logs.create_index([("user_id", ASCENDING)])
            self.db.audit_logs.create_index([("created_at", DESCENDING)])
            self.db.audit_logs.create_index([("action", ASCENDING)])
            self.db.audit_logs.create_index([("resource", ASCENDING)])

            print("[MongoDB Atlas]: All 6 collection indexes initialized successfully.")
        except Exception as e:
            print(f"[MongoDB Atlas Warning]: Index initialization notice: {str(e)}")

    def log_audit_event(
        self,
        action: str,
        resource: str,
        resource_id: Optional[Union[str, int]] = None,
        user_id: Optional[Union[str, int]] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Record security & administrative audit log entry to 'audit_logs' collection.
        Fields: _id, user_id, action, resource, resource_id, ip_address, created_at
        """
        if not self.is_connected() or self.db is None:
            return False
        try:
            doc = {
                "user_id": user_id,
                "action": action,
                "resource": resource,
                "resource_id": str(resource_id) if resource_id is not None else None,
                "ip_address": ip_address or "unknown",
                "details": details or {},
                "created_at": utcnow()
            }
            self.db.audit_logs.insert_one(doc)
            return True
        except Exception as e:
            print(f"[MongoDB Audit Log Notice]: Failed to write audit event: {str(e)}")
            return False

    def get_audit_logs(
        self,
        limit: int = 50,
        user_id: Optional[Union[str, int]] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve recent sanitized audit logs from 'audit_logs' collection."""
        if not self.is_connected() or self.db is None:
            return []
        try:
            query = {}
            if user_id is not None:
                query["user_id"] = user_id
            cursor = self.db.audit_logs.find(query, {"_id": 0}).sort("created_at", DESCENDING).limit(limit)
            logs = list(cursor)
            # Serialize datetimes for JSON responses
            for log in logs:
                if isinstance(log.get("created_at"), datetime.datetime):
                    log["created_at"] = log["created_at"].isoformat()
            return logs
        except Exception as e:
            print(f"[MongoDB Audit Log Retrieval Notice]: {str(e)}")
            return []

    def record_report(
        self,
        scan_id: Union[str, int],
        user_id: Union[str, int],
        report_type: str,
        report_path: str,
        status: str = "completed"
    ) -> Optional[Any]:
        """
        Persist a generated report record to 'reports' collection.
        Fields: _id, scan_id, user_id, report_type, report_path, status, created_at
        """
        if not self.is_connected() or self.db is None:
            return None
        try:
            doc = {
                "scan_id": scan_id,
                "user_id": user_id,
                "report_type": report_type,
                "report_path": report_path,
                "status": status,
                "created_at": utcnow()
            }
            res = self.db.reports.insert_one(doc)
            return res.inserted_id
        except Exception as e:
            print(f"[MongoDB Reports Notice]: Failed to record report: {str(e)}")
            return None

    # Backward compatibility alias
    def log_security_event(self, event_type: str, description: str, user_id: Optional[int] = None, ip_address: Optional[str] = None, user_agent: Optional[str] = None):
        return self.log_audit_event(
            action=event_type,
            resource="system",
            resource_id=None,
            user_id=user_id,
            ip_address=ip_address,
            details={"description": description, "user_agent": user_agent}
        )

    def get_security_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.get_audit_logs(limit=limit)

    def sync_system_settings(self, settings_dict: Dict[str, Any]):
        """Persist platform settings snapshot to MongoDB Atlas."""
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
