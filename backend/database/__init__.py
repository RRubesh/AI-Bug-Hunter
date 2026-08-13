from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.config import settings

# For SQLite, we need to allow access from multiple threads and prevent lock timeouts
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    connect_args["timeout"] = 30  # 30-second timeout for lock acquisition

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args
)

# Enable WAL (Write-Ahead Logging) mode for SQLite to handle concurrent reads/writes cleanly
if settings.DATABASE_URL.startswith("sqlite"):
    from sqlalchemy import event
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()
        except Exception:
            pass

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# MongoDB Atlas Manager Integration
from backend.database.mongodb import mongo_manager

# Connect to MongoDB Atlas on module import if URL provided
mongo_manager.connect()

def run_sqlite_migrations():
    """Ensure missing columns are dynamically added to SQLite tables if schema evolved."""
    if not settings.DATABASE_URL.startswith("sqlite"):
        return

    import os
    import sqlite3
    db_path = settings.DATABASE_URL.replace("sqlite:///", "")
    if not os.path.exists(db_path):
        return

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # 1. Check columns in vulnerabilities table
        cursor.execute("PRAGMA table_info(vulnerabilities);")
        existing_vuln_cols = {row[1] for row in cursor.fetchall()}
        if existing_vuln_cols:
            if "status" not in existing_vuln_cols:
                cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN status TEXT DEFAULT 'open';")
                print("[Database Auto-Migration]: Added missing 'status' column to 'vulnerabilities' table.")

            if "remediation" not in existing_vuln_cols:
                cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN remediation TEXT;")
                print("[Database Auto-Migration]: Added missing 'remediation' column to 'vulnerabilities' table.")

            if "ai_explanation" not in existing_vuln_cols:
                cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN ai_explanation TEXT;")
                print("[Database Auto-Migration]: Added missing 'ai_explanation' column to 'vulnerabilities' table.")

            if "ai_fix" not in existing_vuln_cols:
                cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN ai_fix TEXT;")
                print("[Database Auto-Migration]: Added missing 'ai_fix' column to 'vulnerabilities' table.")

        # 2. Check columns in scans table
        cursor.execute("PRAGMA table_info(scans);")
        existing_scan_cols = {row[1] for row in cursor.fetchall()}
        if existing_scan_cols:
            if "trigger_type" not in existing_scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN trigger_type TEXT DEFAULT 'manual';")
                print("[Database Auto-Migration]: Added missing 'trigger_type' column to 'scans' table.")

            if "finished_at" not in existing_scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN finished_at DATETIME;")
                print("[Database Auto-Migration]: Added missing 'finished_at' column to 'scans' table.")

        # 3. Check columns in projects table
        cursor.execute("PRAGMA table_info(projects);")
        existing_project_cols = {row[1] for row in cursor.fetchall()}
        if existing_project_cols:
            if "language_detected" not in existing_project_cols:
                cursor.execute("ALTER TABLE projects ADD COLUMN language_detected TEXT;")
                print("[Database Auto-Migration]: Added missing 'language_detected' column to 'projects' table.")

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Database Auto-Migration Notice]: {str(e)}")

# Run SQLite migrations immediately upon database initialization
run_sqlite_migrations()

def get_mongo_db():
    return mongo_manager.db

def is_mongo_connected() -> bool:
    return mongo_manager.is_connected()

def get_db():
    try:
        Base.metadata.create_all(bind=engine)
    except Exception:
        pass
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


