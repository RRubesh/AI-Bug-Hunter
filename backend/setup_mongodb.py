import os
import sys
import argparse
from pathlib import Path

# Ensure backend modules can be imported
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import PyMongoError

def setup_mongodb(uri: str = None, db_name: str = "ai_bug_hunter", update_env: bool = False):
    """
    Connects to MongoDB Atlas, verifies connectivity, creates all 9 application
    collections, sets up database indexes, and tests read/write capability.
    """
    env_path = Path(__file__).resolve().parent.parent / ".env"
    
    # 1. Resolve URI from argument or .env file
    if not uri:
        if env_path.exists():
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("MONGODB_URI=") or line.startswith("MONGODB_URL="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if val and "XXXXX" not in val and "<username>" not in val:
                            uri = val
                            break
    
    print("=" * 65)
    print("      MongoDB Atlas Database Setup & Verification - AI Bug Hunter")
    print("=" * 65)

    if not uri or "XXXXX" in uri or "<username>" in uri or "<password>" in uri:
        print("\n[!] Error: Valid MongoDB Atlas URI not detected.")
        print("\nPlease replace the placeholders in your .env file or run this script with your URI:")
        print("  python backend/setup_mongodb.py --uri \"mongodb+srv://<username>:<password>@cluster0.abcde.mongodb.net/?retryWrites=true&w=majority\"")
        print("\nHow to set up MongoDB Atlas:")
        print(" 1. Log in to https://cloud.mongodb.com/")
        print(" 2. Create a Free Cluster (M0 Sandbox) or select your existing cluster.")
        print(" 3. Go to 'Database Access' -> Add a database user with Read/Write privileges.")
        print(" 4. Go to 'Network Access' -> Add IP Address (0.0.0.0/0 for development access).")
        print(" 5. Click 'Database' -> 'Connect' -> 'Drivers' and copy the connection string.")
        print(" 6. Replace <password> and <username> in the connection string.")
        print("=" * 65)
        return False

    # Mask password for secure console display
    masked_uri = uri
    if "@" in uri:
        prefix, rest = uri.split("@", 1)
        if ":" in prefix:
            user_part, _ = prefix.rsplit(":", 1)
            masked_uri = f"{user_part}:****@{rest}"

    print(f"\n[*] Target URI     : {masked_uri}")
    print(f"[*] Target Database: {db_name}")
    print("[*] Connecting to MongoDB Atlas...")

    try:
        client = MongoClient(
            uri,
            serverSelectionTimeoutMS=8000,
            maxPoolSize=50,
            minPoolSize=5,
            retryWrites=True
        )

        # Test server ping
        ping_response = client.admin.command('ping')
        print(f"[✓] Ping response  : {ping_response}")

        db = client[db_name]

        print("\n[*] Initializing collections & database indexes...")
        collections_created = 0

        # Collection & Index definitions
        index_specs = {
            "users": [
                ([("username", ASCENDING)], {"unique": True}),
                ([("email", ASCENDING)], {})
            ],
            "projects": [
                ([("user_id", ASCENDING)], {}),
                ([("created_at", DESCENDING)], {})
            ],
            "scans": [
                ([("project_id", ASCENDING)], {}),
                ([("user_id", ASCENDING)], {}),
                ([("status", ASCENDING)], {}),
                ([("started_at", DESCENDING)], {})
            ],
            "vulnerabilities": [
                ([("scan_id", ASCENDING)], {}),
                ([("project_id", ASCENDING)], {}),
                ([("severity", ASCENDING)], {}),
                ([("status", ASCENDING)], {})
            ],
            "dependencies": [
                ([("scan_id", ASCENDING)], {}),
                ([("project_id", ASCENDING)], {})
            ],
            "scanner_results": [
                ([("scan_id", ASCENDING)], {}),
                ([("scanner", ASCENDING)], {})
            ],
            "ai_analysis": [
                ([("scan_id", ASCENDING)], {}),
                ([("vulnerability_id", ASCENDING)], {})
            ],
            "reports": [
                ([("scan_id", ASCENDING)], {}),
                ([("user_id", ASCENDING)], {})
            ],
            "security_events": [
                ([("user_id", ASCENDING)], {}),
                ([("event_type", ASCENDING)], {}),
                ([("created_at", DESCENDING)], {})
            ]
        }

        for coll_name, specs in index_specs.items():
            coll = db[coll_name]
            for keys, kwargs in specs:
                coll.create_index(keys, **kwargs)
            collections_created += 1
            print(f"  [✓] Collection '{coll_name}' - indexes applied.")

        print(f"\n[✓] Successfully configured {collections_created} collections with indexes!")

        # Perform test write/read operation
        health_coll = db["_healthcheck"]
        test_doc = {"status": "ok", "service": "AI Bug Hunter", "message": "MongoDB Atlas connection verified."}
        res = health_coll.insert_one(test_doc)
        doc_id = res.inserted_id
        retrieved = health_coll.find_one({"_id": doc_id})
        health_coll.delete_one({"_id": doc_id})

        if retrieved:
            print("[✓] Read/Write test: Passed (inserted and cleaned up test document).")

        # Update .env file if requested or valid URI supplied
        if update_env and env_path.exists():
            print("\n[*] Updating .env configuration file...")
            lines = []
            with open(env_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            new_lines = []
            uri_set = False
            db_set = False

            for line in lines:
                if line.startswith("MONGODB_URI="):
                    new_lines.append(f"MONGODB_URI={uri}\n")
                    uri_set = True
                elif line.startswith("MONGODB_URL="):
                    new_lines.append(f"MONGODB_URL={uri}\n")
                elif line.startswith("MONGODB_DATABASE=") or line.startswith("MONGODB_DB_NAME="):
                    key = line.split("=", 1)[0]
                    new_lines.append(f"{key}={db_name}\n")
                    db_set = True
                else:
                    new_lines.append(line)

            if not uri_set:
                new_lines.append(f"\nMONGODB_URI={uri}\nMONGODB_URL={uri}\n")
            if not db_set:
                new_lines.append(f"MONGODB_DATABASE={db_name}\nMONGODB_DB_NAME={db_name}\n")

            with open(env_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            print("[✓] Updated .env file with active MongoDB Atlas URI.")

        print("\n" + "=" * 65)
        print("  🎉 MongoDB Atlas Database initialization complete!")
        print("=" * 65)
        return True

    except PyMongoError as pe:
        print(f"\n[!] PyMongo Error: {pe}")
        return False
    except Exception as e:
        print(f"\n[!] Unexpected Error: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Initialize and verify MongoDB Atlas database for AI Bug Hunter")
    parser.add_argument("--uri", type=str, help="MongoDB Atlas connection string")
    parser.add_argument("--db-name", type=str, default="ai_bug_hunter", help="Target database name")
    parser.add_argument("--update-env", action="store_true", help="Update .env file with the provided URI")

    args = parser.parse_args()
    setup_mongodb(uri=args.uri, db_name=args.db_name, update_env=args.update_env)
