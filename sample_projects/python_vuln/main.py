import os
import hashlib
import tempfile

def process_user_query(user_input):
    # 1. SQL Injection vulnerability via string interpolation
    query = "SELECT * FROM users WHERE name = '%s'" % user_input
    print(f"Executing query: {query}")
    
    # 2. Command Injection vulnerability via shell formatting
    os.system("ping -c 1 " + user_input)

def execute_dynamic_calculation():
    # 3. Code Injection vulnerability via eval
    formula = input("Enter mathematical formula: ")
    result = eval(formula)
    return result

def hash_user_password(password):
    # 4. Weak cryptography algorithm usage (MD5 is broken)
    hasher = hashlib.md5()
    hasher.update(password.encode('utf-8'))
    return hasher.hexdigest()

def write_cache_log(data):
    # 5. Insecure Temporary File usage (Race Condition)
    temp_path = tempfile.mktemp()
    with open(temp_path, "w") as f:
        f.write(data)
    
    # 6. Hardcoded Secret (Fake AWS Credentials for Gitleaks check)
    aws_access_key = "AKIA1234567890ABCDEF"
    aws_secret_key = "aws_secret_access_key='aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ABCD'"
    
    # 7. Assert usage (optimized away in production)
    assert len(data) > 0, "Log data cannot be empty"

if __name__ == "__main__":
    process_user_query("admin' OR '1'='1")
    execute_dynamic_calculation()
