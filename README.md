# AI Bug Hunter

AI Bug Hunter is an AI-powered static application security testing (SAST) platform. It allows developers to analyze code repositories (ZIP files, Git repository clones, or copy-pasted files) for critical security vulnerabilities, credentials leaks, and outdated dependencies. It enriches results with a local Large Language Model (Ollama) to deliver custom defensive explanations and secure code rewrites without leaking source files to third-party APIs.

---

## Key Features

1. **Relational Data Mapping**: Handles user registration, scans queue progress logging, and keeps structured vulnerability details (severity, category, references, code lines).
2. **Scanner Engine**:
   - **Secrets (Gitleaks)**: Scans for exposed private keys, AWS access credentials, Stripe client tokens, Slack hooks, and generic secrets (with built-in fallback regex checks).
   - **Python SAST (Bandit)**: Builds an Abstract Syntax Tree (AST) to track dynamically executed commands (`eval()`, `exec()`), shell subprocess injection points, insecure hashlib algorithms, and SQL formatting concats.
   - **Multi-Language Linting (Semgrep)**: Matches rule patterns for JavaScript/TypeScript (XSS in innerHTML, DOM injections), C/C++ (stack overflows like strcpy), Java (SQL concatenation in statements), and PHP.
   - **Outdated Dependencies Audit**: Scans package manifests (`package.json`, `requirements.txt`) against offline libraries signature database records (Lodash Prototype Pollution, Axios SSRF).
3. **Defensive AI Remediation (Ollama)**: Employs local coding models (like Qwen Coder or DeepSeek-Coder) using system constraints to explain vulnerabilities and suggest secure rewrites without explaining exploit methods.
4. **HTML/PDF Reports**: Exports executive summaries, severity distribution donut charts, and detail lists with code snippet references.
5. **Interactive Chat Sidebar**: Allows developers to ask the AI assistant questions about specific findings and code snippets.

---

## Core System Architecture

```
                 +-----------------------------------------+
                 |            React Frontend               |
                 | (Vite, TypeScript, Tailwind CSS v4)     |
                 +--------------------+--------------------+
                                      | (JSON API / WebSocket)
                                      v
                 +--------------------+--------------------+
                 |           FastAPI Backend               |
                 +----------+-------------------+----------+
                            |                   |
                            v                   v
            +---------------+---------------+   +----------+-----------+
            |      Scanning Orchestrator    |   |      Local LLM       |
            | (Gitleaks, Bandit, Semgrep,   |   |   (Ollama API client)|
            |  Dependency Analyzers)        |   +----------------------+
            +---------------+---------------+
                            |
                            v
            +---------------+---------------+
            |      Relational Database      |
            |  (SQLite / PostgreSQL via DB) |
            +-------------------------------+
```

---

## Database Schemas Reference

The application uses SQLAlchemy to model the database schema:

- **Users**: Unique username, pass hashes (bcrypt), and authorization role (`admin` or `developer`). First registered user is automatically created as an Admin.
- **Projects**: Unique identifier, repository name, descriptions, uploaded file paths, ingestion type (`zip`, `folder`, `git`, `file`), and primary programming language detected.
- **Scans**: Tracks scanner status (`pending`, `running`, `completed`, `failed`), progress counter (0-100), severity counts, execution timestamp, and PDF/HTML paths.
- **Vulnerabilities**: References scan ID. Stores severity badges, categories (XSS, SQLi), details description, tool indicators, file line number coordinates, code block snippets, and AI-generated reviews (explanations & secure rewrites).
- **ChatMessages**: Stores query chat logs between developers and the AI assistant, mapping thread logs to the scan session.

---

## Local Development Installation

### Prerequisites
- **Python 3.10** installed.
- **Node.js v20+** installed.
- **Ollama** installed locally (running on `http://localhost:11434`).

### Setup Ollama Model
Run the following in your terminal to pull the recommended lightweight coding model:
```bash
ollama pull qwen2.5-coder:1.5b
```
Ensure Ollama is running (`ollama serve` or via desktop app).

---

### Step 1: Start Backend Server

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Install Python requirements:
   ```bash
   python -m pip install -r requirements.txt
   ```
3. Run the FastAPI development server:
   ```bash
   python main.py
   ```
The backend API documentation will be available at `http://localhost:8000/docs`.

---

### Step 2: Start Frontend Application

1. Navigate to the frontend directory:
   ```bash
   cd ../frontend
   ```
2. Install npm packages:
   ```bash
   npm install
   ```
3. Run the Vite development server:
   ```bash
   npm run dev
   ```
Open `http://localhost:5173` in your browser.

---

## Production Deployment using Docker

1. Ensure **Docker Desktop** is running on your machine.
2. In the root directory of the project, run:
   ```bash
   docker-compose up --build
   ```
This commands builds:
- **`bug_hunter_db`**: A PostgreSQL 15 database instance.
- **`bug_hunter_redis`**: A Redis 7 instance for background tasks.
- **`bug_hunter_backend`**: The FastAPI server listening on port 8000.
- **`bug_hunter_frontend`**: The compiled React production assets served via Nginx on port 80.

---

## Verifying Scanner with Test Projects

We provide two sample projects inside the `sample_projects` directory containing vulnerabilities to test the scanner:

1. **`sample_projects/python_vuln`**:
   - Contains dynamic SQL query building (`main.py`).
   - Contains shell command injection execution (`main.py`).
   - Contains `eval()` code injection (`main.py`).
   - Contains weak MD5 hash and insecure temp files (`main.py`).
   - Contains vulnerable package versions in `requirements.txt` (`django==3.2.1`).

2. **`sample_projects/js_vuln`**:
   - Contains innerHTML DOM XSS (`index.js`).
   - Contains command execution injection (`index.js`).
   - Contains vulnerable npm packages in `package.json` (`lodash==4.17.15`).

### How to Scan:
1. Log in to the application.
2. Click **New Analysis Scan**.
3. Choose **Paste Code** or **ZIP Archive** (zip the files inside `sample_projects/python_vuln` and upload).
4. Click **Trigger Scan Run**.
5. Once completed, navigate to **View Results** to inspect code lines highlighted in red, read security remediation details, and trigger the AI assistant to show secure rewrites.
