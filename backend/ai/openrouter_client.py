import httpx
import json
import re
from typing import Dict, Any, List, Optional
from backend.config import settings

CURATED_OPENROUTER_MODELS = [
    # Top Free Tier Models (No Credit / Free OpenRouter Tier)
    "deepseek/deepseek-r1:free",
    "deepseek/deepseek-chat:free",
    "google/gemini-2.0-flash-exp:free",
    "google/gemini-2.0-flash-thinking-exp:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "meta-llama/llama-3.1-8b-instruct:free",
    "qwen/qwen-2.5-coder-32b-instruct:free",
    "mistralai/mistral-small-24b-instruct-2501:free",
    # Flagship & Cloud SOTA Models
    "deepseek/deepseek-chat",
    "deepseek/deepseek-r1",
    "google/gemini-2.0-flash-001",
    "anthropic/claude-3.5-sonnet",
    "openai/o3-mini",
    "openai/gpt-4o-mini",
    "meta-llama/llama-3.3-70b-instruct",
    "qwen/qwen-2.5-coder-32b-instruct",
    "mistralai/mistral-large-2411",
]

class OpenRouterClient:
    def __init__(self, base_url: Optional[str] = None):
        self._base_url = base_url
        self.timeout = 45.0

    @property
    def base_url(self) -> str:
        url = self._base_url or settings.OPENROUTER_API_BASE_URL or "https://openrouter.ai/api/v1"
        return url.rstrip("/")

    @base_url.setter
    def base_url(self, value: str):
        self._base_url = value

    async def list_models(self) -> List[str]:
        provider = settings.AI_PROVIDER
        if provider == "openai":
            return ["gpt-4o-mini", "gpt-4o", "o3-mini", "o1", "o1-mini", "gpt-4-turbo", "gpt-3.5-turbo"]
        elif provider == "gemini":
            return ["gemini-2.0-flash", "gemini-2.0-flash-thinking-exp", "gemini-1.5-pro", "gemini-1.5-flash", "gemini-1.5-flash-8b"]
        elif provider == "groq":
            return ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "deepseek-r1-distill-llama-70b", "mixtral-8x7b-32768"]
        elif provider == "claude":
            return ["claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022", "claude-3-opus-20240229", "claude-3-haiku-20240307"]
        elif provider == "grok":
            return ["grok-2-1212", "grok-2-vision-1212", "grok-2-mini", "grok-beta"]
        
        # OpenRouter provider
        key = settings.OPENROUTER_API_KEY
        if key:
            try:
                target_url = f"{self.base_url}/models"
                headers = {
                    "Authorization": f"Bearer {key}",
                    "HTTP-Referer": "https://aibughunter.local",
                    "X-Title": "AI Bug Hunter",
                }
                async with httpx.AsyncClient(timeout=5.0) as client:
                    response = await client.get(target_url, headers=headers)
                    if response.status_code == 200:
                        data = response.json().get("data", [])
                        if isinstance(data, list) and len(data) > 0:
                            model_ids = [m["id"] for m in data if isinstance(m, dict) and "id" in m]
                            if model_ids:
                                return model_ids[:30]
            except Exception:
                pass

        return CURATED_OPENROUTER_MODELS

    def _get_offline_fallback(self, category: str, message: str, code_snippet: str) -> Dict[str, str]:
        # Generates a comprehensive fallback explanation offline
        return {
            "explanation": (
                f"### Security Risk: {category}\n\n"
                f"A security issue categorized under **{category}** was detected. Details:\n"
                f"> {message}\n\n"
                f"Insecure code snippet identified:\n"
                f"```python\n{code_snippet}\n```\n\n"
                f"**Potential Impact:**\n"
                f"- Unauthorized read, write, or modification of system files and resources.\n"
                f"- Arbitrary code injection or state manipulation by external inputs.\n"
                f"- System denial of service, resource exhaustion, or exposure of authentication tokens.\n"
                f"- Compromise of data confidentiality, integrity, and non-repudiation."
            ),
            "fix": (
                f"### Recommended Remediation\n\n"
                f"To resolve this vulnerability, follow these secure development best practices:\n"
                f"1. **Input Sanitization**: Always validate and clean user input against strict whitelists.\n"
                f"2. **Parameterized Interfaces**: Avoid concatenating raw values inside system utilities, subprocess boundaries, and databases.\n"
                f"3. **Secrets Management**: Read sensitive configurations exclusively via environment properties or vault API repositories.\n"
                f"4. **Least Privilege**: Execute application processes under the minimum OS privileges necessary."
            )
        }

    def _get_offline_chat_response(
        self,
        user_message: str,
        code_context: str = "",
        provider: str = "openrouter",
        model: str = "deepseek/deepseek-chat",
        error_notice: Optional[str] = None
    ) -> str:
        msg_lower = (user_message + " " + code_context).lower()
        key_help = ""
        clean_prov = (provider or "openrouter").lower()
        if clean_prov == "ollama":
            clean_prov = "openrouter"
        prov_label = clean_prov.upper()

        if error_notice:
            key_help = (
                f"> [!NOTE]\n"
                f"> **Live AI Reasoning Notice:** To connect directly to live cloud intelligence ({prov_label} · `{model}`), configure your API key using the **'🔑 Enter Key'** button above or in **Settings**.\n\n"
            )

        if "sql" in msg_lower or "injection" in msg_lower or "sqli" in msg_lower:
            return key_help + (
                "### 🛡️ SQL Injection (CWE-89) Exploit Analysis & Remediation\n\n"
                "**Vulnerability Mechanism:**\n"
                "SQL Injection occurs when untrusted input is directly interpolated or concatenated into a database query string. An attacker can break out of data literals to manipulate SQL syntax, bypass authentication (`' OR '1'='1`), read sensitive tables (`UNION SELECT`), or execute administrative commands.\n\n"
                "**Secure Pattern — Parameterized Statements (Python / FastAPI):**\n"
                "```python\n"
                "# ❌ VULNERABLE (Dynamic string formatting)\n"
                "cursor.execute(f\"SELECT id, email, role FROM users WHERE username = '{raw_user}' AND status = 'active'\")\n\n"
                "# ✅ SECURE (Parameterized query with placeholders)\n"
                "cursor.execute(\n"
                "    \"SELECT id, email, role FROM users WHERE username = %s AND status = 'active'\",\n"
                "    (raw_user,)\n"
                ")\n"
                "user = cursor.fetchone()\n"
                "```\n\n"
                "**Secure Pattern — SQLAlchemy 2.0 ORM:**\n"
                "```python\n"
                "# ✅ SECURE (ORM parameterized query)\n"
                "stmt = select(User).where(User.username == raw_user, User.is_active == True)\n"
                "user = db.scalars(stmt).first()\n"
                "```\n\n"
                "**Key Defenses:**\n"
                "1. Always use parameterized queries or trusted ORMs.\n"
                "2. Enforce strict type validation using Pydantic schemas.\n"
                "3. Apply least privilege DB user permissions (deny DDL/schema alteration)."
            )

        if "secret" in msg_lower or "hardcode" in msg_lower or "api key" in msg_lower or "token" in msg_lower or "password" in msg_lower:
            return key_help + (
                "### 🔑 Hardcoded Credentials & Secret Leaks (CWE-798 / OWASP A07:2021)\n\n"
                "**Vulnerability Mechanism:**\n"
                "Embedding API keys, database passwords, private certificates, or JWT secrets directly into codebase commits exposes credentials to version control history, log aggregators, and reverse engineering.\n\n"
                "**Remediation Steps:**\n"
                "1. **Immediate Revocation**: Rotate any exposed secret in the corresponding cloud console immediately.\n"
                "2. **Environment Variable Injection**: Externalize secrets to environment variables via `.env` (kept in `.gitignore`).\n"
                "3. **Secrets Manager Integration**: In production, utilize AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault.\n\n"
                "**Secure Implementation (Python `pydantic-settings`):**\n"
                "```python\n"
                "# ❌ VULNERABLE\n"
                "AWS_SECRET_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n"
                "DATABASE_URL = \"postgresql://admin:SecretPass123@db.prod.internal/main\"\n\n"
                "# ✅ SECURE\n"
                "import os\n"
                "from pydantic_settings import BaseSettings\n\n"
                "class Config(BaseSettings):\n"
                "    AWS_SECRET_KEY: str\n"
                "    DATABASE_URL: str\n"
                "    class Config:\n"
                "        env_file = \".env\"\n\n"
                "config = Config()\n"
                "```"
            )

        if "xss" in msg_lower or "cross-site" in msg_lower or "script" in msg_lower:
            return key_help + (
                "### ⚡ Cross-Site Scripting (XSS) Prevention (CWE-79)\n\n"
                "**Vulnerability Mechanism:**\n"
                "XSS occurs when an application includes untrusted data in an HTTP response without adequate validation or context-aware encoding. Attackers execute malicious JavaScript in a victim's browser, hijacking session cookies, redirecting users, or defacing UI.\n\n"
                "**Secure Patterns:**\n"
                "```typescript\n"
                "// ❌ VULNERABLE (Direct innerHTML assignment)\n"
                "element.innerHTML = userComment;\n\n"
                "// ✅ SECURE (Safe DOM text binding / DOMPurify)\n"
                "element.textContent = userComment;\n"
                "// OR with DOMPurify for HTML rich text:\n"
                "element.innerHTML = DOMPurify.sanitize(userComment);\n"
                "```\n\n"
                "**HTTP Security Headers (FastAPI / Nginx):**\n"
                "```python\n"
                "# Content Security Policy & Cookie Hardening\n"
                "response.headers[\"Content-Security-Policy\"] = \"default-src 'self'; script-src 'self';\"\n"
                "response.set_cookie(\"session_id\", token, httponly=True, secure=True, samesite=\"Strict\")\n"
                "```"
            )

        if "ssrf" in msg_lower or "request forgery" in msg_lower:
            return key_help + (
                "### 🌐 Server-Side Request Forgery (SSRF) Mitigation (CWE-918)\n\n"
                "**Vulnerability Mechanism:**\n"
                "SSRF occurs when a server-side application fetches a remote resource without validating the user-supplied URL. Attackers can coerce the backend into querying internal metadata endpoints (`169.254.169.254`), loopback services (`127.0.0.1:6379`), or private subnet microservices.\n\n"
                "**Secure Pattern — Strict Whitelist & Private IP Blocking:**\n"
                "```python\n"
                "import ipaddress, socket, urllib.parse, httpx\n\n"
                "ALLOWED_DOMAINS = {\"api.trusted-partner.com\", \"cdn.example.com\"}\n\n"
                "def validate_safe_url(target_url: str) -> bool:\n"
                "    parsed = urllib.parse.urlparse(target_url)\n"
                "    if parsed.scheme not in (\"https\",):\n"
                "        return False\n"
                "    if parsed.hostname not in ALLOWED_DOMAINS:\n"
                "        return False\n"
                "    # Resolve IP and verify it is not private/loopback/link-local\n"
                "    ip = socket.gethostbyname(parsed.hostname)\n"
                "    ip_obj = ipaddress.ip_address(ip)\n"
                "    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:\n"
                "        return False\n"
                "    return True\n"
                "```"
            )

        if "rce" in msg_lower or "command" in msg_lower or "exec" in msg_lower or "subprocess" in msg_lower:
            return key_help + (
                "### 🛑 Command Injection & Arbitrary Code Execution (CWE-78 / CWE-94)\n\n"
                "**Vulnerability Mechanism:**\n"
                "Passing unsanitized user inputs into system shell wrappers (`os.system`, `subprocess.Popen(..., shell=True)`, `eval()`, `exec()`) allows attackers to append shell meta-characters (`;`, `&&`, `|`) to execute arbitrary commands with web server privileges.\n\n"
                "**Secure Pattern — Non-Shell Subprocess Lists:**\n"
                "```python\n"
                "# ❌ VULNERABLE (Shell enabled)\n"
                "# os.system(\"ping -c 4 \" + user_input)\n\n"
                "# ✅ SECURE (Direct argument vector without shell interpreter)\n"
                "import subprocess, re\n\n"
                "if not re.match(r'^[a-zA-Z0-9.-]+$', user_input):\n"
                "    raise ValueError(\"Invalid hostname format\")\n\n"
                "result = subprocess.run(\n"
                "    [\"ping\", \"-c\", \"4\", user_input],\n"
                "    capture_output=True,\n"
                "    text=True,\n"
                "    timeout=5\n"
                ")\n"
                "```"
            )

        if "cors" in msg_lower or "csrf" in msg_lower:
            return key_help + (
                "### 🛡️ CORS & CSRF Defense Architecture\n\n"
                "**Cross-Origin Resource Sharing (CORS):**\n"
                "Wildcard origins (`allow_origins=[\"*\"]`) combined with credentials (`allow_credentials=True`) allow malicious third-party websites to extract sensitive API responses.\n\n"
                "**FastAPI CORS Hardening:**\n"
                "```python\n"
                "from fastapi.middleware.cors import CORSMiddleware\n\n"
                "app.add_middleware(\n"
                "    CORSMiddleware,\n"
                "    allow_origins=[\"https://app.yourdomain.com\"],  # Specific domain\n"
                "    allow_credentials=True,\n"
                "    allow_methods=[\"GET\", \"POST\", \"PUT\", \"DELETE\"],\n"
                "    allow_headers=[\"Authorization\", \"Content-Type\"],\n"
                "    max_age=3600,\n"
                ")\n"
                "```\n\n"
                "**Cross-Site Request Forgery (CSRF) Mitigation:**\n"
                "- Store session tokens in `HttpOnly; Secure; SameSite=Strict` cookies.\n"
                "- For state-changing requests, require custom headers (`X-Requested-With` or `X-CSRF-Token`)."
            )

        if "owasp" in msg_lower or "checklist" in msg_lower or "top 10" in msg_lower:
            return key_help + (
                "### 📋 OWASP Top 10 Security Architecture Checklist\n\n"
                "| Category | Vulnerability Type | Primary Defense Strategy |\n"
                "| :--- | :--- | :--- |\n"
                "| **A01:2021** | **Broken Access Control** | Enforce RBAC/ABAC on every endpoint; deny by default. |\n"
                "| **A02:2021** | **Cryptographic Failures** | Use Argon2id / bcrypt; TLS 1.3+; avoid hardcoded keys. |\n"
                "| **A03:2021** | **Injection** | Parameterized queries; AST input validation; ORMs. |\n"
                "| **A04:2021** | **Insecure Design** | Threat modeling; automated SAST integration. |\n"
                "| **A05:2021** | **Security Misconfiguration** | Disable debug mode in production; harden HTTP headers. |\n"
                "| **A06:2021** | **Vulnerable Components** | Scan dependencies with `pip-audit` / `npm audit`. |\n"
                "| **A07:2021** | **Identification & Auth** | Implement MFA; enforce rate limits; secure session cookies. |\n"
                "| **A08:2021** | **Software & Data Integrity** | Code signing; verify CI/CD pipelines & checksums. |\n"
                "| **A09:2021** | **Security Logging Failures** | Log security events (login, role change) to SIEM. |\n"
                "| **A10:2021** | **SSRF** | Validate URL scheme & hostname against strict allowlists. |"
            )

        # Default comprehensive security response
        return key_help + (
            "### 🛡️ AI Security Architecture & Vulnerability Remediation\n\n"
            f"**Query Analysis:**\n"
            f"Regarding your query: *\"{user_message}\"*\n\n"
            "**Core Security Recommendations:**\n"
            "1. **Defense in Depth**: Implement layered security across input validation, application business logic, authorization boundaries, and database query parameters.\n"
            "2. **Principle of Least Privilege**: Ensure services and background workers operate with minimal required OS and DB privileges.\n"
            "3. **Static & Dynamic Analysis**: Regularly run AI Bug Hunter SAST scans across repository pull requests to catch CWEs before production release.\n"
            "4. **Secrets Sanitization**: Store all credentials, tokens, and encryption keys in `.env` or managed cloud vaults."
        )

    async def _call_llm(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        provider: Optional[str] = None,
        model: Optional[str] = None
    ) -> str:
        # Determine active provider and model
        target_provider = (provider or settings.AI_PROVIDER or "openrouter").lower()
        if target_provider == "ollama":
            target_provider = "openrouter"
        target_model = model or settings.DEFAULT_LLM_MODEL or "deepseek/deepseek-chat"

        # Auto-infer provider from model name if not explicitly set
        if not provider or provider == "openrouter":
            if target_model.startswith(("gpt-", "o1", "o3", "openai/")) and settings.OPENAI_API_KEY:
                target_provider = "openai"
            elif (target_model.startswith("gemini-") or (target_model.startswith("google/") and not target_model.endswith(":free"))) and settings.GEMINI_API_KEY:
                target_provider = "gemini"
            elif target_model.startswith(("claude-", "anthropic/")) and settings.CLAUDE_API_KEY:
                target_provider = "claude"
            elif target_model.startswith(("grok-", "x-ai/")) and settings.GROK_API_KEY:
                target_provider = "grok"
            elif ("groq" in target_model or "llama-3" in target_model) and settings.GROQ_API_KEY:
                target_provider = "groq"

        # Tier 1: Direct Provider APIs
        if target_provider == "openai" and settings.OPENAI_API_KEY:
            try:
                headers = {
                    "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
                    "Content-Type": "application/json"
                }
                clean_model = target_model.replace("openai/", "").split(":")[0]
                if not clean_model:
                    clean_model = "gpt-4o-mini"
                
                payload: Dict[str, Any] = {
                    "model": clean_model,
                    "messages": messages
                }
                # o1 and o3 models do not support custom temperature
                if not clean_model.startswith(("o1", "o3")):
                    payload["temperature"] = temperature

                async with httpx.AsyncClient(timeout=35.0) as client:
                    response = await client.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
                    if response.status_code == 200:
                        return response.json()["choices"][0]["message"]["content"]
                    raise httpx.HTTPStatusError(f"OpenAI error {response.status_code}: {response.text}", request=response.request, response=response)
            except Exception as direct_err:
                if not settings.OPENROUTER_API_KEY:
                    raise direct_err

        elif target_provider == "gemini" and settings.GEMINI_API_KEY:
            try:
                headers = {
                    "Authorization": f"Bearer {settings.GEMINI_API_KEY}",
                    "Content-Type": "application/json"
                }
                clean_model = target_model.replace("google/", "").split(":")[0]
                if clean_model.endswith("-001"):
                    clean_model = clean_model[:-4]
                if not clean_model or not clean_model.startswith("gemini"):
                    clean_model = "gemini-2.0-flash"

                payload = {
                    "model": clean_model,
                    "messages": messages,
                    "temperature": temperature
                }
                # Google OpenAI-compatible endpoint supports Authorization header and URL key
                endpoint_url = f"https://generativelanguage.googleapis.com/v1beta/openai/chat/completions?key={settings.GEMINI_API_KEY}"
                async with httpx.AsyncClient(timeout=35.0) as client:
                    response = await client.post(endpoint_url, headers=headers, json=payload)
                    if response.status_code == 200:
                        choices = response.json().get("choices", [])
                        if choices and len(choices) > 0:
                            return choices[0].get("message", {}).get("content", "")
                    raise httpx.HTTPStatusError(f"Gemini error {response.status_code}: {response.text}", request=response.request, response=response)
            except Exception as direct_err:
                if not settings.OPENROUTER_API_KEY:
                    raise direct_err

        elif target_provider == "claude" and settings.CLAUDE_API_KEY:
            try:
                headers = {
                    "x-api-key": settings.CLAUDE_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json"
                }
                clean_model = target_model.replace("anthropic/", "").split(":")[0]
                if not clean_model:
                    clean_model = "claude-3-5-sonnet-20241022"

                system_text = ""
                claude_msgs: List[Dict[str, str]] = []
                for msg in messages:
                    if msg["role"] == "system":
                        system_text += msg["content"] + "\n"
                    else:
                        role = "assistant" if msg["role"] == "assistant" else "user"
                        # Merge consecutive messages with identical roles for Anthropic spec
                        if claude_msgs and claude_msgs[-1]["role"] == role:
                            claude_msgs[-1]["content"] += "\n\n" + msg["content"]
                        else:
                            claude_msgs.append({"role": role, "content": msg["content"]})

                if not claude_msgs:
                    claude_msgs.append({"role": "user", "content": "Hello"})

                payload = {
                    "model": clean_model,
                    "max_tokens": 4096,
                    "messages": claude_msgs,
                    "temperature": temperature
                }
                if system_text:
                    payload["system"] = system_text.strip()

                async with httpx.AsyncClient(timeout=35.0) as client:
                    response = await client.post("https://api.anthropic.com/v1/messages", headers=headers, json=payload)
                    if response.status_code == 200:
                        content_arr = response.json().get("content", [])
                        if content_arr and len(content_arr) > 0:
                            return content_arr[0].get("text", "")
                    raise httpx.HTTPStatusError(f"Claude error {response.status_code}: {response.text}", request=response.request, response=response)
            except Exception as direct_err:
                if not settings.OPENROUTER_API_KEY:
                    raise direct_err

        elif target_provider == "grok" and settings.GROK_API_KEY:
            try:
                headers = {
                    "Authorization": f"Bearer {settings.GROK_API_KEY}",
                    "Content-Type": "application/json"
                }
                clean_model = target_model.replace("x-ai/", "").split(":")[0]
                payload = {
                    "model": clean_model if clean_model else "grok-2-1212",
                    "messages": messages,
                    "temperature": temperature
                }
                async with httpx.AsyncClient(timeout=35.0) as client:
                    response = await client.post("https://api.x.ai/v1/chat/completions", headers=headers, json=payload)
                    if response.status_code == 200:
                        choices = response.json().get("choices", [])
                        if choices and len(choices) > 0:
                            return choices[0].get("message", {}).get("content", "")
                    raise httpx.HTTPStatusError(f"Grok error {response.status_code}: {response.text}", request=response.request, response=response)
            except Exception as direct_err:
                if not settings.OPENROUTER_API_KEY:
                    raise direct_err

        elif target_provider == "groq" and settings.GROQ_API_KEY:
            try:
                headers = {
                    "Authorization": f"Bearer {settings.GROQ_API_KEY}",
                    "Content-Type": "application/json"
                }
                clean_model = target_model.replace("groq/", "").split(":")[0]
                payload = {
                    "model": clean_model if clean_model else "llama-3.3-70b-versatile",
                    "messages": messages,
                    "temperature": temperature
                }
                async with httpx.AsyncClient(timeout=35.0) as client:
                    response = await client.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload)
                    if response.status_code == 200:
                        choices = response.json().get("choices", [])
                        if choices and len(choices) > 0:
                            return choices[0].get("message", {}).get("content", "")
                    raise httpx.HTTPStatusError(f"Groq error {response.status_code}: {response.text}", request=response.request, response=response)
            except Exception as direct_err:
                if not settings.OPENROUTER_API_KEY:
                    raise direct_err

        # Tier 2: OpenRouter Hub Routing
        if settings.OPENROUTER_API_KEY:
            headers = {
                "Authorization": f"Bearer {settings.OPENROUTER_API_KEY}",
                "HTTP-Referer": "https://aibughunter.local",
                "X-Title": "AI Bug Hunter",
                "Content-Type": "application/json"
            }
            
            # Map model names to OpenRouter namespaces if needed
            or_model = target_model
            if not "/" in or_model:
                if or_model.startswith(("gpt-", "o1", "o3")):
                    or_model = f"openai/{or_model}"
                elif or_model.startswith("gemini-"):
                    or_model = f"google/{or_model}"
                elif or_model.startswith("claude-"):
                    or_model = f"anthropic/{or_model}"
                elif or_model.startswith("grok-"):
                    or_model = f"x-ai/{or_model}"
                elif "deepseek" in or_model:
                    or_model = f"deepseek/{or_model}"

            payload = {
                "model": or_model,
                "messages": messages,
                "temperature": temperature
            }
            target_url = f"{self.base_url}/chat/completions"
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(target_url, headers=headers, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    choices = data.get("choices", [])
                    if choices and len(choices) > 0:
                        return choices[0].get("message", {}).get("content", "")
                raise httpx.HTTPStatusError(f"OpenRouter error {response.status_code}: {response.text}", request=response.request, response=response)

        # Tier 3: No valid API key configured - Raise for graceful offline fallback
        raise ValueError(
            f"No active API key configured for {target_provider.upper()} (or OpenRouter). "
            f"Please enter your {target_provider.upper()} API Key to connect live cloud reasoning."
        )

    async def explain_vulnerability(
        self,
        category: str,
        message: str,
        code_snippet: str,
        provider: Optional[str] = None,
        model: Optional[str] = None
    ) -> Dict[str, str]:
        system_prompt = (
            "You are a Senior Defensive Cybersecurity Engineer and Secure Coding Expert.\n"
            "Analyze the detected vulnerability and provide an educational review.\n"
            "Format the output strictly into two sections using Markdown headers:\n"
            "1. '### Vulnerability Explanation': Explain why this code is vulnerable in a helpful, educational tone. Detail the potential business/system risks and threat vectors.\n"
            "2. '### Secure Remediation': Provide a secure rewrite of the code snippet. Explain what secure coding concepts (like input sanitization, parameterized queries, or cryptography) were applied to make the code robust.\n"
            "CRITICAL: DO NOT write exploit payloads, instructions to exploit the code, or shell attacks. Keep your focus entirely defensive."
        )

        user_prompt = (
            f"Vulnerability Category: {category}\n"
            f"Scanner Message: {message}\n"
            f"Insecure Code Snippet:\n"
            f"```\n{code_snippet}\n```\n"
            f"Provide explanation and remediation:"
        )

        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]

            ai_message = await self._call_llm(messages, temperature=0.2, provider=provider, model=model)
            
            # Look for variations of remediation header
            pattern = re.compile(r'#+\s*(?:Secure\s*)?Remediation', re.IGNORECASE)
            match = pattern.search(ai_message)
            if match:
                split_idx = match.start()
                explanation = ai_message[:split_idx].strip()
                fix = ai_message[split_idx:].strip()
            else:
                parts = ai_message.split("### Secure Remediation")
                if len(parts) >= 2:
                    explanation = parts[0].strip()
                    fix = "### Secure Remediation\n\n" + parts[1].strip()
                else:
                    explanation = ai_message
                    fix = "Refer to standard OWASP/SANS guidelines to remediate this vulnerability."

            return {
                "explanation": explanation,
                "fix": fix
            }
        except Exception:
            pass

        return self._get_offline_fallback(category, message, code_snippet)

    def explain_vulnerability_sync(self, category: str, message: str, code_snippet: str) -> Dict[str, str]:
        # Sync version for background worker threads
        import asyncio
        try:
            return asyncio.run(self.explain_vulnerability(category, message, code_snippet))
        except Exception:
            try:
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(lambda: asyncio.run(self.explain_vulnerability(category, message, code_snippet)))
                    return future.result()
            except Exception:
                return self._get_offline_fallback(category, message, code_snippet)

    async def chat_about_scan(
        self,
        chat_history: list,
        user_message: str,
        code_context: str = "",
        provider: Optional[str] = None,
        model: Optional[str] = None
    ) -> str:
        system_prompt = (
            "You are a Senior Defensive Cybersecurity Architect and Automated SAST Remediation Expert built into AI Bug Hunter.\n"
            "Your mission is to provide rigorous, accurate, actionable security code review, exploit analysis, and secure code rewrites.\n"
            "When answering user questions:\n"
            "1. Explain the root cause of the vulnerability or security concept clearly.\n"
            "2. Provide concrete, modern, secure code examples with syntax highlighting.\n"
            "3. Reference relevant OWASP, CWE, and NIST standards.\n"
            "CRITICAL: Never generate offensive exploits, attack payloads, malicious shell scripts, or attack tooling. Keep all advice strictly defensive and educational."
        )

        messages = [{"role": "system", "content": system_prompt}]
        for msg in chat_history:
            is_ai = getattr(msg, "is_ai", False) if not isinstance(msg, dict) else msg.get("is_ai", False)
            content = getattr(msg, "message", "") if not isinstance(msg, dict) else msg.get("message", "")
            if content:
                messages.append({"role": "assistant" if is_ai else "user", "content": content})
        
        # Build prompt with optional code context
        if code_context and code_context.strip():
            user_content = f"### Related Code & Vulnerability Context:\n```\n{code_context.strip()}\n```\n\n### User Question:\n{user_message}"
        else:
            user_content = user_message

        messages.append({"role": "user", "content": user_content})

        try:
            return await self._call_llm(messages, temperature=0.3, provider=provider, model=model)
        except Exception as e:
            # Fallback to local security intelligence engine
            return self._get_offline_chat_response(
                user_message,
                code_context,
                provider or settings.AI_PROVIDER,
                model or settings.DEFAULT_LLM_MODEL,
                error_notice=str(e)
            )

openrouter_client = OpenRouterClient()
# Aliases for smooth migration & backward-compatibility
ai_client = openrouter_client
ollama_client = openrouter_client
