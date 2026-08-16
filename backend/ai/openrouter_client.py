import httpx
import json
import re
from typing import Dict, Any, List, Optional
from backend.config import settings

CURATED_OPENROUTER_MODELS = [
    "deepseek/deepseek-chat",
    "deepseek/deepseek-r1:free",
    "google/gemini-2.0-flash-exp:free",
    "google/gemini-flash-1.5",
    "meta-llama/llama-3.3-70b-instruct",
    "qwen/qwen-2.5-coder-32b-instruct",
    "anthropic/claude-3.5-sonnet",
    "openai/gpt-4o-mini",
    "mistralai/mistral-large-2407",
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
            return ["gpt-4o-mini", "gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"]
        elif provider == "gemini":
            return ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-1.0-pro"]
        elif provider == "groq":
            return ["llama-3.1-8b-instant", "llama-3.1-70b-versatile", "mixtral-8x7b-32768"]
        elif provider == "claude":
            return ["claude-3-5-sonnet-20240620", "claude-3-haiku-20240307", "claude-3-opus-20240229"]
        elif provider == "grok":
            return ["grok-2-1212", "grok-2-vision-1212", "grok-beta"]
        
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

    async def _call_llm(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> str:
        provider = settings.AI_PROVIDER
        model = settings.DEFAULT_LLM_MODEL or "deepseek/deepseek-chat"

        if provider == "openai":
            key = settings.OPENAI_API_KEY
            if not key:
                raise ValueError("OpenAI API key is not configured in settings.")
            
            headers = {
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": model if model and not "/" in model else "gpt-4o-mini",
                "messages": messages,
                "temperature": temperature
            }
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
                if response.status_code != 200:
                    raise httpx.HTTPStatusError(
                        f"OpenAI API returned status {response.status_code}: {response.text}",
                        request=response.request,
                        response=response
                    )
                return response.json()["choices"][0]["message"]["content"]

        elif provider == "gemini":
            key = settings.GEMINI_API_KEY
            if not key:
                raise ValueError("Google Gemini API key is not configured in settings.")
            
            headers = {
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": model if model and not "/" in model else "gemini-1.5-flash",
                "messages": messages,
                "temperature": temperature
            }
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post("https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", headers=headers, json=payload)
                if response.status_code != 200:
                    raise httpx.HTTPStatusError(
                        f"Gemini API returned status {response.status_code}: {response.text}",
                        request=response.request,
                        response=response
                    )
                return response.json()["choices"][0]["message"]["content"]

        elif provider == "groq":
            key = settings.GROQ_API_KEY
            if not key:
                raise ValueError("Groq API key is not configured in settings.")
            
            headers = {
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": model if model and not "/" in model else "llama-3.1-8b-instant",
                "messages": messages,
                "temperature": temperature
            }
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload)
                if response.status_code != 200:
                    raise httpx.HTTPStatusError(
                        f"Groq API returned status {response.status_code}: {response.text}",
                        request=response.request,
                        response=response
                    )
                return response.json()["choices"][0]["message"]["content"]

        elif provider == "claude":
            key = settings.CLAUDE_API_KEY
            if not key:
                raise ValueError("Anthropic Claude API key is not configured in settings.")
            
            headers = {
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            }
            
            system_text = ""
            claude_msgs = []
            for msg in messages:
                if msg["role"] == "system":
                    system_text += msg["content"] + "\n"
                else:
                    claude_msgs.append({"role": msg["role"], "content": msg["content"]})
            
            if not claude_msgs:
                claude_msgs.append({"role": "user", "content": "Hello"})
                
            payload = {
                "model": model if model and not "/" in model else "claude-3-5-sonnet-20240620",
                "max_tokens": 4096,
                "messages": claude_msgs,
                "temperature": temperature
            }
            if system_text:
                payload["system"] = system_text.strip()
                
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post("https://api.anthropic.com/v1/messages", headers=headers, json=payload)
                if response.status_code != 200:
                    raise httpx.HTTPStatusError(
                        f"Claude API returned status {response.status_code}: {response.text}",
                        request=response.request,
                        response=response
                    )
                return response.json()["content"][0]["text"]

        elif provider == "grok":
            key = settings.GROK_API_KEY
            if not key:
                raise ValueError("Grok API key is not configured in settings.")
            
            headers = {
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": model if model and not "/" in model else "grok-2-1212",
                "messages": messages,
                "temperature": temperature
            }
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post("https://api.x.ai/v1/chat/completions", headers=headers, json=payload)
                if response.status_code != 200:
                    raise httpx.HTTPStatusError(
                        f"Grok API returned status {response.status_code}: {response.text}",
                        request=response.request,
                        response=response
                    )
                return response.json()["choices"][0]["message"]["content"]

        else:  # OpenRouter (default)
            key = settings.OPENROUTER_API_KEY
            if not key:
                raise ValueError("OpenRouter API key is not configured. Please add your OPENROUTER_API_KEY in Settings or .env file.")

            headers = {
                "Authorization": f"Bearer {key}",
                "HTTP-Referer": "https://aibughunter.local",
                "X-Title": "AI Bug Hunter",
                "Content-Type": "application/json"
            }
            payload = {
                "model": model or "deepseek/deepseek-chat",
                "messages": messages,
                "temperature": temperature
            }
            target_url = f"{self.base_url}/chat/completions"
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(target_url, headers=headers, json=payload)
                if response.status_code != 200:
                    raise httpx.HTTPStatusError(
                        f"OpenRouter API returned status {response.status_code}: {response.text}",
                        request=response.request,
                        response=response
                    )
                data = response.json()
                choices = data.get("choices", [])
                if choices and len(choices) > 0:
                    return choices[0].get("message", {}).get("content", "")
                return ""

    async def explain_vulnerability(self, category: str, message: str, code_snippet: str) -> Dict[str, str]:
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

            ai_message = await self._call_llm(messages, temperature=0.2)
            
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

    async def chat_about_scan(self, chat_history: list, user_message: str, code_context: str) -> str:
        system_prompt = (
            "You are an AI Security Assistant built into the AI Bug Hunter static analysis platform.\n"
            "Answer the user's questions about their codebase and scan results.\n"
            "You have access to the code context provided in the prompt.\n"
            "Help the user understand the security risk, explain how to write secure code, and provide secure rewrites.\n"
            "CRITICAL: Never generate exploit vectors, payloads, shell commands, or penetration testing instructions. Always remain defensive."
        )

        messages = [{"role": "system", "content": system_prompt}]
        for msg in chat_history:
            messages.append({"role": "user" if not msg.is_ai else "assistant", "content": msg.message})
        
        # Append latest message with context
        context_prompt = (
            f"Related code context:\n```\n{code_context}\n```\n\n"
            f"User Question: {user_message}"
        )
        messages.append({"role": "user", "content": context_prompt})

        try:
            return await self._call_llm(messages, temperature=0.3)
        except Exception as e:
            return f"Error communicating with AI model ({settings.AI_PROVIDER}): {str(e)}."

openrouter_client = OpenRouterClient()
# Aliases for smooth migration & backward-compatibility
ai_client = openrouter_client
ollama_client = openrouter_client
