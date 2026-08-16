"""
Legacy Ollama client module - redirected to openrouter_client for OpenRouter.ai integration.
"""
from backend.ai.openrouter_client import (
    OpenRouterClient,
    openrouter_client,
    ai_client,
    ollama_client,
)

OllamaClient = OpenRouterClient
__all__ = ["OpenRouterClient", "OllamaClient", "openrouter_client", "ai_client", "ollama_client"]
