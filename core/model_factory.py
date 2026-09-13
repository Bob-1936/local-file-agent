# core/model_factory.py
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional
from urllib.parse import urlparse
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI

from core.security import SecurityManager


def _clean_endpoint_for_openai(endpoint: str) -> Optional[str]:
    """清洗用于 OpenAI 兼容生态的 base_url"""
    if not endpoint:
        return None
    url = endpoint.strip()
    for suffix in ["/chat/completions", "/completions"]:
        if url.endswith(suffix):
            url = url[:-len(suffix)]
    if "deepseek.com" in url and not url.endswith("/v1"):
        url = f"{url.rstrip('/')}/v1"
    return url.rstrip('/')


def _clean_endpoint_for_gemini(endpoint: str) -> Optional[str]:
    """
    清洗用于 Google Gemini 的自定义端点。
    - 仅当明确属于官方公开主域名且无自定义前缀时，返回 None 由 SDK 原生最优接管。
    - 针对第三方代理、私有网关、专属端口或 VPC，完整保留协议头与前缀路径。
    """
    if not endpoint:
        return None
    raw = endpoint.strip()
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = f"https://{raw}"

    parsed = urlparse(raw)

    # 仅当纯粹是官方标准公开端点且无自定义路径时，返回 None 触发默认接管
    if parsed.netloc == "generativelanguage.googleapis.com" and parsed.path in ["", "/"]:
        return None

    # 针对第三方反向代理，剥离末尾的具体调用后缀，保留主干 Path
    path = parsed.path.rstrip('/')
    for suffix in ["/models", "/chat/completions", "/v1beta", "/v1"]:
        if path.endswith(suffix):
            path = path[:-len(suffix)]

    base = f"{parsed.scheme}://{parsed.netloc}"
    if path:
        base = f"{base}{path}"
    return base.rstrip('/')


def create_chat_model(profile_cfg: Dict[str, Any], temperature: Optional[float] = None) -> BaseChatModel:
    """
    模型工厂函数：统一构建适配多厂商协议的标准 ChatModel 实例。
    """
    platform = profile_cfg.get("platform", "DeepSeek")
    raw_key = profile_cfg.get("key", "")
    api_key = SecurityManager.decrypt_api_key(raw_key) if raw_key else ""
    model_name = profile_cfg.get("selected_model", "")
    endpoint = profile_cfg.get("url", "").strip()

    if not model_name:
        raise ValueError("模型配置错误：未指定具体的模型名称 (selected_model)。")

    # 1. Anthropic Claude 原生分支
    if "Anthropic" in platform or platform.startswith("claude"):
        kwargs = {
            "model_name": model_name,
            "anthropic_api_key": api_key,
            "timeout": 90.0,
            "max_retries": 3
        }
        if endpoint:
            kwargs["base_url"] = endpoint.rstrip('/')
        if temperature is not None:
            kwargs["temperature"] = temperature
        return ChatAnthropic(**kwargs)

    # 2. Google Gemini 原生分支
    elif "Google" in platform or "Gemini" in platform:
        kwargs = {
            "model": model_name,
            "google_api_key": api_key,
            "timeout": 90.0,
            "max_retries": 3
        }
        if endpoint:
            cleaned_ep = _clean_endpoint_for_gemini(endpoint)
            if cleaned_ep:
                kwargs["client_options"] = {"api_endpoint": cleaned_ep}

        if temperature is not None:
            kwargs["temperature"] = temperature
        return ChatGoogleGenerativeAI(**kwargs)

    # 3. OpenAI 及其生态兼容分支 (DeepSeek, 月之暗面, 通义千问, 本地 Ollama 等)
    else:
        base_url = _clean_endpoint_for_openai(endpoint)
        kwargs = {
            "model": model_name,
            "api_key": api_key if api_key else "dummy_key",
            "base_url": base_url if base_url else None,
            "request_timeout": 90.0,
            "max_retries": 3
        }
        if temperature is not None:
            kwargs["temperature"] = temperature
        return ChatOpenAI(**kwargs)