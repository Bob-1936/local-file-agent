# core/tokenizer.py

import os
import re
from typing import Optional

# 尝试载入 tiktoken，如果未安装则降级为本地启发式算法
try:
    import tiktoken
    _TIKTOKEN_ENCODER = tiktoken.get_encoding("cl100k_base")
except Exception:
    _TIKTOKEN_ENCODER = None


def count_text_tokens(text: Optional[str], platform: str = "DeepSeek") -> int:
    """
    纯本地离线计算文本 Token 数量。
    支持根据模型平台（OpenAI/DeepSeek 与 Google Gemini）的底层分词器差异自适应切换算法。
    不消耗任何 API 额度，断网可用。
    """
    if not text:
        return 0

    is_gemini = "google" in platform.lower() or "gemini" in platform.lower()

    if not is_gemini:
        # ================= 1. 标准 OpenAI / DeepSeek / 通用分支 (BPE cl100k) =================
        if _TIKTOKEN_ENCODER is not None:
            try:
                return len(_TIKTOKEN_ENCODER.encode(text, disallowed_special=()))
            except Exception:
                pass

        # tiktoken 缺失时的本地平滑降级
        chinese_chars = len(re.findall(r'[\u4e00-\u9fa5\u3000-\u303f\uff00-\uffef]', text))
        other_chars = len(text) - chinese_chars
        return max(1, int(chinese_chars * 0.8) + int(other_chars / 3.8))

    else:
        # ================= 2. Google Gemini 本地拟合分支 (SentencePiece 字节级回退) =================
        # 1) Unicode 框线字符 (Box Drawing: │, ├, ─, └, ┬ 等，编码区间 U+2500 - U+257F)
        # Gemini 对每个 3 字节 UTF-8 框线符号拆解为 3 个独立 Token
        box_chars = len(re.findall(r'[\u2500-\u257f]', text))

        # 2) 中文字符及全角符号 (Gemini 切分粒度较碎，实测约 1.85 tokens / 字)
        cjk_chars = len(re.findall(r'[\u4e00-\u9fa5\u3000-\u303f\uff00-\uffef]', text))

        # 3) 空格字符 (Gemini 不合并连续缩进空格，约 0.8 token / 空格)
        spaces = len(re.findall(r' ', text))

        # 4) 英文及通用 ASCII 字符
        cleaned_text = re.sub(r'[\u2500-\u257f\u4e00-\u9fa5\u3000-\u303f\uff00-\uffef ]', '', text)
        other_chars = len(cleaned_text)

        gemini_estimated = (
            int(box_chars * 3.0) +
            int(cjk_chars * 1.85) +
            int(spaces * 0.8) +
            int(other_chars / 3.5)
        )

        return max(1, gemini_estimated)


def count_image_tokens(img_path: Optional[str], platform: str = "") -> int:
    """估算视觉模型多模态图片的 Token 消耗"""
    if not img_path or not os.path.exists(img_path):
        return 0
    # Gemini 1.5 系列默认单张图片基准为 258 tokens，其他平台约 850 tokens
    if "google" in platform.lower() or "gemini" in platform.lower():
        return 258
    return 850


def format_token_count(count: int) -> str:
    """格式化展示 Token 数量，如 29314 -> 29.3k"""
    if count >= 1000:
        return f"{count / 1000:.1f}k"
    return str(count)