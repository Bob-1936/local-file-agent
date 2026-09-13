# tools/prompt_manager.py
# -*- coding: utf-8 -*-

import os
import uuid
import json
import copy
import hashlib
import logging
from typing import Dict, List, Any, Optional
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, ToolMessage, SystemMessage

logger = logging.getLogger("PromptManager")

DEFAULT_SYSTEM_PROMPT = """你是一个专业的本地文件管理智能助手。
你可以查阅已挂载的资料库，或者在必要时调用本地扫描与数据库工具来定位与操作文件。

### 可用工具一览（共 15 项）：
1. `scan_directory`：物理扫描磁盘目录并重新生成压缩文件树（宏观全景）。
2. `search_files`：在数据库中检索本地文件，支持自然语言语义模糊匹配、文件名搜索及文件后缀/体积过滤。
3. `read_file_content`：安全读取沙箱内指定文本文件的正文内容（单次限额 500 行或 30KB，可指定读 head/middle/tail）。若目标是文件夹，则自动罗列其子项结构。【⚠️ 受资产安全等级保护：读 2 级资产弹出确认，读 3 级资产强制需要用户输入主管理密码】。
4. `delete_file`：将指定名单的文件安全放入系统回收站。【⚠️ 破坏性操作说明：此操作无法通过撤销按钮自动还原，若需找回请用户在系统回收站中手动拾回】。
5. `move_file`：批量剪切/移动文件到沙箱内的新目录（源文件离开原路径）。【支持 overwrite 覆盖替换模式或 rename_to 换名模式；移入低安全等级目录时触发安全降级警报】。
6. `copy_file`：批量复制文件到沙箱内的新目录（源文件完好保留）。【支持 overwrite 覆盖替换模式或 rename_to 换名模式】。
7. `create_directory`：在沙箱内新建目录文件夹。
8. `write_file`：新建空文件/文本文件并写入正文内容（单次限额 5MB）。【支持 overwrite_name 规避冲突】。
9. `compress_files`：将指定文件或文件夹制作打包为 ZIP 压缩包。
10. `extract_archive`：解压 ZIP 压缩包（受 Zip Slip 路径穿越防御、压缩炸弹预检与软链接拦截保护）。
11. `find_duplicate_files`：查找具有相同哈希内容的重复文件。
12. `get_storage_insights`：获取全库存储空间透视与体检报告（按后缀分类及 Top10 巨石文件）。
13. `rename_file`：对特定文件或文件夹重命名。支持直接提供相对/绝对路径 `file_path` 或数据库 `file_id`。【遇同名冲突前置弹窗换名】。
14. `set_security_level`：调整特定文件或目录的安全等级（1=普通，2=敏感，3=机密）。【升为3级需密码；任何降级操作均会跳窗发出降级警告，原为3级降级需主密码】。
15. `locate_or_open_file`：在系统原生资源管理器中定位高亮文件或使用关联软件打开。

### 核心安全与业务决策准则（非常重要）：
1. **资产安全等级防护与调整准则 (Security Levels)**：
   - 系统的物理文件与目录分为三级：**1 级（普通，默认）**、**2 级（敏感，操作需确认）**、**3 级（机密高危，受主密码保护）**；
   - 文件夹设为 2/3 级时，其内部所有文件与子目录均动态继承该安全等级；
   - **读取 3 级文件（`read_file_content`）属于机密行为，必须强制验证密码**；
   - **调整安全等级（`set_security_level`）**：
     - 若将资产升级为 3 级（机密），系统强制验证主密码；
     - 若将 2 级或 3 级资产降低安全等级（如 3->1/2，或 2->1），系统会弹出严重降级警报，并要求确认（原为 3 级降级时强制验证主密码）；
     - 当用户要求更改安全等级时，请直接调用 `set_security_level`，严禁谎称无此能力。
2. **重命名操作规范（文件与文件夹通用）**：
   - 调用 `rename_file` 时，优先使用 `file_path` 传入文件或文件夹路径，无需事先搜索数字 ID；
   - 若遇到目标已存在同名资产，系统会自动挂起弹出换名窗口，不得强行使用破坏性覆盖。
3. **同名冲突与覆盖替换明确准则（区分覆盖与换名）**：
   - **“覆盖替换”与“重命名”是两种完全不同的物理操作**：
     - 若用户的指令意图是“还原”、“更新”、“覆写”或明确要求“覆盖已有同名文件”，在调用 `copy_file` 或 `move_file` 时显式将 `overwrite=True` 传入，系统会弹窗由用户输入主管理密码进行物理覆盖授权；
     - 若用户希望保留原有文件并以新名字存放，应通过 `rename_to` 传入新文件名；
     - 严禁在未确认用户意图时私自将“覆盖”篡改为“换名”，也严禁未征得同意执行盲目覆盖。
4. **破坏性删除与撤销边界准则**：
   - `delete_file` 会把文件放入系统回收站，并从数据库清理索引。向用户报告删除时，必须明确告知：“**文件已移入系统回收站。本系统不支持自动恢复，若误删请打开操作系统回收站/废纸篓手动拾回。**”
   - 系统界面顶栏的“↩ 撤销上一步”属于纯本地原子事务流水，由用户在前端直接点击触发，不经过 Agent 图调度。若你收到物理回滚通知，必须立刻采信回滚事实。
5. **用户拦截即绝对终结原则**：
   - 如果任何操作工具返回了包含“操作已被安全策略拦截”或“用户在界面端拒绝了该操作”的信息，**代表用户已经明确放弃或否决了该操作**。
   - **严禁擅自更换参数、更换文件后缀等任何方式再次暗中尝试该动作！** 立刻停止所有工具调用，向用户回复说明“操作已被您取消”。
"""


class PromptManager:
    """提示词上下文管理内核：负责物理工作区绝对锚定注入、常驻与临时资料库调度及原子事务历史管理。"""

    def __init__(self, system_prompt: str = DEFAULT_SYSTEM_PROMPT, max_history_rounds: int = 10, target_path: str = ""):
        self.system_prompt = system_prompt
        self.max_history_rounds = max_history_rounds
        self.target_path = os.path.normpath(os.path.abspath(target_path)) if target_path else self._detect_config_target_path()
        self.chat_history: List[BaseMessage] = []
        self._history_snapshot: Optional[List[BaseMessage]] = None
        self.temp_prompts: List[Dict[str, str]] = []
        self.persistent_prompts: List[Dict[str, Any]] = []

    def _detect_config_target_path(self) -> str:
        try:
            cfg_p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "config.json")
            if os.path.exists(cfg_p):
                with open(cfg_p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    tp = data.get("target_path", "")
                    if tp:
                        return os.path.normpath(os.path.abspath(tp))
        except Exception:
            pass
        return ""

    def update_target_path(self, target_path: str):
        if target_path:
            self.target_path = os.path.normpath(os.path.abspath(target_path))

    def set_system_prompt(self, text: str):
        self.system_prompt = text.strip() if text else DEFAULT_SYSTEM_PROMPT

    def reset_system_prompt(self):
        self.system_prompt = DEFAULT_SYSTEM_PROMPT

    # ==================== 常驻提示词与本地资料库 ====================

    def scan_and_load_data_prompts(self, data_dir: str, previously_enabled_paths: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        if previously_enabled_paths is None:
            previously_enabled_paths = [p["rel_path"] for p in self.persistent_prompts if p.get("enabled", False)]

        new_persistent: List[Dict[str, Any]] = []
        valid_extensions = {".txt", ".md", ".json", ".csv", ".py", ".yaml", ".yml", ".xml", ".html"}
        system_ignored_dirs = {"database", "lancedb", ".git", "__pycache__"}
        system_ignored_files = {"scan_result.json", "file_indexer.db", "asset_security_levels.json"}

        if os.path.exists(data_dir) and os.path.isdir(data_dir):
            for root, dirs, files in os.walk(data_dir):
                dirs[:] = [d for d in dirs if d not in system_ignored_dirs]

                for file_name in sorted(files):
                    if file_name in system_ignored_files:
                        continue

                    ext = os.path.splitext(file_name)[1].lower()
                    if ext in valid_extensions or "." not in file_name:
                        abs_p = os.path.join(root, file_name)
                        rel_p = os.path.relpath(abs_p, data_dir).replace("\\", "/")

                        parts = rel_p.split("/")
                        if any(p in system_ignored_dirs for p in parts):
                            continue

                        try:
                            with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read()
                        except Exception:
                            content = ""

                        is_enabled = rel_p in previously_enabled_paths
                        new_persistent.append({
                            "id": str(uuid.uuid4())[:8],
                            "rel_path": rel_p,
                            "abs_path": abs_p,
                            "content": content,
                            "enabled": is_enabled
                        })

        self.persistent_prompts = new_persistent
        return self.persistent_prompts

    def set_persistent_prompt_enabled(self, prompt_id: str, enabled: bool):
        for item in self.persistent_prompts:
            if item["id"] == prompt_id:
                item["enabled"] = enabled
                break

    # ==================== 临时提示词挂载管理 ====================

    def add_temp_prompt(self, title: str, content: str) -> str:
        prompt_id = str(uuid.uuid4())[:8]
        self.temp_prompts.append({
            "id": prompt_id,
            "title": title or f"临时规则_{len(self.temp_prompts) + 1}",
            "content": content
        })
        return prompt_id

    def upsert_temp_prompt(self, title: str, content: str, key: Optional[str] = None) -> str:
        effective_key = key or title
        for p in self.temp_prompts:
            if p.get("key") == effective_key or p.get("title") == title:
                p["title"] = title
                p["content"] = content
                p["key"] = effective_key
                return p["id"]
        prompt_id = str(uuid.uuid4())[:8]
        self.temp_prompts.append({
            "id": prompt_id,
            "key": effective_key,
            "title": title,
            "content": content
        })
        return prompt_id

    def update_temp_prompt(self, prompt_id: str, title: str, content: str) -> bool:
        for p in self.temp_prompts:
            if p["id"] == prompt_id:
                p["title"] = title.strip() or p["title"]
                p["content"] = content.strip()
                return True
        return False

    def remove_temp_prompt(self, prompt_id: str):
        self.temp_prompts = [p for p in self.temp_prompts if p["id"] != prompt_id]

    def move_temp_prompt(self, from_idx: int, to_idx: int):
        if 0 <= from_idx < len(self.temp_prompts) and 0 <= to_idx < len(self.temp_prompts):
            item = self.temp_prompts.pop(from_idx)
            self.temp_prompts.insert(to_idx, item)

    # ==================== 提示词注入汇编核心 ====================

    def get_full_system_instruction(self) -> str:
        parts = []

        current_work_root = self.target_path or self._detect_config_target_path() or "(未指定工作区)"
        root_anchor_instruction = (
            f"### 【当前授权物理工作区（沙箱根目录）】\n"
            f"- **当前工作区绝对路径（即本系统的唯一操作根）**: `{current_work_root}`\n"
            f"- **根目录基准原则**：\n"
            f"  1. 当用户提到“根目录”、“当前目录”或“工作区”时，100% 严格指代上述绝对路径。\n"
            f"  2. 严禁将操作系统的物理驱动器盘符（如 `C:\\`、`/`）当作本系统工作区根目录！\n"
            f"  3. 在工具调用参数中，可以直接传入相对于上述根目录的相对路径，系统会自动对齐沙箱。\n"
            f"  4. 遇到受保护的 2 级或 3 级文件时，严格等待系统安全弹窗授权，不得私自变更扩展名规避拦截。"
        )
        parts.append(root_anchor_instruction)
        parts.append(self.system_prompt)

        active_persistent = [p for p in self.persistent_prompts if p.get("enabled", False)]
        if active_persistent:
            parts.append("\n\n### 【已挂载的常驻基础资料库】\n说明：以下文件属于系统预加载的快照基准数据：")
            for idx, p in enumerate(active_persistent, 1):
                parts.append(f"\n[常驻文件 {idx}: {p['rel_path']}]\n{p['content']}")

        if self.temp_prompts:
            parts.append("\n\n### 【动态挂载的环境数据与临时指令】：")
            for idx, p in enumerate(self.temp_prompts, 1):
                parts.append(f"\n[{idx}. {p['title']}]\n{p['content']}")

        return "\n\n".join(parts)

    def get_instruction_hash(self) -> str:
        full_text = self.get_full_system_instruction()
        return hashlib.md5(full_text.encode("utf-8")).hexdigest()

    # ==================== 原子事务历史管理 ====================

    def begin_turn_transaction(self):
        self._history_snapshot = copy.deepcopy(self.chat_history)

    def rollback_turn_transaction(self):
        if self._history_snapshot is not None:
            self.chat_history = copy.deepcopy(self._history_snapshot)
            self._history_snapshot = None

    def commit_turn_transaction(self):
        self._history_snapshot = None
        self._safe_trim_history()

    def add_user_message(self, text: str, img_data: Optional[Dict[str, str]] = None):
        if img_data:
            content_block = [
                {"type": "text", "text": text},
                {"type": "image_url", "image_url": {"url": f"data:image/{img_data['mime']};base64,{img_data['base64']}"}}
            ]
            self.chat_history.append(HumanMessage(content=content_block))
        else:
            self.chat_history.append(HumanMessage(content=text))

    def add_assistant_message(self, text: str):
        if text:
            self.chat_history.append(AIMessage(content=text))

    def clear_history(self):
        self.chat_history.clear()
        self._history_snapshot = None

    def _safe_trim_history(self):
        max_messages = self.max_history_rounds * 4
        if len(self.chat_history) <= max_messages:
            return

        cut_idx = len(self.chat_history) - max_messages
        while cut_idx < len(self.chat_history):
            if isinstance(self.chat_history[cut_idx], HumanMessage):
                break
            cut_idx += 1

        if cut_idx >= len(self.chat_history):
            logger.warning("_safe_trim_history 未找到 HumanMessage 边界，放弃本次截断以保护上下文完整。")
            return

        self.chat_history = self.chat_history[cut_idx:]

    def record_undo_event(self, summary: str, affected_items: List[str], can_undo: bool):
        if self.chat_history and isinstance(self.chat_history[-1], ToolMessage):
            self.chat_history.append(AIMessage(content="操作执行已被中断或废弃。"))

        items_str = "\n".join([f"  - {it}" for it in affected_items]) if affected_items else "  - 见系统底层详细事务记录"
        undo_notification = (
            f"【物理事务原子回滚生效通知】\n"
            f"用户在控制台顶栏点击了“↩ 撤销上一步”，系统已在物理磁盘与本地数据库中完成了原子回转：\n"
            f"- 回滚摘要: {summary}\n"
            f"- 物理变动明细:\n{items_str}\n"
            f"- 回滚后流水栈状态: {'仍有更早的操作可继续撤回' if can_undo else '所有历史操作已全部撤回至会话初始状态'}\n"
            f"【注意】：上述被撤销生成的目标文件已从磁盘中抹除，被移走的文件已移回原位，SQLite、安全等级灾备清单与向量库已同步完成注销与修正。后续分析必须以当前回滚后的真实物理状态为准！"
        )

        self.chat_history.append(HumanMessage(content=undo_notification))
        self.chat_history.append(
            AIMessage(content=f"已确认感知物理回滚事实：{summary}。本地资产库与上下文索引已同步对齐。"))