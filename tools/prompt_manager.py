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

from core.chat_log_store import (
    ChatLogStore,
    DEFAULT_WINDOW_ROUNDS,
    resolve_size_warn_bytes,
    resolve_window_rounds,
)

logger = logging.getLogger("PromptManager")

# tools/prompt_manager.py

DEFAULT_SYSTEM_PROMPT = """你是一个专业的本地文件管理智能助手。
你可以查阅已挂载的资料库，或者在必要时调用本地扫描与数据库工具来定位与操作文件。

### 可用工具一览（共 15 项）：
1. `scan_directory`：物理扫描磁盘目录并重新生成压缩文件树（宏观全景）。
2. `search_files`：在数据库中检索本地文件，支持自然语言语义模糊匹配、文件名搜索及文件后缀/体积过滤。
3. `read_file_content`：安全读取沙箱内指定文本文件或目录的内容（单次限额 500 行或 30KB，可指定读 head/middle/tail）。
4. `delete_file`：将指定名单的文件安全放入系统回收站（破坏性操作不可撤回，需在系统回收站手动拾回）。
5. `move_file`：批量剪切/移动文件到沙箱内的新目录（支持 overwrite 覆盖或 rename_to 换名）。
6. `copy_file`：批量复制文件到沙箱内的新目录（源文件完好保留）。
7. `create_directory`：在沙箱内新建目录文件夹。
8. `write_file`：新建空文件/文本文件并写入正文内容（单次限额 5MB）。
9. `compress_files`：将指定文件或文件夹制作打包为 ZIP 压缩包。
10. `extract_archive`：解压 ZIP 压缩包（内置 Zip Slip 与压缩炸弹预检）。
11. `find_duplicate_files`：查找具有相同哈希内容的重复文件。
12. `get_storage_insights`：获取全库存储空间透视报告。
13. `rename_file`：对特定文件或文件夹重命名，支持直接提供路径 `file_path`。
14. `set_security_level`：调整文件或目录的安全等级（1=普通，2=敏感，3=机密）。
15. `locate_or_open_file`：在系统资源管理器中定位高亮文件或使用关联软件打开。

### 核心行为准则：
1. **静默执行原则（重点）**：
   - 系统的安全拦截、密码核验与敏感确认完全由**底层切面网关自动接管**并唤起前端模态框。
   - **严禁在回复中提前向用户长篇累牍地背诵或预警安全等级、密码要求或免责声明**。明确操作目标后直接调用相应工具，鉴权逻辑交由系统自然触发。
2. **高效简洁沟通**：
   - 当需要用户指定目标文件时，列出代表性条目即可，避免罗列过多冗余信息。
3. **同名冲突与覆盖规范**：
   - 区分“覆盖原有文件”与“换名存放”：用户明确要求覆盖时传入 `overwrite=True`；希望保留原文件并以新名字存放时传入 `rename_to`。
4. **安全拦截即停止**：
   - 工具若返回被用户拒绝或拦截，立刻停止后续尝试并向用户简明确认。
"""


class PromptManager:
    """提示词上下文管理内核：负责物理工作区绝对锚定注入、常驻与临时资料库调度及原子事务历史管理。"""

    def __init__(self, system_prompt: str = DEFAULT_SYSTEM_PROMPT,
                 max_history_rounds: int = DEFAULT_WINDOW_ROUNDS,
                 target_path: str = "", app_config: Optional[Dict[str, Any]] = None,
                 log_dir: Optional[str] = None):
        self.system_prompt = system_prompt
        # 窗口轮数：来自配置（可配置），不再是写死的常量
        self.max_history_rounds = (
            resolve_window_rounds(app_config) if app_config is not None else max_history_rounds
        )
        self.target_path = os.path.normpath(os.path.abspath(target_path)) if target_path else self._detect_config_target_path()
        self.chat_history: List[BaseMessage] = []
        # 【回滚标记】用"消息对象"而不是下标：即使内存窗口滚动过，也认得出本轮起点
        self._turn_marker: Optional[BaseMessage] = None
        self._turn_marker_index: Optional[int] = None
        self.temp_prompts: List[Dict[str, str]] = []
        self.persistent_prompts: List[Dict[str, Any]] = []

        # 【记录落盘】完整记录写本地文件，内存只保留窗口范围内的内容
        self.chat_store = ChatLogStore(
            log_dir=log_dir or self._default_log_dir(),
            size_warn_bytes=resolve_size_warn_bytes(app_config),
        )
        self.last_window_dropped = 0
        self.size_warning: str = ""

    def _default_log_dir(self) -> str:
        """记录目录：默认 <项目根>/data/chat/（测试可整体覆盖，见 chat_log_store）。"""
        from core.chat_log_store import default_chat_log_dir

        return default_chat_log_dir()

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

    # ==================== 回合事务与记录落盘 ====================

    def _remember(self, messages: List[BaseMessage]):
        """把消息**同时**写进记录文件与内存。

        文件保存完整内容、永不删减；内存只保留窗口范围内的最近若干轮。
        窗口滚动只影响内存，**绝不动文件**。
        """
        if not messages:
            return
        try:
            self.chat_store.append_messages(list(messages))
        except Exception as e:
            # 落盘失败不能影响对话本身；如实记下来即可
            logger.error(f"对话记录落盘失败: {e}")

        self.chat_history.extend(messages)
        self._apply_window()
        self._refresh_size_warning()

    def _apply_window(self):
        """把内存里的记录裁剪到窗口范围内（只在内存发生）。

        【就地把窗口外的消息从头部移除】不重新赋值整个列表：
        重新赋值会丢掉列表自身的类型/包装，也会让任何持有引用的观察者失联。
        """
        drop = self.chat_store.window_drop_count(self.chat_history, self.max_history_rounds)
        self.last_window_dropped = drop
        if drop > 0:
            del self.chat_history[:drop]

    def reapply_window(self, window_rounds: Optional[int] = None) -> int:
        """按（可能是新的）窗口轮数**立刻**重裁内存，返回丢弃条数。

        【为什么需要】裁剪此前只在"下一条消息到来时"发生。于是用户在设置里
        把窗口从 50 调小到 3 之后，内存里已有的那些旧消息会一直留着，
        界面也就一直显示旧内容——要等到他再发一句话才生效。
        设置保存时调用本方法，改动即可实时生效。
        """
        if window_rounds is not None:
            self.max_history_rounds = max(1, int(window_rounds))
        before = len(self.chat_history)
        self._apply_window()
        return before - len(self.chat_history)

    def _refresh_size_warning(self):
        """记录文件超过阈值时**只告警一次**，不做任何其它行为。"""
        try:
            if self.chat_store.should_warn_size():
                mb = self.chat_store.size_bytes() / (1024 * 1024)
                self.size_warning = (
                    f"当前对话记录文件已超过 {mb:.1f}MB（阈值 "
                    f"{self.chat_store.size_warn_bytes / (1024 * 1024):.0f}MB）。"
                    f"记录不会被删减或压缩；如需控制体积，建议新建对话。"
                )
                logger.warning(self.size_warning)
        except Exception:
            pass

    def begin_turn_transaction(self):
        """标记本轮的起点：**本轮用户消息之前**的那条消息。

        只记一个"标记"，**不再整份深拷贝聊天记录**——那会让每轮开始与回滚
        都要复制一次完整历史，记录越大越慢（这正是收尾会卡住的根源）。

        【标记为什么必须在用户消息之前】
        回滚的语义是"这一轮从没发生过"，因此要连**本轮的提问**一起丢掉；
        否则提问会留下来变成一条没有回答的孤儿消息，下一轮模型会看到
        "我问了但没答"的错误上下文。

        实现上同时记"下标 + 消息对象"：窗口滚动会让下标失效，
        而下标能覆盖"本轮是历史第一条消息、之前没有任何消息"的情况
        （此时没有对象可指，只能靠下标）。
        """
        self._turn_marker = self.chat_history[-1] if self.chat_history else None
        self._turn_marker_index = len(self.chat_history)

    def rollback_turn_transaction(self):
        """丢弃本轮产生的消息（从标记处截断）。不动物理记录文件。"""
        marker = self._turn_marker
        marker_idx = getattr(self, "_turn_marker_index", None)
        self._turn_marker = None
        self._turn_marker_index = None

        if marker is None:
            # 本轮是历史的第一条消息：整段内存都归本轮所有 → 清空内存。
            # 文件内容不受影响（完整记录仍在记录文件里）。
            if marker_idx == 0:
                self.chat_history.clear()
            return

        for i, m in enumerate(self.chat_history):
            if m is marker:
                # 截断掉标记**之后**的内容（含本轮的提问）
                del self.chat_history[i + 1:]
                return

        # 标记已被内存窗口滚出去：说明本轮残留全在内存里，直接清空。
        # 文件内容不受影响。
        self.chat_history.clear()

    def commit_turn_transaction(self):
        self._turn_marker = None
        self._apply_window()
        self._refresh_size_warning()

    def add_user_message(self, text: str, img_data: Optional[Dict[str, str]] = None):
        if img_data:
            content_block = [
                {"type": "text", "text": text},
                {"type": "image_url", "image_url": {"url": f"data:image/{img_data['mime']};base64,{img_data['base64']}"}}
            ]
            self._remember([HumanMessage(content=content_block)])
        else:
            self._remember([HumanMessage(content=text)])

    def add_assistant_message(self, text: str):
        if text:
            self._remember([AIMessage(content=text)])

    def add_generated_messages(self, messages: List[BaseMessage]):
        """本轮跑完后把模型/工具产生的消息写进记录与内存。"""
        self._remember(list(messages))

    def load_history_from_disk(self, path: Optional[str] = None):
        """从记录文件载入窗口视图（只读尾部，不把整个文件读进内存）。

        【每次启动新开一份对话（除非最新那份本来就是空的）】
        这满足"每次打开就是一次新对话"的直觉，同时避免启动一次就多一个空文件：
        若最近那份记录一条消息都没有，就直接续用它。

        【必须把解析到的路径写回 chat_store】此前只在显式传 path 时才回写，
        于是"续接最近一份对话记录"这条分支虽然读到了内容，
        `chat_store.path` 却仍是空 —— 后续追加会**新建一个文件**，
        历史被劈成两份、状态接口也报不出文件名。
        """
        if path:
            target = path
        else:
            latest = self.chat_store.latest_log()
            if latest:
                try:
                    self.chat_store.path = latest
                    if self.chat_store.total_messages() == 0:
                        target = latest          # 最新那份还是空的：直接续用
                    else:
                        target = self.chat_store.start_new_log()
                except Exception:
                    target = self.chat_store.start_new_log()
            else:
                target = self.chat_store.start_new_log()

        self.chat_store.path = target
        window = self.chat_store.load_window(self.max_history_rounds)
        self.chat_history = window.messages
        self.last_window_dropped = window.dropped
        self._refresh_size_warning()

    def clear_history(self):
        """清空 = 开新对话：新建一份记录文件并清空内存。旧文件原地保留。"""
        self.chat_history.clear()
        self._turn_marker = None
        self.last_window_dropped = 0
        self.size_warning = ""
        self.chat_store.start_new_log()

    def history_status(self) -> Dict[str, Any]:
        """给前端的对话记录状态（窗口内条数、未载入内存的条数、文件体积）。

        ``dropped`` 是**文件总条数 - 内存条数**，即"更早还有多少条没显示"。
        注意不能直接用最近一次窗口滚动的条数：那一项只反映最后一次裁剪，
        而界面要的是累计缺口。
        """
        total = 0
        try:
            total = self.chat_store.total_messages()
        except Exception:
            total = len(self.chat_history)
        return {
            "log_file": os.path.basename(self.chat_store.path) if self.chat_store.path else "",
            "in_window": len(self.chat_history),
            "dropped": max(0, total - len(self.chat_history)),
            "total_messages": total,
            "size_bytes": self.chat_store.size_bytes(),
            "window_rounds": self.max_history_rounds,
            "warning": self.size_warning,
        }

    def record_undo_event(self, summary: str, affected_items: List[str], can_undo: bool):
        extra = []
        if self.chat_history and isinstance(self.chat_history[-1], ToolMessage):
            extra.append(AIMessage(content="操作执行已被中断或废弃。"))

        items_str = "\n".join([f"  - {it}" for it in affected_items]) if affected_items else "  - 见系统底层详细事务记录"
        undo_notification = (
            f"【物理事务原子回滚生效通知】\n"
            f"用户在控制台顶栏点击了“↩ 撤销上一步”，系统已在物理磁盘与本地数据库中完成了原子回转：\n"
            f"- 回滚摘要: {summary}\n"
            f"- 物理变动明细:\n{items_str}\n"
            f"- 回滚后流水栈状态: {'仍有更早的操作可继续撤回' if can_undo else '所有历史操作已全部撤回至会话初始状态'}\n"
            f"【注意】：上述被撤销生成的目标文件已从磁盘中抹除，被移走的文件已移回原位，SQLite、安全等级灾备清单与向量库已同步完成注销与修正。后续分析必须以当前回滚后的真实物理状态为准！"
        )

        extra.append(HumanMessage(content=undo_notification))
        extra.append(AIMessage(content=f"已确认感知物理回滚事实：{summary}。本地资产库与上下文索引已同步对齐。"))
        self._remember(extra)