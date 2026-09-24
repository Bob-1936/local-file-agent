# server.py
# -*- coding: utf-8 -*-

import os
import json
import time
import base64
import asyncio
import logging
import tempfile
import threading
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple, AsyncGenerator
from contextlib import asynccontextmanager, suppress

import requests
from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from langchain_core.messages import AIMessage, ToolMessage, HumanMessage

from core.security import SecurityManager, AssetSecurityManager
from core.chat_log_store import (
    ChatLogStore,
    resolve_size_warn_bytes,
    resolve_window_rounds,
)
from core.model_factory import create_chat_model
from core.tokenizer import count_text_tokens, count_image_tokens, format_token_count
from core.agent_graph_web import build_web_file_agent_graph, WebThinkingStreamParser
from tools.tool_contract import all_path_field_names
from tools.prompt_manager import PromptManager, DEFAULT_SYSTEM_PROMPT
from tools.file_manager_tool import FileManagerTool
from tools.agent_tools_web import get_web_agent_tools

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
DATA_DIR = os.path.join(BASE_DIR, "data")
WEB_DIR = os.path.join(BASE_DIR, "web")
API_CONFIG_FILE = os.path.join(CONFIG_DIR, "API_config.json")
APP_CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
FAST_CHAT_FILE = os.path.join(CONFIG_DIR, "fast_chat.json")

MAX_UPLOAD_SIZE = 15 * 1024 * 1024

# 库模块不得在 import 期调用 logging.basicConfig() 强行设定宿主进程日志级别，
# 只保留自己的 logger，跟随宿主/框架配置（与 core/indexer_engine.py 的约定一致）。
logger = logging.getLogger("Server")

os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(WEB_DIR, exist_ok=True)

global_undo_lock = asyncio.Lock()

PLATFORM_PRESETS = {
    "DeepSeek": {
        "url": "https://api.deepseek.com/chat/completions",
        "models_url": "https://api.deepseek.com/models",
        "type": "openai"
    },
    "OpenAI": {
        "url": "https://api.openai.com/v1/chat/completions",
        "models_url": "https://api.openai.com/v1/models",
        "type": "openai"
    },
    "Anthropic (Claude)": {
        "url": "https://api.anthropic.com/v1/messages",
        "models_url": "https://api.anthropic.com/v1/models",
        "type": "claude"
    },
    "Google Gemini": {
        "url": "https://generativelanguage.googleapis.com/v1beta/models",
        "models_url": "https://generativelanguage.googleapis.com/v1beta/models",
        "type": "gemini"
    },
    "月之暗面 (Kimi)": {
        "url": "https://api.moonshot.cn/v1/chat/completions",
        "models_url": "https://api.moonshot.cn/v1/models",
        "type": "openai"
    },
    "阿里通义千问 (DashScope)": {
        "url": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        "models_url": "https://dashscope.aliyuncs.com/compatible-mode/v1/models",
        "type": "openai"
    },
    "智谱 AI (GLM)": {
        "url": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        "models_url": "https://open.bigmodel.cn/api/paas/v4/models",
        "type": "openai"
    },
    "硅基流动 (SiliconFlow)": {
        "url": "https://api.siliconflow.cn/v1/chat/completions",
        "models_url": "https://api.siliconflow.cn/v1/models",
        "type": "openai"
    },
    "本地 Ollama": {
        "url": "http://localhost:11434/v1/chat/completions",
        "models_url": "http://localhost:11434/v1/models",
        "type": "openai"
    },
    "自定义端点 (高级)": {
        "url": "",
        "models_url": "",
        "type": "openai"
    }
}


def _keep_only_complete_tool_turns(messages: List[Any]) -> List[Any]:
    result: List[Any] = []
    i = 0
    n = len(messages)
    while i < n:
        m = messages[i]
        if isinstance(m, AIMessage) and getattr(m, "tool_calls", None):
            needed_ids = {tc.get("id") for tc in m.tool_calls if tc.get("id")}
            j = i + 1
            collected: List[ToolMessage] = []
            found_ids = set()
            while j < n and isinstance(messages[j], ToolMessage):
                tm = messages[j]
                if tm.tool_call_id in needed_ids:
                    collected.append(tm)
                    found_ids.add(tm.tool_call_id)
                j += 1
            if needed_ids and needed_ids.issubset(found_ids):
                result.append(m)
                result.extend(collected)
            i = j
        else:
            result.append(m)
            i += 1
    return result


def _classify_abort_timeout(session: "SessionContext", abort_res: dict) -> str:
    """中止等待超时后的处置：**先分清原因**，再决定是"提醒"还是"告警"。

    按约定：
      · 记录过大导致的慢  → 返回一句给用户看的提醒（**不中断**，本轮照常开始）；
      · 其他原因导致的慢  → 不返回任何用户可见文案，只写日志告警
        （用户对此无从处理，弹提示只会造成干扰）。

    无论哪种情况，函数本身**不改变任何行为**——不删除、不裁剪、
    不阻止本轮开始。被放弃的旧回合由保留的中止标志挡住，不会写入记录。
    """
    waited = float(abort_res.get("waited") or 0.0)
    try:
        status = session.prompt_mgr.history_status()
        size_bytes = int(status.get("size_bytes") or 0)
        window = int(status.get("window_rounds") or 0)
    except Exception:
        return ""

    # 判据：记录文件本身已经不小（说明"慢"可以用记录体积解释）
    large_threshold = 8 * 1024 * 1024  # 8MB
    if size_bytes >= large_threshold:
        mb = size_bytes / (1024 * 1024)
        return (
            f"⚠️ 上一轮收尾耗时超过 {waited:.1f} 秒（当前对话记录约 {mb:.1f}MB，"
            f"窗口 {window} 轮）。本次不会中断；若这种情况反复出现，"
            f"建议新建对话以减小记录体积。"
        )

    logger.warning(
        f"上一轮收尾超过 {abort_res.get('waited', 0):.1f}s 仍未确认结束，"
        f"且记录体积仅 {size_bytes / 1024:.1f}KB —— 不是『记录过大』能解释的原因，"
        f"请排查是否有线程/锁长时间占用。旧回合已被挡住，不会写入对话记录。"
    )
    return ""


def _collect_involved_asset_paths(
        file_tool: "FileManagerTool",
        candidate_inputs: List[str],
        target_root: str
) -> Tuple[List[str], List[dict]]:
    """把工具入参中的候选路径聚合为"参与安全等级评估"的资产路径清单。

    【SEC-04 修复 · 从 `_async_security_intercept` 闭包中抽出以便直接测试】
    旧实现在闭包内写死为：

        resolved_p = records[0][1] if records else f_str
        involved_paths.append(resolved_p)

    解析失败时会把**原始入参**当作已确认的资产路径塞进 `involved_paths`。于是
    `E:/secret/x.txt` 这类越界/不存在的字符串会进入 `evaluate_action_with_assets`，
    而 `AssetSecurityManager.get_effective_level()` 又会把它当成"相对工作区路径"
    继续解析，从而污染 2/3 级资产判定与弹窗元数据。

    现在的纪律：**只有位于沙箱内的路径才有资格参与安全等级评估**。越界或命中黑名单的
    候选值被隔离到 `rejected_meta`，仅用于前端展示，绝不进入 `involved_paths`。

    :return: (involved_paths, items_meta)，items_meta 含被拒绝项（带 rejected 标记）
    """
    involved_paths: List[str] = []
    raw_items_meta: List[dict] = []

    for f_str in candidate_inputs:
        records = file_tool._resolve_file_records(f_str)
        is_safe, verified = file_tool._verify_sandbox_path(f_str)

        if records:
            resolved_p = records[0][1]
        elif is_safe:
            # 尚未入库但确实位于沙箱内（例如即将创建的新文件）：允许作为候选路径
            resolved_p = verified
        else:
            # 越界或黑名单：完全不参与安全评估，仅保留原始值用于展示
            logger.warning("安全切面：已忽略越界/不可解析的候选路径 %r（%s）", f_str, verified)
            raw_items_meta.append({
                "path": str(f_str),
                "is_dir": str(f_str).endswith('/') or str(f_str).endswith('\\'),
                "security_level": 1,
                "rejected": True,
                "reject_reason": verified,
            })
            continue

        involved_paths.append(resolved_p)

        if os.path.exists(resolved_p):
            is_d = os.path.isdir(resolved_p)
        else:
            is_d = str(f_str).endswith('/') or str(f_str).endswith('\\')

        eff_lvl = file_tool.asset_sec_mgr.get_effective_level(resolved_p, target_root)
        raw_items_meta.append({"path": resolved_p, "is_dir": is_d, "security_level": eff_lvl})

    return involved_paths, raw_items_meta


def _dedupe_keep_order(items: List[str]) -> List[str]:
    """去重但保留首次出现顺序"""
    seen = set()
    out: List[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


class HITLPendingItem:
    def __init__(self, action_name: str, reason: str, params: dict, level: str,
                 raw_items: List[dict] = None, is_conflict: bool = False,
                 is_downgrade: bool = False, max_asset_level: int = 1):
        self.action_name = action_name
        self.reason = reason
        self.params = params
        self.level = level
        self.raw_items = raw_items or []
        self.is_conflict = is_conflict
        self.is_downgrade = is_downgrade
        self.max_asset_level = max_asset_level
        self.decision: Dict[str, Any] = {
            "authorized": False,
            "skip_this_session": False,
            "exempt_this_tool": False,
            "effective_params": params
        }
        self.event = asyncio.Event()


class SessionContext:
    def __init__(self, session_id: str, app_config: dict):
        self.session_id = session_id
        target_path = app_config.get("target_path", os.path.expanduser("~"))
        # 【记录落盘】窗口轮数与记录体积阈值都来自配置（可配置，不再是写死的常量）
        self.prompt_mgr = PromptManager(target_path=target_path, app_config=app_config)
        # 续接最近一份对话记录，内存里只装窗口范围内的内容
        self.prompt_mgr.load_history_from_disk()
        self.file_tool = FileManagerTool(APP_CONFIG_FILE)
        self.async_abort_event: asyncio.Event = asyncio.Event()
        self.thread_abort_event: threading.Event = threading.Event()
        self.current_hitl_item: Optional[HITLPendingItem] = None
        self.current_runner_task: Optional[asyncio.Task] = None
        # 【P0-1 修复】同一会话的请求串行化锁。见 agent_sse_generator 中的说明。
        self.turn_lock: asyncio.Lock = asyncio.Lock()
        self.prompt_mgr.scan_and_load_data_prompts(DATA_DIR, app_config.get("enabled_persistent_files", []))

    def reset_abort(self):
        self.async_abort_event.clear()
        self.thread_abort_event.clear()

    def abort(self):
        self.async_abort_event.set()
        self.thread_abort_event.set()
        if self.current_hitl_item:
            self.current_hitl_item.event.set()
        if self.current_runner_task and not self.current_runner_task.done():
            self.current_runner_task.cancel()

    async def abort_and_wait(self, timeout: float = 5.0) -> dict:
        """中止当前回合并**等待其真正结束**。

        【返回】不再只回一个 bool，而是如实回一份结果：
          - ``confirmed``：是否**确认**旧回合已经结束（True 才允许清中止标志）
          - ``had_runner``：此前是否有正在执行的回合
          - ``timed_out``：是否等超时了（即**没能确认**结束）
          - ``waited``：实际等待秒数

        【P0-1 修复的关键】只有在**确认**旧回合已结束、或本来就没有旧回合时，
        才清除"正在中止"的标志。一旦超时（说明没能确认），**绝不清除**：

        旧回合的收尾代码是**同步**的、中间没有 await，所以它一旦开始收尾
        就会一路跑到底；而它的收尾会先看一眼这个中止标志来决定
        "走被中止的分支（不写记录）"还是"走成功分支（把自己写进记录）"。
        过去超时后无条件清掉标志，等于通知被放弃的那一轮"没人取消你了"，
        于是它照常把自己写进历史——这正是"被中止的回合仍然落在记录里"的成因。

        不清标志的副作用是零：它只影响"被中止回合的收尾走哪个分支"，
        新回合会在自己开始时重新评估，不需要这个标志是干净的。
        """
        started = time.monotonic()
        had_runner = self.current_runner_task is not None
        self.abort()
        runner = self.current_runner_task
        timed_out = False

        if runner is None or runner.done():
            return self._finish_abort(had_runner=had_runner, timed_out=False,
                                      waited=time.monotonic() - started)

        # 【为什么不用 asyncio.wait_for + shield】
        # `wait_for` 在超时时会**先取消被等待对象、再等它真的结束**，然后才抛超时；
        # 若对方抗取消（收尾里 swallowed CancelledError 或长同步段），
        # `wait_for` 会**永远挂住**——超时形同虚设，连上报的机会都没有。
        # `asyncio.wait` 到点直接返回 pending 集合，不会替我们取消，也不会挂住。
        done, _pending = await asyncio.wait({runner}, timeout=timeout)
        if runner not in done:
            timed_out = True

        return self._finish_abort(had_runner=had_runner, timed_out=timed_out,
                                  waited=time.monotonic() - started)

    def _finish_abort(self, had_runner: bool, timed_out: bool, waited: float) -> dict:
        if timed_out:
            # 【不清理】标志保留，旧回合的收尾会因此走"不写记录"的分支。
            # 引用也保留，以便后续仍能取消/等待它。
            logger.warning(
                f"中止未能确认完成：等待 {waited:.2f}s 后旧回合仍未退出。"
                f"已保留中止标志（旧回合不会写入对话记录），未放弃对其的引用。"
            )
            return {
                "confirmed": False, "had_runner": had_runner,
                "timed_out": True, "waited": waited,
            }
        self.current_runner_task = None
        self.current_hitl_item = None
        self.reset_abort()
        return {
            "confirmed": True, "had_runner": had_runner,
            "timed_out": False, "waited": waited,
        }


class AppStateManager:
    def __init__(self):
        self.app_config: Dict[str, Any] = {
            "theme": "dark",
            "target_path": os.path.expanduser("~"),
            "max_depth": 3,
            "blacklist_paths": [],
            "tool_token_warning_threshold": 10000,
            "enabled_persistent_files": [],
            # 对话记录：内存窗口轮数 与 记录文件体积告警阈值（MB）
            "chat_history_window_rounds": 50,
            "chat_log_size_warn_mb": 100,
            "security": {
                "master_password_hash": "",
                "master_password_salt": "",
                "permanent_skip_sensitive": False,
                "permanent_skip_destructive": False
            }
        }
        self.api_profiles: Dict[str, Any] = {}
        self.current_api_profile: str = ""
        self.fast_chats: List[Dict[str, str]] = []
        self.sessions: Dict[str, SessionContext] = {}

        self.load_all_configs()
        self.sec_mgr = SecurityManager(self.app_config, save_config_callback=self.save_app_config)

    def load_all_configs(self):
        if os.path.exists(API_CONFIG_FILE):
            try:
                with open(API_CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.api_profiles = data.get("profiles", {})
                    self.current_api_profile = data.get("current_profile", "")
            except Exception:
                pass

        if os.path.exists(APP_CONFIG_FILE):
            try:
                with open(APP_CONFIG_FILE, "r", encoding="utf-8") as f:
                    self.app_config.update(json.load(f))
            except Exception:
                pass

        if os.path.exists(FAST_CHAT_FILE):
            try:
                with open(FAST_CHAT_FILE, "r", encoding="utf-8") as f:
                    self.fast_chats = json.load(f)
            except Exception:
                pass
        else:
            self.fast_chats = [
                {"title": "扫描全景", "content": "请对当前目录发起物理扫描，重新构建最新的宏观全景文件树。"},
                {"title": "检索代码", "content": "请在数据库中检索包含核心业务逻辑的 Python 代码文件。"},
                {"title": "新建目录", "content": "帮我在当前工作区新建一个名为 'workspace_test' 的文件夹。"},
                {"title": "存储透视", "content": "请分析当前磁盘的存储占用透视报告，告诉我哪些类型文件最占空间。"}
            ]
            self.save_fast_chats()

    def save_app_config(self):
        with open(APP_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(self.app_config, f, ensure_ascii=False, indent=2)

    def save_api_config(self):
        with open(API_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump({"current_profile": self.current_api_profile, "profiles": self.api_profiles}, f,
                      ensure_ascii=False, indent=2)

    def save_fast_chats(self):
        with open(FAST_CHAT_FILE, "w", encoding="utf-8") as f:
            json.dump(self.fast_chats, f, ensure_ascii=False, indent=2)

    def get_session(self, session_id: str) -> SessionContext:
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionContext(session_id, self.app_config)
        return self.sessions[session_id]


state_mgr = AppStateManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    default_session = state_mgr.get_session("default")
    async def _startup_tasks():
        try:
            await asyncio.to_thread(default_session.file_tool.core.clear_operation_journal)
            await asyncio.to_thread(default_session.file_tool.sync_database)
            # 【D1 修复】从灾备真相源重建派生的 files.security_level 列。
            # 必须在 sync_database 之后执行：同步会新增/软删除记录，
            # 重建需要覆盖最终的行集合。重建后该列与 get_effective_level()
            # 读数一致，可被 SQL 消费者安全使用。
            fixed = await asyncio.to_thread(
                default_session.file_tool.core.recompute_effective_security_levels
            )
            v_res = await asyncio.to_thread(default_session.file_tool.build_vector_index)
            # 【确定性失败的处理】向量构建现在不再抛异常而是返回结果；
            # 这里必须检查，否则会先打印"已对齐"，把"模型不可用导致未构建"说成成功。
            if isinstance(v_res, dict) and not v_res.get("success"):
                print(f"[-] 启动自愈：向量索引未完成 —— {v_res.get('message')}")
            else:
                print(f"[启动自愈] 会话撤销流水已重置，SQLite 资产与 LanceDB 向量索引已对齐，"
                      f"安全等级派生列已重建（修正 {fixed} 行）。")
        except Exception as e:
            print(f"[-] 启动自愈异常: {e}")

    asyncio.create_task(_startup_tasks())
    yield
    for s in state_mgr.sessions.values():
        s.abort()
    state_mgr.sessions.clear()


app = FastAPI(
    title="Local File Agent API (2026 Web Security Edition)",
    description="工业级 LangGraph 异步流式本地资产智能体与三级安全网关",
    version="2.5.0",
    lifespan=lifespan
)

# 【BUG-17 修复】本服务只监听 127.0.0.1（见 run_web.py），属于零鉴权的本地管理接口。
# 原先 allow_origins=["*"] + allow_credentials=True 会把任意第三方网页纳入跨源白名单
# （实测回显 evil.example 并允许凭证），等于任意网页都能驱动本地管理接口。
# 现收窄为显式列举的本机来源；若将来引入统一 token 鉴权，应连同本清单一起重新设计。
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1", "http://localhost",
        "http://127.0.0.1:8000", "http://localhost:8000",
        "http://127.0.0.1:8080", "http://localhost:8080",
        "http://127.0.0.1:9000", "http://localhost:9000",
    ],
    allow_origin_regex=r"^https?://(127\.0\.0\.1|localhost)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SendChatRequest(BaseModel):
    session_id: str = Field(default="default")
    message: str = Field(description="用户提问内容")
    image_base64: Optional[str] = Field(default=None)
    image_mime: Optional[str] = Field(default="jpeg")


class HITLResumeRequest(BaseModel):
    session_id: str = Field(default="default")
    authorized: bool = Field(description="用户是否批准该操作")
    password: Optional[str] = Field(default="")
    skip_this_session: Optional[bool] = Field(default=False)
    exempt_this_tool: Optional[bool] = Field(default=False)
    conflict_action: Optional[str] = Field(default="rename", description="冲突策略: rename (重命名) 或 overwrite (覆盖替换)")
    new_name: Optional[str] = Field(default=None, description="同名冲突时用户指定的新名称")


class UpdateSecurityLevelsRequest(BaseModel):
    session_id: str = Field(default="default")
    items: List[Dict[str, Any]] = Field(description="待设置资产列表，每项包含 path 与 is_dir")
    target_level: int = Field(description="设定的目标等级: 1(普通), 2(敏感), 3(机密)")
    password: Optional[str] = Field(default=None, description="涉及 3 级机密资产（升为 3 级 / 将 3 级降级）时必填的主管理密码")


class SaveSecurityPolicyRequest(BaseModel):
    policy: Dict[str, Any]


class UpdateSystemPromptRequest(BaseModel):
    session_id: str = Field(default="default")
    prompt: str


class AddTempPromptRequest(BaseModel):
    session_id: str = Field(default="default")
    title: str
    content: str


class UpdateTempPromptRequest(BaseModel):
    session_id: str = Field(default="default")
    prompt_id: str
    title: str
    content: str


class ReorderTempPromptRequest(BaseModel):
    session_id: str = Field(default="default")
    src_idx: int
    dest_idx: int


class TogglePersistentPromptRequest(BaseModel):
    session_id: str = Field(default="default")
    prompt_id: str
    enabled: bool


class SaveApiProfileRequest(BaseModel):
    name: str
    data: Dict[str, Any]


class FetchModelsRequest(BaseModel):
    platform: str
    url: Optional[str] = ""
    key: Optional[str] = ""
    profile_name: Optional[str] = None


class SaveScanConfigRequest(BaseModel):
    target_path: str
    max_depth: int
    blacklist_paths: List[str]
    tool_token_warning_threshold: Optional[int] = 10000
    new_password: Optional[str] = None
    old_password: Optional[str] = None
    permanent_skip_sensitive: bool = False
    permanent_skip_destructive: bool = False
    # 对话记录：窗口轮数 与 记录体积告警阈值（MB）——均可在设置里配置
    chat_history_window_rounds: Optional[int] = None
    chat_log_size_warn_mb: Optional[float] = None


class ChatLogSwitchRequest(BaseModel):
    name: str = Field(..., description="要接续的记录文件名（来自列表接口）")


class ChatLogDeleteRequest(BaseModel):
    name: str = Field(..., description="要删除的记录文件名（来自列表接口）")


class SaveFastChatsRequest(BaseModel):
    fast_chats: List[Dict[str, str]]


class UpdatePasswordRequest(BaseModel):
    old_password: Optional[str] = None
    new_password: str


class UpdateThemeRequest(BaseModel):
    theme: str


def sse_pack(event: str, data: Any) -> str:
    data_str = json.dumps(data, ensure_ascii=False)
    return f"event: {event}\ndata: {data_str}\n\n"


def _sanitized_app_config() -> Dict[str, Any]:
    """对外返回的配置副本：剔除主密码散列与盐等本地鉴权机密，绝不随响应下发。

    （与同一接口特意剥离 API Key 的做法保持一致；这是 BUG-16 的修复点）
    """
    cfg = dict(state_mgr.app_config)
    sec = dict(cfg.get("security") or {})
    for secret_key in ("master_password_hash", "master_password_salt"):
        sec.pop(secret_key, None)
    cfg["security"] = sec
    return cfg


async def direct_emit_text(queue: asyncio.Queue, event_name: str, text: str):
    if not text:
        return
    chunk_size = 40
    for i in range(0, len(text), chunk_size):
        chunk = text[i:i + chunk_size]
        await queue.put(sse_pack(event_name, chunk))
        await asyncio.sleep(0.001)


async def agent_sse_generator(req: SendChatRequest) -> AsyncGenerator[str, None]:
    session = state_mgr.get_session(req.session_id)

    # 【P0-1 修复】同一会话内串行化：先等旧回合**真正结束**，再开启新回合。
    # 等待结果如实区分三种情况（见 SessionContext.abort_and_wait）：
    #   · 确认结束        → 正常开始本轮；
    #   · 超时但记录过大  → **提醒用户，但不中断**（开新对话即可缓解）；
    #   · 超时且是别的原因 → **告警**（只记日志，用户无从处理，不打扰）。
    # 无论哪种情况，被放弃的旧回合都不会再写入对话记录（中止标志被保留）。
    async with session.turn_lock:
        abort_res = await session.abort_and_wait()
        if abort_res.get("timed_out"):
            warn = _classify_abort_timeout(session, abort_res)
            if warn:
                yield sse_pack("notice", warn)

        current_prof_name = state_mgr.current_api_profile
        if not current_prof_name or current_prof_name not in state_mgr.api_profiles:
            yield sse_pack("error", "未配置或未选中大模型 API，请前往右上角设置配置！")
            return

        profile_cfg = state_mgr.api_profiles[current_prof_name]
        platform_name = profile_cfg.get("platform", "DeepSeek")

        session.prompt_mgr.begin_turn_transaction()

        img_data = None
        if req.image_base64:
            img_data = {"base64": req.image_base64, "mime": req.image_mime or "jpeg"}
        session.prompt_mgr.add_user_message(req.message, img_data=img_data)

    event_queue: asyncio.Queue[Optional[str]] = asyncio.Queue()

    async def _async_security_intercept(act_name: str, act_params: dict) -> Tuple[bool, str, dict]:
        """
        严谨的全工具安全切面拦截：
        - 覆盖所有入参中的资产路径（包括 parent_path / target_dir 等）；
        - 实时从全局唯一 AssetSecurityManager 读取最新等级；
        - 命中 2/3 级受控资产时强制阻断并触发 HITL 确认/密码校验。
        """
        effective_params = dict(act_params)
        raw_items_meta = []
        is_conflict = False
        is_downgrade = False
        target_root = session.file_tool.core.config.target_path

        involved_paths: List[str] = []

        fid = effective_params.get("file_id")
        if fid is not None and str(fid).strip() != "":
            records = session.file_tool._resolve_file_records(fid)
            if records:
                involved_paths.append(records[0][1])

        # 【阶段3 第1步】"哪些入参承载资产路径"的契约已收敛到工具层单一来源
        # （tools/tool_contract.py）。此前这里是**手抄的字段名清单**，
        # 而 rename_to / new_name / overwrite_name 三个"隐性目标路径"曾经漏在外面，
        # 导致重命名/覆盖类操作指向的 2/3 级资产完全不参与安全判定（BUG-02/03 深层成因）。
        # 现在改为从工具注册表推导，并由测试校验"工具新增了路径参数却忘了登记"，
        # 使这类漏检从"线上静默失效"变成"测试即报错"。
        path_fields = all_path_field_names()
        file_list = []
        for field in path_fields:
            val = effective_params.get(field)
            if not val:
                continue
            if isinstance(val, list):
                file_list.extend([str(x) for x in val if x])
            else:
                file_list.append(str(val))

        # 去重保留顺序
        deduped_file_list = _dedupe_keep_order(file_list)

        # 【SEC-04 修复】统一走可测试的聚合助手：越界/不可解析的候选路径被隔离，
        # 绝不进入 involved_paths 参与安全等级评估。
        secured_paths, secured_meta = _collect_involved_asset_paths(
            file_tool=session.file_tool,
            candidate_inputs=deduped_file_list,
            target_root=target_root,
        )
        involved_paths.extend(secured_paths)
        raw_items_meta.extend(secured_meta)

        eval_res = state_mgr.sec_mgr.evaluate_action_with_assets(
            action_name=act_name,
            params=effective_params,
            target_root=target_root,
            involved_paths=involved_paths
        )

        level = eval_res["final_level"]
        reason = eval_res["reason"]
        max_asset_level = eval_res["max_asset_level"]
        is_asset_guarded = eval_res["is_asset_guarded"]

        # ==================== 特殊工具个性化判定 ====================

        # 动作级安全事实：由工具层统一产出（网关不再自己探磁盘/解读等级）
        _FACT_ACTIONS = {"move_file", "copy_file", "rename_file", "write_file", "extract_archive"}
        act_facts: Optional[Dict[str, Any]] = None
        if act_name in _FACT_ACTIONS:
            act_facts = await asyncio.to_thread(
                session.file_tool.describe_action, act_name, effective_params
            )

        # 1. 移动与复制时的冲突与降级综合预检
        #
        # 【阶段 3 单一来源】这里过去**自己**判"目标是否存在"、自己读源/目标等级、
        # 自己拼告警文案 —— 与工具层口径不一致，② 就出在这段。
        # 现在网关**只消费**工具层产出的逐项安全事实，不再自行重算任何判定。
        if act_name in ["move_file", "copy_file"]:
            files = effective_params.get("files", [])
            target_dir = effective_params.get("target_dir", "")
            rename_to = effective_params.get("rename_to") or None
            facts = await asyncio.to_thread(
                session.file_tool.describe_transfer_sources, files, target_dir, rename_to
            )

            # 1.1 源不可解析/目标目录非法 → 直接终止（不弹窗、不执行）
            blocking = [f for f in facts if f.get("type") != "ok"]
            if blocking:
                return False, "源资产在库中匹配到多个对象或不存在，已终止操作。", effective_params

            _LEVEL_ORDER = {
                state_mgr.sec_mgr.LEVEL_SAFE: 0,
                state_mgr.sec_mgr.LEVEL_SENSITIVE: 1,
                state_mgr.sec_mgr.LEVEL_DESTRUCTIVE: 2,
            }

            def _max_level(a: str, b: str) -> str:
                """取更高的安全级别 —— 级别只允许**升级**，绝不允许被后续判断降回来。"""
                return a if _LEVEL_ORDER.get(a, 0) >= _LEVEL_ORDER.get(b, 0) else b

            # 【② 修复】各风险分量互不覆盖，按"取更严"合并。
            # 旧实现把降级与冲突**顺序各写一遍** `level` / `reason`，冲突分支无条件
            # `level = SENSITIVE`、`reason = 冲突文案`，把刚算出的降级结论整个覆盖掉：
            # 3 级机密移出保护目录 + 目标有同名文件时，level 由 DESTRUCTIVE 被拉回
            # SENSITIVE、降级警报完全消失、need_password 由 True 变 False。
            issue_reasons: List[str] = []

            # 1.2 降级：事实里已标明是否降级，这里只负责"定级"与"文案"
            downgrades = [f for f in facts if f.get("is_downgrade")]
            if downgrades:
                is_downgrade = True
                down_item = downgrades[0]
                issue_reasons.append(
                    f"⚠️【全员安全降级告警】：正在将原受【{down_item['src_level']}级】保护的资产移出至"
                    f"【{down_item['target_dir_level']}级】目录！"
                    f"移出后该资产及其内部所有文件都会降级为【{down_item['target_dir_level']}级】！"
                )
                downgrade_level = (
                    state_mgr.sec_mgr.LEVEL_DESTRUCTIVE
                    if down_item["src_level"] == 3
                    else state_mgr.sec_mgr.LEVEL_SENSITIVE
                )
                level = _max_level(level, downgrade_level)

            # 1.3 同名冲突：只有"真的会覆盖既有文件"才算。
            # 用户选择换名后（rename_to 指向不存在的新名）不再是冲突，
            # 不会出现"确认完又被拦一次"的空转。
            conflicts = [f for f in facts if f.get("would_overwrite")]
            if conflicts:
                is_conflict = True
                conflict_name = conflicts[0].get("name", "")
                conflict_msg = (
                    f"⚠️ 目标目录已存在同名资产 `{conflict_name}`！"
                    f"【更换名称】免密安全；【覆盖替换原有文件】属于高危操作，必须验证管理密码。"
                )
                # 降级在先时补一句说明：提示用户"冲突只是并发风险，降级才是那个警告"，
                # 避免用户把这条当成普通同名冲突而忽略机密保护被削弱。
                if is_downgrade:
                    conflict_msg += (
                        "　※ 请注意：本条拦截的主要风险是【安全等级降级】，不是同名冲突；"
                        "无论是否覆盖，该资产都会被移出受保护目录、机密保护随之削弱。"
                    )
                issue_reasons.append(conflict_msg)
                level = _max_level(level, state_mgr.sec_mgr.LEVEL_SENSITIVE)

            if issue_reasons:
                reason = "\n".join(issue_reasons)

        # 2. AI 调整安全等级切面拦截
        elif act_name == "set_security_level":
            target_lvl = int(effective_params.get("target_level", 1))
            t_input = effective_params.get("file_path") or effective_params.get("file_id")
            resolved_id, resolved_path = session.file_tool._resolve_file_record(t_input)
            current_level = 1
            if resolved_path and os.path.exists(resolved_path):
                current_level = state_mgr.sec_mgr.asset_sec_mgr.get_effective_level(resolved_path, target_root)
                max_asset_level = max(max_asset_level, current_level)

            lvl_names = {1: "1级 (普通)", 2: "2级 (敏感)", 3: "3级 (机密)"}

            if target_lvl < current_level:
                is_downgrade = True
                reason = (
                    f"⚠️【安全降级拦截】：正在将原受【{lvl_names.get(current_level)}】保护的资产降级为【{lvl_names.get(target_lvl)}】！"
                    f"降级后该资产及其子项的安全控制将被削弱。"
                )
                if current_level == 3:
                    level = state_mgr.sec_mgr.LEVEL_DESTRUCTIVE
                else:
                    level = state_mgr.sec_mgr.LEVEL_SENSITIVE
            elif target_lvl == 3:
                level = state_mgr.sec_mgr.LEVEL_DESTRUCTIVE
                max_asset_level = 3
                reason = f"🔒【机密升级鉴权】：将资产安全等级升级为【3级 (机密)】受主密码保护，系统强制要求验证管理密码！"
            elif target_lvl == 2:
                level = state_mgr.sec_mgr.LEVEL_SENSITIVE
                reason = f"⚠️【设置敏感等级】：即将把资产安全等级设为【2级 (敏感)】，后续操作需人工确认。"
            else:
                level = state_mgr.sec_mgr.LEVEL_SAFE
                reason = f"将资产安全等级重置为【1级 (普通)】。"

        # 3. 重命名切面拦截（兼容 file_path 与 file_id）
        #
        # 【阶段 3 单一来源】过去这里自己 `lexists` 探磁盘；现在只读工具层产出的事实。
        # 重命名按用户口径**始终**为敏感操作（要确认），与实际是否冲突无关；
        # 事实只用来补充告警文案并精确标记冲突。
        #
        # 【level 与 max_asset_level 是两个不同的东西，不得混用】
        #   level           = 政策定级字符串（SAFE/SENSITIVE/DESTRUCTIVE）
        #   max_asset_level = 涉及资产的等级数字（1/2/3）
        # 旧代码在这里写了 `level = max_asset_level if max_asset_level > 1 else level`，
        # 把**数字**塞进了 level 字段，前端会收到 `level: 2` 而不是 `"SENSITIVE"`。
        # 资产等级对定级的提升由统一的 `level = _max_level(level, _asset_level)` 处理。
        elif act_name == "rename_file":
            level = state_mgr.sec_mgr.LEVEL_SENSITIVE
            _detail = (act_facts or {}).get("detail", {})
            _new_n = _detail.get("name") or os.path.basename(str(effective_params.get("new_name", "")).strip())
            if (act_facts or {}).get("would_overwrite"):
                is_conflict = True
                reason = f"⚠️ 所在目录下已存在同名资产 `{_new_n}`！请在弹窗中重新指定一个新名称，或取消操作。"
            else:
                reason = f"将资产重命名为 `{_new_n}`。"

        elif act_name == "extract_archive":
            # 【阶段 3 单一来源】过去是"目标目录非空即冲突"的过近似，会白弹窗要密码；
            # 现在按事实：**只有真的会覆盖同名文件**才算冲突。
            _detail = (act_facts or {}).get("detail", {})
            if (act_facts or {}).get("would_overwrite"):
                is_conflict = True
                _name = os.path.basename(_detail.get("target_dir", "") or "")
                reason = (f"⚠️ 解压目标目录 `{_name}` 下已存在 {len(_detail.get('collisions', []))} 项同名资产！"
                          f"【更换新目录】为常规操作；【覆盖同名文件】属于危险操作，需输入管理密码。")

        # 4. 文本写入的同名冲突前置预检
        elif act_name == "write_file":
            # 【阶段 3 单一来源】只消费事实，不自己探磁盘。
            _detail = (act_facts or {}).get("detail", {})
            if (act_facts or {}).get("would_overwrite"):
                is_conflict = True
                _name = _detail.get("name", "")
                reason = (f"⚠️ 目标文件 `{_name}` 已存在！"
                          f"【更换新文件名】为常规文件名；【覆盖替换原有文件】属于高危操作，必须验证管理密码。")

        # 5. 打包输出包的同名冲突前置预检
        elif act_name == "compress_files":
            oz = effective_params.get("output_zip", "")
            rn = effective_params.get("rename_to") or None
            if oz:
                cand = os.path.join(os.path.dirname(str(oz)), str(rn)) if rn else str(oz)
                if not str(cand).lower().endswith(".zip"):
                    cand = str(cand) + ".zip"
                is_s_oz, v_oz = session.file_tool._verify_sandbox_path(cand)
                if is_s_oz and os.path.lexists(v_oz) and not rn:
                    is_conflict = True
                    level = state_mgr.sec_mgr.LEVEL_SENSITIVE
                    reason = (f"⚠️ 目标压缩包 `{os.path.basename(v_oz)}` 已存在！"
                              f"【更换新包名】为常规操作；【覆盖替换原有压缩包】属于高危操作，必须验证管理密码。")

        elif act_name == "delete_file":
            # 用户口径：删除永远危险，必须输入密码。保持破坏性定级、不可跳过。
            level = state_mgr.sec_mgr.LEVEL_DESTRUCTIVE
            reason = "将资产移入系统回收站【⚠️ 破坏性操作说明：此操作无法通过撤销按钮自动还原，若需找回请在系统回收站中手动拾回】"

        # ==================== 按事实与资产等级统一校准 ====================
        #
        # 原则（用户口径）：弹不弹、要不要密码，看**这次操作实际会造成什么、
        # 会不会动到安全等级**，而不是看它是哪个工具。
        #
        # 两条独立的校准，顺序不能反：
        #   ① 资产等级抬升：涉及 2 级 → 至少 SENSITIVE；涉及 3 级 → DESTRUCTIVE。
        #      放在"免打扰"判定**之前**，受控资产才不会被降级放行。
        #   ② 免打扰降级：仅当事实明确"什么都没被破坏"且不涉受控资产时降为 SAFE。

        # ① 资产等级 → 最低定级（2 级弹窗不要密码；3 级弹窗+密码）
        _LEVEL_ORDER_FINAL = {
            state_mgr.sec_mgr.LEVEL_SAFE: 0,
            state_mgr.sec_mgr.LEVEL_SENSITIVE: 1,
            state_mgr.sec_mgr.LEVEL_DESTRUCTIVE: 2,
        }

        def _max_level(a: str, b: str) -> str:
            return a if _LEVEL_ORDER_FINAL.get(a, 0) >= _LEVEL_ORDER_FINAL.get(b, 0) else b

        if max_asset_level >= 3:
            level = _max_level(level, state_mgr.sec_mgr.LEVEL_DESTRUCTIVE)
        elif max_asset_level == 2:
            level = _max_level(level, state_mgr.sec_mgr.LEVEL_SENSITIVE)

        # ② 免打扰降级（必须同时满足，缺一不可）：
        #   · 工具层事实明确"什么都没被破坏"（creates_new，且不涉降级）
        #   · 本次判定没有冲突、没有降级
        #   · 不涉及受控资产（max_asset_level == 1）
        #   · 不是删除（删除永远危险，用户已明确定调）
        #
        # 效果：
        #   移动本身              → SAFE（只是换了位置，无损失）—— 用户第 1 条
        #   新建文件              → SAFE（没覆盖任何东西）
        #   解压到无同名文件的目录  → SAFE（实测不会覆盖任何东西）
        #   重命名                → 仍 SENSITIVE（用户第 3 条：总是敏感）
        #   覆盖/替换既有文件      → 仍 SENSITIVE（确有内容被替换）
        #   涉及 2 级 / 3 级资产   → 仍强制拦截（3 级另加密码）
        if (
            act_facts and act_facts.get("handled", True) is not False
            and act_facts.get("creates_new") is True
            and not act_facts.get("is_downgrade")
            and not is_conflict
            and not is_downgrade
            and not is_asset_guarded
            and max_asset_level == 1
            and act_name != "delete_file"
            and act_name != "rename_file"
        ):
            level = state_mgr.sec_mgr.LEVEL_SAFE

        if not is_conflict and not is_downgrade:
            if state_mgr.sec_mgr.is_action_exempt(level, action_name=act_name,
                                                  is_asset_guarded=is_asset_guarded):
                return True, "", effective_params

        pending = HITLPendingItem(
            action_name=act_name,
            reason=reason,
            params=effective_params,
            level=level,
            raw_items=raw_items_meta,
            is_conflict=is_conflict,
            is_downgrade=is_downgrade,
            max_asset_level=max_asset_level
        )
        session.current_hitl_item = pending

        need_pwd = (level == state_mgr.sec_mgr.LEVEL_DESTRUCTIVE or max_asset_level == 3)
        await event_queue.put(sse_pack("hitl_suspend", {
            "session_id": req.session_id,
            "action_name": act_name,
            "reason": reason,
            "level": level,
            "params": effective_params,
            "items_meta": raw_items_meta,
            "is_conflict": is_conflict,
            "is_downgrade": is_downgrade,
            "max_asset_level": max_asset_level,
            "need_password": need_pwd
        }))

        wait_auth = asyncio.create_task(pending.event.wait())
        wait_abort = asyncio.create_task(session.async_abort_event.wait())

        done, pending_tasks = await asyncio.wait([wait_auth, wait_abort], return_when=asyncio.FIRST_COMPLETED)
        for t in pending_tasks:
            t.cancel()

        session.current_hitl_item = None

        if session.async_abort_event.is_set():
            return False, "用户主动终止了操作", effective_params

        if pending.decision.get("authorized"):
            if pending.decision.get("skip_this_session") and not is_conflict and not is_asset_guarded:
                state_mgr.sec_mgr.set_session_skip(level, True)
            if pending.decision.get("exempt_this_tool") and not is_conflict and not is_asset_guarded:
                state_mgr.sec_mgr.set_tool_exemption(act_name, True)
            return True, "", pending.decision.get("effective_params", effective_params)
        else:
            return False, "用户在界面端取消了操作（或密码校验未通过）", effective_params

    async def _async_token_warning_intercept(act_name: str, total_tokens: int, threshold: int) -> bool:
        reason = f"扫描生成的宏观文件树数据量过大 (~{format_token_count(total_tokens)} Tokens)，超过了安全告警阈值 ({threshold} Tokens)。"
        pending = HITLPendingItem(act_name, reason, {"total_tokens": total_tokens, "threshold": threshold}, "TOKEN_WARNING")
        session.current_hitl_item = pending

        await event_queue.put(sse_pack("hitl_suspend", {
            "session_id": req.session_id,
            "action_name": act_name,
            "reason": reason,
            "level": "TOKEN_WARNING",
            "params": {"tokens": total_tokens, "threshold": threshold},
            "items_meta": [],
            "is_conflict": False,
            "is_downgrade": False,
            "max_asset_level": 1,
            "need_password": False
        }))

        wait_auth = asyncio.create_task(pending.event.wait())
        wait_abort = asyncio.create_task(session.async_abort_event.wait())
        done, pending_tasks = await asyncio.wait([wait_auth, wait_abort], return_when=asyncio.FIRST_COMPLETED)
        for t in pending_tasks:
            t.cancel()

        session.current_hitl_item = None
        if session.async_abort_event.is_set():
            return False
        return bool(pending.decision.get("authorized", False))

    def _sync_attach_callback(title: str, content: str):
        key = "scan_directory" if "scan_directory" in title else title
        session.prompt_mgr.upsert_temp_prompt(title, content, key=key)
        asyncio.create_task(event_queue.put(sse_pack("temp_prompt_synced", {"title": title})))

    async def _graph_runner():
        from langchain_core.messages import AIMessage, ToolMessage, HumanMessage

        tools = get_web_agent_tools(
            file_tool=session.file_tool,
            intercept_async_callback=_async_security_intercept,
            token_warning_async_callback=_async_token_warning_intercept,
            attach_scan_callback=_sync_attach_callback,
            abort_event=session.thread_abort_event,
            check_abort_func=lambda: session.async_abort_event.is_set(),
            platform=platform_name
        )

        turn_generated_messages: List[Any] = []
        stream_parser = WebThinkingStreamParser()
        turn_success = False

        try:
            model = create_chat_model(profile_cfg)
            web_graph = build_web_file_agent_graph(
                model=model,
                tools=tools,
                get_system_instruction=session.prompt_mgr.get_full_system_instruction,
                max_turns=10
            )

            inputs = {
                "messages": list(session.prompt_mgr.chat_history),
                "turn_count": 0,
                "is_interrupted": False
            }

            has_tools_executed = False

            async for step_event in web_graph.astream(inputs, stream_mode="updates"):
                if session.async_abort_event.is_set():
                    await event_queue.put(sse_pack("abort", "🛑 操作已被用户主动终止。"))
                    break

                for node_name, node_output in step_event.items():
                    messages = node_output.get("messages", [])
                    if not messages:
                        continue

                    for msg_item in messages:
                        turn_generated_messages.append(msg_item)

                        if node_name == "agent" and isinstance(msg_item, AIMessage):
                            if msg_item.tool_calls:
                                has_tools_executed = True
                                for tc in msg_item.tool_calls:
                                    await event_queue.put(sse_pack("tool_start", {
                                        "id": tc.get("id"),
                                        "name": tc.get("name"),
                                        "args": tc.get("args")
                                    }))
                            elif msg_item.content:
                                raw_text = WebThinkingStreamParser.normalize_content_to_str(msg_item.content)
                                parsed = stream_parser.process_full_text(raw_text)
                                if parsed["thought"]:
                                    await direct_emit_text(event_queue, "thought", parsed["thought"])
                                if parsed["text"]:
                                    await direct_emit_text(event_queue, "text_delta", parsed["text"])

                        elif node_name == "tools" and isinstance(msg_item, ToolMessage):
                            obs_content = str(msg_item.content)
                            await event_queue.put(sse_pack("tool_result", {
                                "tool_call_id": msg_item.tool_call_id,
                                "name": msg_item.name,
                                "content": obs_content
                            }))

            has_valid_text_reply = any(
                isinstance(m, AIMessage) and bool(
                    WebThinkingStreamParser.normalize_content_to_str(m.content).strip())
                for m in turn_generated_messages
            )

            if not session.async_abort_event.is_set() and has_tools_executed and not has_valid_text_reply:
                summary_prompt = [
                    *session.prompt_mgr.chat_history,
                    *turn_generated_messages,
                    HumanMessage(content="请根据上述工具的执行结果与数据，向用户输出一份简洁、明确的最终执行结果说明。")
                ]
                final_resp = await model.ainvoke(summary_prompt)
                turn_generated_messages.append(final_resp)
                if final_resp.content:
                    final_text = WebThinkingStreamParser.normalize_content_to_str(final_resp.content)
                    parsed = stream_parser.process_full_text(final_text)
                    if parsed["text"]:
                        await direct_emit_text(event_queue, "text_delta", parsed["text"])

            if not session.async_abort_event.is_set():
                session.prompt_mgr.add_generated_messages(turn_generated_messages)
                session.prompt_mgr.commit_turn_transaction()
                turn_success = True
                await event_queue.put(sse_pack("done", {"session_id": req.session_id, "status": "success"}))
            else:
                safe_msgs = _keep_only_complete_tool_turns(turn_generated_messages)
                if any(isinstance(m, ToolMessage) for m in safe_msgs):
                    session.prompt_mgr.add_generated_messages(safe_msgs)
                    session.prompt_mgr.commit_turn_transaction()
                else:
                    session.prompt_mgr.rollback_turn_transaction()

        except asyncio.CancelledError:
            safe_msgs = _keep_only_complete_tool_turns(turn_generated_messages)
            if any(isinstance(m, ToolMessage) for m in safe_msgs):
                session.prompt_mgr.add_generated_messages(safe_msgs)
                session.prompt_mgr.commit_turn_transaction()
            else:
                session.prompt_mgr.rollback_turn_transaction()
            await event_queue.put(sse_pack("abort", "🛑 操作已被强制撤销。"))
        except Exception as ex:
            if not turn_success:
                safe_msgs = _keep_only_complete_tool_turns(turn_generated_messages)
                if any(isinstance(m, ToolMessage) for m in safe_msgs):
                    session.prompt_mgr.add_generated_messages(safe_msgs)
                    session.prompt_mgr.commit_turn_transaction()
                else:
                    session.prompt_mgr.rollback_turn_transaction()
            await event_queue.put(sse_pack("error", f"Agent 运行时异常: {str(ex)}"))
        finally:
            await event_queue.put(None)

    session.current_runner_task = asyncio.create_task(_graph_runner())

    try:
        while True:
            item = await event_queue.get()
            if item is None:
                break
            yield item
    finally:
        if session.current_runner_task and not session.current_runner_task.done():
            session.current_runner_task.cancel()


@app.post("/api/chat/stream")
async def chat_stream_endpoint(req: SendChatRequest):
    return StreamingResponse(
        agent_sse_generator(req),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@app.post("/api/agent/resume")
async def agent_resume_endpoint(req: HITLResumeRequest):
    session = state_mgr.get_session(req.session_id)
    if not session.current_hitl_item:
        raise HTTPException(status_code=400, detail="当前会话没有处于挂起等待的操作。")

    pending = session.current_hitl_item

    if not req.authorized:
        pending.decision = {"authorized": False, "effective_params": pending.params}
        pending.event.set()
        return {"success": True, "message": "已取消该操作"}

    is_overwrite_action = (req.conflict_action == "overwrite")
    is_destructive = (pending.level == state_mgr.sec_mgr.LEVEL_DESTRUCTIVE)
    is_critical_asset = (pending.max_asset_level == 3)
    # 覆盖替换类工具即便当前定级为 SENSITIVE（例如普通文件的 write_file / compress_files 同名冲突），
    # 一旦用户选择"覆盖替换"就等于销毁既有数据，必须与 move/copy 同一强度地验证主密码。
    is_overwrite_tool = pending.action_name in ("move_file", "copy_file", "write_file", "compress_files", "extract_archive")
    if is_overwrite_action and is_overwrite_tool:
        is_destructive = True

    if is_overwrite_action or is_destructive or is_critical_asset:
        if not state_mgr.sec_mgr.has_password_set():
            raise HTTPException(status_code=428, detail="系统尚未设置主管理密码，请先在右上角【安全配置】中设置主密码！")
        if not state_mgr.sec_mgr.verify_password(req.password or ""):
            raise HTTPException(status_code=403, detail="【机密/危险操作拦截】主管理密码验证失败，拒绝执行该操作！")

    eff_p = dict(pending.params)
    if req.conflict_action == "overwrite":
        eff_p["overwrite"] = True
        eff_p["rename_to"] = None
    elif req.new_name and str(req.new_name).strip():
        new_name_clean = os.path.basename(str(req.new_name).strip())
        eff_p["overwrite"] = False
        if pending.action_name in ("move_file", "copy_file", "compress_files"):
            eff_p["rename_to"] = new_name_clean
        elif pending.action_name == "write_file":
            eff_p["overwrite_name"] = new_name_clean
        elif pending.action_name == "rename_file":
            eff_p["new_name"] = new_name_clean
        elif pending.action_name == "extract_archive":
            # 【BUG-F5 修复】解压不支持"换名"，用户输入的新名称必须落成新的解压目标目录，
            # 否则前端"更名并继续（免密）"的参数会被静默丢弃、解压仍写回冲突目录。
            old_target = str(eff_p.get("target_dir") or "")
            if not old_target:
                zp = str(eff_p.get("zip_path") or "")
                old_target = os.path.splitext(zp)[0] if zp else session.file_tool.core.config.target_path
            eff_p["target_dir"] = os.path.join(os.path.dirname(old_target), new_name_clean)

    pending.decision = {
        "authorized": True,
        "skip_this_session": req.skip_this_session,
        "exempt_this_tool": req.exempt_this_tool,
        "effective_params": eff_p
    }
    pending.event.set()
    return {"success": True, "message": "授权成功，已恢复执行"}


# ==================== 资产安全等级管理 API ====================

@app.get("/api/security/levels/list")
async def list_security_levels_endpoint(session_id: str = "default"):
    session = state_mgr.get_session(session_id)
    records = session.file_tool.asset_sec_mgr.get_all_records()
    target_root = session.file_tool.core.config.target_path

    enriched = []
    for rel_p, lvl in records.items():
        abs_p = os.path.normpath(os.path.join(target_root, rel_p))
        is_d = os.path.isdir(abs_p) if os.path.exists(abs_p) else False
        enriched.append({
            "rel_path": rel_p,
            "abs_path": abs_p,
            "security_level": lvl,
            "is_dir": is_d,
            "exists": os.path.exists(abs_p)
        })

    return {
        "success": True,
        "records": enriched,
        "has_password": state_mgr.sec_mgr.has_password_set()
    }


@app.post("/api/security/levels/update")
async def update_security_levels_endpoint(req: UpdateSecurityLevelsRequest):
    session = state_mgr.get_session(req.session_id)
    target_root = session.file_tool.core.config.target_path

    if req.target_level not in (1, 2, 3):
        raise HTTPException(status_code=400, detail="无效的目标等级，必须为 1/2/3。")

    # ==================== 【BUG-14/15 鉴权修复】====================
    # 主管理密码是保护 3 级（机密）资产的唯一凭证。凡是"升级为 3 级"或"把既有的 3 级资产降级"，
    # Web 面板必须与 Agent 侧同一强度地强验主密码，否则 3 级保护形同虚设。
    def _effective_level_of(raw_path: str) -> int:
        is_s, v_p = session.file_tool._verify_sandbox_path(raw_path)
        if is_s:
            if os.path.exists(v_p):
                return int(session.file_tool.asset_sec_mgr.get_effective_level(v_p, target_root))
            rel_p = session.file_tool.asset_sec_mgr.to_rel_path(v_p, target_root)
            if rel_p:
                return int(session.file_tool.asset_sec_mgr.get_effective_level(rel_p, target_root))
        return int(session.file_tool.asset_sec_mgr.get_explicit_level(str(raw_path)))

    touches_critical = (req.target_level == 3)
    if not touches_critical:
        for _item in req.items:
            _raw = str(_item.get("path", "") or "")
            if not _raw:
                continue
            if _effective_level_of(_raw) == 3:
                touches_critical = True
                break

    if touches_critical:
        if not state_mgr.sec_mgr.has_password_set():
            raise HTTPException(
                status_code=428,
                detail="【未初始化主密码】将资产设为 3 级（机密）或修改 3 级机密资产，必须先设置主管理密码！"
            )
        if not state_mgr.sec_mgr.verify_password(req.password or ""):
            raise HTTPException(
                status_code=403,
                detail="【机密资产拦截】主管理密码验证失败，拒绝修改 3 级（机密）资产的安全等级！"
            )

    updated_count = 0
    total_cleaned_sub = 0
    cleaned_details = []
    skipped_items = []
    pairs_for_db = []

    for item in req.items:
        raw_path = item.get("path", "")
        if not raw_path:
            skipped_items.append({"path": str(raw_path), "reason": "路径为空"})
            continue
        is_d = bool(item.get("is_dir", False))
        is_s, v_p = session.file_tool._verify_sandbox_path(raw_path)
        if not is_s:
            # 【P2-10 修复】不再静默跳过：越界/黑名单路径必须如实回传原因
            skipped_items.append({"path": str(raw_path), "reason": v_p})
            continue

        res = session.file_tool.asset_sec_mgr.set_asset_level(
            abs_or_rel_path=v_p,
            level=req.target_level,
            target_root=target_root,
            is_dir=is_d
        )
        if res.get("success"):
            updated_count += 1
            cleaned = res.get("cleaned_sub_items", [])
            if cleaned:
                total_cleaned_sub += len(cleaned)
                cleaned_details.extend(cleaned)
            pairs_for_db.append((v_p, req.target_level, is_d))
        else:
            skipped_items.append({"path": str(raw_path), "reason": res.get("message", "设置失败")})

    if pairs_for_db:
        await asyncio.to_thread(session.file_tool.core.batch_update_security_levels, pairs_for_db)

    hint_msg = f"成功更新 {updated_count} 项资产的安全等级为【{req.target_level}级】。"
    if total_cleaned_sub > 0:
        hint_msg += f"（提示：已自动将下属 {total_cleaned_sub} 项子资产重置为 1 级，统一由父级目录动态继承）"
    if skipped_items:
        hint_msg += f" 另有 {len(skipped_items)} 项被跳过（见 skipped_details）。"

    return {
        "success": True,
        "updated_count": updated_count,
        "cleaned_sub_count": total_cleaned_sub,
        "cleaned_details": cleaned_details,
        "skipped_count": len(skipped_items),
        "skipped_details": skipped_items[:20],
        "message": hint_msg
    }


@app.get("/api/fs/browse_assets")
async def browse_assets_endpoint(session_id: str = "default", rel_dir: str = ""):
    session = state_mgr.get_session(session_id)
    root = session.file_tool.core.config.target_path
    target_abs = os.path.normpath(os.path.join(root, rel_dir.strip("/\\"))) if rel_dir else root

    is_s, v_dir = session.file_tool._verify_sandbox_path(target_abs)
    if not is_s or not os.path.exists(v_dir) or not os.path.isdir(v_dir):
        raise HTTPException(status_code=400, detail="目标目录不存在或超出工作区边界")

    entries = []
    try:
        items = sorted(os.listdir(v_dir))
        for it in items:
            full_p = os.path.normpath(os.path.join(v_dir, it))
            if session.file_tool.core.is_blacklisted(full_p):
                continue
            is_d = os.path.isdir(full_p)
            rel_p = session.file_tool.asset_sec_mgr.to_rel_path(full_p, root)
            explicit_lvl = session.file_tool.asset_sec_mgr.get_explicit_level(rel_p)
            effective_lvl = session.file_tool.asset_sec_mgr.get_effective_level(full_p, root)
            sz = os.path.getsize(full_p) if not is_d and os.path.exists(full_p) else 0

            entries.append({
                "name": it,
                "rel_path": rel_p,
                "abs_path": full_p,
                "is_dir": is_d,
                "size_str": "-" if is_d else session.file_tool._format_size(sz),
                "explicit_level": explicit_lvl,
                "effective_level": effective_lvl,
                "is_inherited": (effective_lvl != explicit_lvl and effective_lvl > 1)
            })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"遍历目录失败: {str(e)}")

    return {
        "success": True,
        "current_rel_dir": session.file_tool.asset_sec_mgr.to_rel_path(v_dir, root),
        "entries": entries
    }


# ==================== 原生无 Agent 撤销与状态探针 API ====================

@app.get("/api/fs/undo_status")
async def get_undo_status_endpoint(session_id: str = "default"):
    session = state_mgr.get_session(session_id)
    status = await asyncio.to_thread(session.file_tool.get_undo_status)
    return {"success": True, **status}


@app.post("/api/fs/undo")
async def undo_operation_endpoint(session_id: str = "default"):
    if global_undo_lock.locked():
        raise HTTPException(status_code=429, detail="已有正在执行的撤销事务，请稍后再试！")

    async with global_undo_lock:
        session = state_mgr.get_session(session_id)
        res = await asyncio.to_thread(session.file_tool.undo_last_operation)
        if not res.get("success"):
            raise HTTPException(status_code=400, detail=res.get("message", "当前没有可撤回的操作记录"))

        summary = res.get("summary", "某项物理资产操作")
        affected_items = res.get("affected_items", [])
        can_undo = res.get("can_undo", False)

        session.prompt_mgr.record_undo_event(
            summary=summary,
            affected_items=affected_items,
            can_undo=can_undo
        )

        return {
            "success": True,
            "can_undo": can_undo,
            "summary": summary,
            "affected_items": affected_items,
            "message": res.get("message")
        }


@app.get("/api/audit/logs")
async def get_audit_logs_endpoint(session_id: str = "default", limit: int = 50, offset: int = 0):
    session = state_mgr.get_session(session_id)
    logs = await asyncio.to_thread(session.file_tool.core.query_audit_logs, limit=limit, offset=offset)
    return {"success": True, "logs": logs}


@app.post("/api/agent/abort")
async def agent_abort_endpoint(session_id: str = "default"):
    """中止当前回合，并**等它真正收尾完**再返回。

    【为什么这里必须等】前端点中止后，会把发送按钮置为"加载中、发不出去"，
    直到本接口返回才恢复。若这里一发出就返回，前端根本无从知道后面还在收尾，
    于是"收尾没结束就允许发送"就成了必然。让本接口的返回时刻等于
    "收尾已完成"，前端只需等这一次请求即可，不需要轮询，也不需要新接口。

    返回里的 ``confirmed=false`` 表示**没能确认**收尾完成（超时）。
    这种情况下中止标志会被保留，旧回合不会写入对话记录。
    """
    session = state_mgr.get_session(session_id)
    res = await session.abort_and_wait()
    if not res.get("confirmed"):
        return {
            "success": False,
            "confirmed": False,
            "message": (
                f"已发送中止信号，但等待 {res.get('waited', 0):.1f} 秒后仍未确认上一回合收尾完成。"
                f"该回合不会写入对话记录。"
            ),
            "waited": res.get("waited"),
        }
    return {"success": True, "confirmed": True, "message": "已中止并确认上一回合收尾完成"}


@app.get("/api/config/init")
async def get_init_config(session_id: str = "default"):
    session = state_mgr.get_session(session_id)
    platform_name = "DeepSeek"
    if state_mgr.current_api_profile in state_mgr.api_profiles:
        platform_name = state_mgr.api_profiles[state_mgr.current_api_profile].get("platform", "DeepSeek")

    sys_tokens = count_text_tokens(session.prompt_mgr.system_prompt, platform=platform_name)
    full_instruction = session.prompt_mgr.get_full_system_instruction()
    total_tokens = count_text_tokens(full_instruction, platform=platform_name)

    history_count = len(session.prompt_mgr.chat_history)
    history_tokens = 0
    for msg in session.prompt_mgr.chat_history:
        content = getattr(msg, "content", "")
        if isinstance(content, str):
            history_tokens += count_text_tokens(content, platform=platform_name)
        elif isinstance(content, list):
            for sub in content:
                if isinstance(sub, dict) and sub.get("type") == "text":
                    history_tokens += count_text_tokens(sub.get("text", ""), platform=platform_name)

    persistent_list = []
    for p in session.prompt_mgr.persistent_prompts:
        p_copy = dict(p)
        p_copy["tokens"] = count_text_tokens(p.get("content", ""), platform=platform_name)
        persistent_list.append(p_copy)

    temp_list = []
    for t in session.prompt_mgr.temp_prompts:
        t_copy = dict(t)
        t_copy["tokens"] = count_text_tokens(t.get("content", ""), platform=platform_name)
        temp_list.append(t_copy)

    grand_total_tokens = total_tokens + history_tokens
    undo_status = session.file_tool.get_undo_status()

    return {
        "app_config": _sanitized_app_config(),
        "security_policy": state_mgr.sec_mgr.security_policy,
        "theme": state_mgr.app_config.get("theme", "dark"),
        "api_profiles": {
            k: {
                "platform": v.get("platform"),
                "selected_model": v.get("selected_model"),
                "url": v.get("url"),
                "cached_models": v.get("cached_models", [])
            } for k, v in state_mgr.api_profiles.items()
        },
        "current_api_profile": state_mgr.current_api_profile,
        "fast_chats": state_mgr.fast_chats,
        "has_password": state_mgr.sec_mgr.has_password_set(),
        "can_undo": undo_status.get("can_undo", False),
        "system_prompt": session.prompt_mgr.system_prompt,
        "system_tokens": sys_tokens,
        "history_count": history_count,
        "history_tokens": history_tokens,
        "total_tokens": grand_total_tokens,
        "persistent_prompts": persistent_list,
        "temp_prompts": temp_list
    }


@app.get("/api/security/policy")
async def get_security_policy_endpoint():
    return {"success": True, "policy": state_mgr.sec_mgr.security_policy}


@app.post("/api/security/policy/save")
async def save_security_policy_endpoint(req: SaveSecurityPolicyRequest):
    if not isinstance(req.policy, dict):
        raise HTTPException(status_code=400, detail="无效的策略格式")
    state_mgr.sec_mgr.security_policy = req.policy
    ok = state_mgr.sec_mgr.save_policy()
    if not ok:
        raise HTTPException(status_code=500, detail="保存 security_policy.json 失败")
    return {"success": True, "message": "安全策略已更新"}


@app.get("/api/config/api/presets")
async def get_api_presets_endpoint():
    return {"success": True, "presets": PLATFORM_PRESETS}


@app.post("/api/models/fetch")
async def fetch_models_endpoint(req: FetchModelsRequest):
    p = req.platform
    key = req.key.strip() if req.key else ""

    if not key and req.profile_name and req.profile_name in state_mgr.api_profiles:
        enc_key = state_mgr.api_profiles[req.profile_name].get("key", "")
        key = SecurityManager.decrypt_api_key(enc_key)

    if not key and "Ollama" not in p:
        raise HTTPException(status_code=400, detail="请先填入或提供有效的 API Key！")

    default_preset = PLATFORM_PRESETS.get(p, {})
    if p == "自定义端点 (高级)":
        models_url = req.url.strip().replace("/chat/completions", "/models") if req.url else ""
    else:
        models_url = default_preset.get("models_url", "")

    if not models_url:
        raise HTTPException(status_code=400, detail=f"平台 {p} 缺少有效的模型拉取端点。")

    def _do_fetch():
        headers = {"Authorization": f"Bearer {key}"} if not p.startswith("Anthropic") else {
            "x-api-key": key,
            "anthropic-version": "2023-06-01"
        }
        url = f"{models_url}?key={key}" if p.startswith("Google") else models_url
        res = requests.get(url, headers=headers, timeout=15)
        if res.status_code != 200:
            raise RuntimeError(f"HTTP {res.status_code}: {res.text[:200]}")
        data = res.json()

        model_list = []
        if "data" in data and isinstance(data["data"], list):
            model_list = [item["id"] for item in data["data"] if isinstance(item, dict) and "id" in item]
        elif "models" in data and isinstance(data["models"], list):
            model_list = [item.get("name", item.get("id", "")).replace("models/", "") for item in data["models"]]

        return sorted(list(set(model_list)))

    try:
        models = await asyncio.to_thread(_do_fetch)
        return {"success": True, "models": models}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"在线拉取模型失败: {str(e)}")


@app.post("/api/utils/browse_dir")
async def browse_directory_endpoint():
    def _pick():
        import tkinter as tk
        from tkinter import filedialog
        try:
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)
            folder_selected = filedialog.askdirectory()
            root.destroy()
            return folder_selected
        except Exception:
            return ""

    picked = await asyncio.to_thread(_pick)
    return {"success": True, "path": picked or ""}


@app.post("/api/config/theme")
async def update_theme_endpoint(req: UpdateThemeRequest):
    state_mgr.app_config["theme"] = req.theme
    state_mgr.save_app_config()
    return {"success": True, "theme": req.theme}


@app.post("/api/config/api/save")
async def save_api_profile_endpoint(req: SaveApiProfileRequest):
    payload = dict(req.data)
    plain_key = payload.get("key", "")
    if plain_key and not plain_key.startswith("enc::"):
        payload["key"] = SecurityManager.encrypt_api_key(plain_key)
    elif not plain_key and req.name in state_mgr.api_profiles:
        payload["key"] = state_mgr.api_profiles[req.name].get("key", "")

    state_mgr.api_profiles[req.name] = payload
    state_mgr.current_api_profile = req.name
    state_mgr.save_api_config()
    return {"success": True}


@app.post("/api/config/api/switch")
async def switch_api_profile_endpoint(profile_name: str):
    if profile_name in state_mgr.api_profiles:
        state_mgr.current_api_profile = profile_name
        state_mgr.save_api_config()
        return {"success": True}
    raise HTTPException(status_code=400, detail="未找到该 Profile")

@app.delete("/api/config/api/{profile_name}")
async def delete_api_profile_endpoint(profile_name: str):
    """安全删除指定的 API Profile，并自动处理当前激活指针迁移"""
    if profile_name not in state_mgr.api_profiles:
        raise HTTPException(status_code=404, detail=f"未找到名为 '{profile_name}' 的 API 配置。")

    # 1. 物理移除该配置
    del state_mgr.api_profiles[profile_name]

    # 2. 状态自愈：如果删除的是当前正激活的 Profile，平滑切换指针
    if state_mgr.current_api_profile == profile_name:
        remaining_keys = list(state_mgr.api_profiles.keys())
        state_mgr.current_api_profile = remaining_keys[0] if remaining_keys else ""

    # 3. 持久化落盘
    state_mgr.save_api_config()

    return {
        "success": True,
        "message": f"API 配置 '{profile_name}' 已成功删除。",
        "current_profile": state_mgr.current_api_profile
    }

@app.post("/api/config/scan/save")
async def save_scan_config_endpoint(req: SaveScanConfigRequest):
    target_abs = os.path.normpath(os.path.abspath(req.target_path))
    if not os.path.exists(target_abs):
        raise HTTPException(status_code=400, detail="设置的目标路径在本地物理磁盘上不存在！")

    state_mgr.app_config["target_path"] = target_abs
    state_mgr.app_config["max_depth"] = req.max_depth
    state_mgr.app_config["blacklist_paths"] = req.blacklist_paths
    state_mgr.app_config["tool_token_warning_threshold"] = req.tool_token_warning_threshold or 10000

    # 【可配置】对话记录窗口轮数与记录体积告警阈值
    if req.chat_history_window_rounds is not None:
        state_mgr.app_config["chat_history_window_rounds"] = max(1, int(req.chat_history_window_rounds))
    if req.chat_log_size_warn_mb is not None:
        state_mgr.app_config["chat_log_size_warn_mb"] = max(1.0, float(req.chat_log_size_warn_mb))

    sec = state_mgr.app_config.setdefault("security", {})
    sec["permanent_skip_sensitive"] = req.permanent_skip_sensitive
    sec["permanent_skip_destructive"] = req.permanent_skip_destructive

    # 【BUG-13 修复】本接口是"工作区/扫描配置保存"，绝不允许成为绕过旧密码的重置后门。
    # 修改主密码必须走 /api/security/password/update（该校验旧密码）；此处即使传了
    # new_password 也必须先证明自己知道旧密码，否则一律拒绝且不得改动任何密码状态。
    if req.new_password:
        if state_mgr.sec_mgr.has_password_set():
            if not req.old_password or not state_mgr.sec_mgr.verify_password(req.old_password):
                raise HTTPException(
                    status_code=403,
                    detail="【鉴权拦截】修改主管理密码必须提供正确的原密码，请改用安全配置中的改密入口或补传 old_password。"
                )
        state_mgr.sec_mgr.set_master_password(req.new_password)

    state_mgr.save_app_config()

    for s in state_mgr.sessions.values():
        s.prompt_mgr.update_target_path(target_abs)
        s.file_tool.core.config.target_path = target_abs
        s.file_tool.core.config.blacklist_paths = req.blacklist_paths
        # 【可配置项立即生效】否则用户改了窗口/阈值却要重启才起作用
        s.prompt_mgr.max_history_rounds = resolve_window_rounds(state_mgr.app_config)
        s.prompt_mgr.chat_store.size_warn_bytes = resolve_size_warn_bytes(state_mgr.app_config)
        # 窗口立刻重裁：否则旧消息要等到"下一条消息到来"才被裁掉，
        # 界面会继续显示超出窗口的内容
        trimmed = s.prompt_mgr.reapply_window()
        if trimmed:
            logger.info(f"窗口调整为 {s.prompt_mgr.max_history_rounds} 轮，已立即裁掉内存中 {trimmed} 条旧消息")

    return {"success": True}


@app.post("/api/config/fast_chats/save")
async def save_fast_chats_endpoint(req: SaveFastChatsRequest):
    state_mgr.fast_chats = req.fast_chats
    state_mgr.save_fast_chats()
    return {"success": True}


@app.post("/api/security/password/update")
async def update_password_endpoint(req: UpdatePasswordRequest):
    has_pwd = state_mgr.sec_mgr.has_password_set()
    if has_pwd:
        if not req.old_password or not state_mgr.sec_mgr.verify_password(req.old_password):
            raise HTTPException(status_code=400, detail="原密码验证失败！")

    if not req.new_password:
        raise HTTPException(status_code=400, detail="新密码不能为空！")

    state_mgr.sec_mgr.set_master_password(req.new_password)
    return {"success": True, "message": "管理密码更新成功！"}


@app.post("/api/scan/estimate_tokens")
async def estimate_scan_tokens_endpoint(target_path: str, max_depth: int):
    target_abs = os.path.normpath(os.path.abspath(target_path))
    if not os.path.exists(target_abs):
        raise HTTPException(status_code=400, detail="目标扫描路径不存在！")

    from tools.scanner import ScannerFilter, scan_directory, DEFAULT_SYSTEM_IGNORED
    from tools.scan_indexer import ScanIndexer

    platform_name = "DeepSeek"
    if state_mgr.current_api_profile in state_mgr.api_profiles:
        platform_name = state_mgr.api_profiles[state_mgr.current_api_profile].get("platform", "DeepSeek")

    def _do_estimate():
        bl_paths = state_mgr.app_config.get("blacklist_paths", [])
        blacklist = {"paths": bl_paths, "names": list(DEFAULT_SYSTEM_IGNORED), "extensions": []}
        filter_engine = ScannerFilter(caller_script=None, output_file=None, blacklist=blacklist)
        visited_set = set()
        scan_start = datetime.now()

        tree_data = scan_directory(
            target_abs,
            current_depth=1,
            max_depth=max_depth,
            filter_engine=filter_engine,
            max_sample_count=100,
            visited_paths=visited_set
        )
        mock_json = {
            "scan_meta": {
                "root_path": target_abs,
                "max_depth": max_depth,
                "scan_time": scan_start.strftime('%Y-%m-%d %H:%M:%S')
            },
            "structure": tree_data
        }
        indexer = ScanIndexer(mock_json)
        primary_md = indexer.generate_compressed_markdown()
        deep_md = indexer.generate_deep_compressed_markdown()

        p_tokens = count_text_tokens(primary_md, platform=platform_name)
        d_tokens = count_text_tokens(deep_md, platform=platform_name)
        threshold = int(state_mgr.app_config.get("tool_token_warning_threshold", 10000))

        return {
            "primary_tokens": p_tokens,
            "deep_tokens": d_tokens,
            "threshold": threshold,
            "is_deep_suggested": p_tokens > threshold
        }

    res = await asyncio.to_thread(_do_estimate)
    return {"success": True, "data": res}


@app.post("/api/upload/file")
async def upload_file_endpoint(file: UploadFile = File(...), session_id: str = Form("default")):
    size_counter = 0
    chunks = []
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        size_counter += len(chunk)
        if size_counter > MAX_UPLOAD_SIZE:
            raise HTTPException(status_code=413, detail=f"文件体积过大！当前系统最大支持 {MAX_UPLOAD_SIZE // (1024 * 1024)}MB 附件。")
        chunks.append(chunk)

    content_bytes = b"".join(chunks)
    filename = file.filename or "unknown"
    ext = os.path.splitext(filename)[1].lower()

    platform_name = "DeepSeek"
    if state_mgr.current_api_profile in state_mgr.api_profiles:
        platform_name = state_mgr.api_profiles[state_mgr.current_api_profile].get("platform", "DeepSeek")

    is_image = ext in [".png", ".jpg", ".jpeg", ".webp", ".bmp"]
    b64_str = base64.b64encode(content_bytes).decode("utf-8")

    if is_image:
        mime = "jpeg" if ext in [".jpg", ".jpeg"] else ext.replace(".", "")
        def _calc_img_tokens():
            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                tmp.write(content_bytes)
                tmp_path = tmp.name
            try:
                return count_image_tokens(tmp_path, platform=platform_name)
            finally:
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass

        calc_tokens = await asyncio.to_thread(_calc_img_tokens)
        return {
            "success": True,
            "filename": filename,
            "is_image": True,
            "base64": b64_str,
            "mime": mime,
            "tokens": calc_tokens
        }
    else:
        text_content = content_bytes.decode("utf-8", errors="ignore")
        tokens = count_text_tokens(text_content, platform=platform_name)
        return {
            "success": True,
            "filename": filename,
            "is_image": False,
            "text_content": text_content,
            "tokens": tokens
        }


@app.post("/api/prompt/system")
async def update_system_prompt(req: UpdateSystemPromptRequest):
    session = state_mgr.get_session(req.session_id)
    session.prompt_mgr.set_system_prompt(req.prompt)
    return {"success": True}


@app.get("/api/prompt/system/default")
async def get_default_system_prompt_endpoint():
    return {"success": True, "prompt": DEFAULT_SYSTEM_PROMPT}


@app.post("/api/prompt/temp/add")
async def add_temp_prompt(req: AddTempPromptRequest):
    session = state_mgr.get_session(req.session_id)
    pid = session.prompt_mgr.add_temp_prompt(req.title, req.content)
    return {"success": True, "prompt_id": pid}


@app.put("/api/prompt/temp/update")
async def update_temp_prompt(req: UpdateTempPromptRequest):
    session = state_mgr.get_session(req.session_id)
    session.prompt_mgr.update_temp_prompt(req.prompt_id, req.title, req.content)
    return {"success": True}


@app.post("/api/prompt/temp/reorder")
async def reorder_temp_prompt(req: ReorderTempPromptRequest):
    session = state_mgr.get_session(req.session_id)
    session.prompt_mgr.move_temp_prompt(req.src_idx, req.dest_idx)
    return {"success": True}


@app.delete("/api/prompt/temp/{prompt_id}")
async def delete_temp_prompt(prompt_id: str, session_id: str = "default"):
    session = state_mgr.get_session(session_id)
    session.prompt_mgr.remove_temp_prompt(prompt_id)
    return {"success": True}


@app.post("/api/prompt/persistent/rescan")
async def rescan_persistent_prompts(session_id: str = "default"):
    session = state_mgr.get_session(session_id)
    session.prompt_mgr.scan_and_load_data_prompts(DATA_DIR, state_mgr.app_config.get("enabled_persistent_files", []))
    return {"success": True, "count": len(session.prompt_mgr.persistent_prompts)}


@app.post("/api/prompt/persistent/toggle")
async def toggle_persistent_prompt(req: TogglePersistentPromptRequest):
    session = state_mgr.get_session(req.session_id)
    session.prompt_mgr.set_persistent_prompt_enabled(req.prompt_id, req.enabled)
    state_mgr.app_config["enabled_persistent_files"] = [
        p["rel_path"] for p in session.prompt_mgr.persistent_prompts if p.get("enabled", False)
    ]
    state_mgr.save_app_config()
    return {"success": True}


@app.post("/api/chat/clear")
async def clear_chat_history(session_id: str = "default"):
    """清空 = 开新对话：新建一份记录文件并清空内存，**旧文件原地保留**。

    中止同样要**等收尾确认完**再清空——否则被放弃的旧回合可能在清空之后
    把自己写回来。未确认时中止标志被保留，旧回合不会写入记录。
    """
    session = state_mgr.get_session(session_id)
    res = await session.abort_and_wait()
    session.prompt_mgr.clear_history()
    return {
        "success": True,
        "confirmed": bool(res.get("confirmed")),
        "message": "已开启新的对话（原有记录文件保留）",
    }


@app.get("/api/chat/status")
async def chat_history_status(session_id: str = "default"):
    """对话记录状态：窗口内条数、因窗口滚动而未载入内存的条数、文件体积。

    前端用它在滚动到顶部时提示"更早还有多少条未显示"。
    """
    session = state_mgr.get_session(session_id)
    return {"success": True, **session.prompt_mgr.history_status()}


def _history_to_ui_messages(prompt_mgr) -> List[Dict[str, Any]]:
    """把内存里的对话窗口转成前端可直接渲染的消息列表。

    只保留用户提问与"最终回答"（不带工具调用的 AI 消息），
    跳过工具结果与中间思考——这些在流式过程中已由事件单独呈现，
    放进历史列表会变成大段无人看的原始数据。
    """
    ui: List[Dict[str, Any]] = []
    for m in prompt_mgr.chat_history:
        content = getattr(m, "content", "")
        if isinstance(content, list):
            text = " ".join(
                b.get("text", "") for b in content
                if isinstance(b, dict) and b.get("type") == "text"
            )
        else:
            text = str(content or "")
        if isinstance(m, HumanMessage):
            if text:
                ui.append({"role": "user", "content": text, "image": None})
        elif isinstance(m, AIMessage):
            if getattr(m, "tool_calls", None):
                continue          # 中间的工具调用轮，不作为对话气泡显示
            if text:
                ui.append({"role": "assistant", "content": text, "thought": "",
                           "thinkExpanded": False, "tool_calls": []})
    return ui


@app.get("/api/chat/history")
async def get_chat_history(session_id: str = "default"):
    """返回当前对话窗口内的消息列表。

    前端的消息气泡此前只存在于浏览器内存里：启动、接续历史对话之后
    界面都是空的。这个接口让界面能按后端的真实窗口重建。
    """
    session = state_mgr.get_session(session_id)
    return {
        "success": True,
        "messages": _history_to_ui_messages(session.prompt_mgr),
        **session.prompt_mgr.history_status(),
    }


# ==================== 对话记录管理（审计面板） ====================

def _chat_log_store_for(session: "SessionContext") -> ChatLogStore:
    return session.prompt_mgr.chat_store


def _resolve_log_path(session: "SessionContext", name: str) -> str:
    """把列表接口给出的文件名解析成路径，并挡住目录穿越。

    只接受"位于记录目录之下的普通文件名"，避免 `../` 之类的输入被用来
    读写记录目录以外的文件。
    """
    safe = os.path.basename(str(name or "").strip())
    if not safe or safe != str(name or "").strip():
        raise HTTPException(status_code=400, detail="非法的记录文件名。")
    full = os.path.join(_chat_log_store_for(session).log_dir, safe)
    if not os.path.isfile(full):
        raise HTTPException(status_code=404, detail="记录文件不存在。")
    return full


@app.get("/api/chat/logs")
async def list_chat_logs(session_id: str = "default"):
    """列出全部对话记录（供审计面板选择继续哪一份）。"""
    session = state_mgr.get_session(session_id)
    store = _chat_log_store_for(session)
    current = os.path.basename(store.path) if store.path else ""
    items = []
    for log in store.list_logs():
        try:
            store.path = log["path"]
            total = store.total_messages()
        except Exception:
            total = 0
        items.append({
            "name": log["name"],
            "size_bytes": log["size_bytes"],
            "modified_time": log["modified_time"],
            "messages": total,
            "is_current": log["name"] == current,
        })
    store.path = os.path.join(store.log_dir, current) if current else store.path
    return {
        "success": True,
        "log_dir": store.log_dir,
        "current": current,
        "logs": items,
    }


@app.post("/api/chat/logs/switch")
async def switch_chat_log(req: ChatLogSwitchRequest, session_id: str = "default"):
    """切换到（接续）某一份历史对话。

    切之前先等当前回合收尾完成——否则被切走的那一轮可能把内容写到新记录上。
    """
    session = state_mgr.get_session(session_id)
    full = _resolve_log_path(session, req.name)
    res = await session.abort_and_wait()
    session.prompt_mgr.load_history_from_disk(full)
    return {
        "success": True,
        "confirmed": bool(res.get("confirmed")),
        "message": f"已接续对话记录 {os.path.basename(full)}",
        **session.prompt_mgr.history_status(),
    }


@app.post("/api/chat/logs/delete")
async def delete_chat_log(req: ChatLogDeleteRequest, session_id: str = "default"):
    """删除某一份对话记录。

    【注意】这是**显式**的删除动作（用户在审计面板里点删），
    与"记录永不自动删减"的约定不冲突：约定约束的是系统不得擅自丢弃内容，
    而不是禁止用户主动清理。当前正在使用的那一份会被拒绝删除。
    """
    session = state_mgr.get_session(session_id)
    store = _chat_log_store_for(session)
    full = _resolve_log_path(session, req.name)
    if store.path and os.path.normcase(os.path.abspath(store.path)) == os.path.normcase(os.path.abspath(full)):
        raise HTTPException(status_code=400, detail="不能删除当前正在使用的对话记录，请先切换到其它记录或新建对话。")
    try:
        os.remove(full)
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"删除失败: {e}")
    return {"success": True, "message": f"已删除对话记录 {req.name}"}


@app.post("/api/db/sync")
async def sync_database_manual(session_id: str = "default"):
    session = state_mgr.get_session(session_id)
    sync_res = await asyncio.to_thread(session.file_tool.sync_database)
    v_res = await asyncio.to_thread(session.file_tool.build_vector_index)
    if not isinstance(v_res, dict):
        v_res = {"success": bool(v_res), "message": str(v_res), "retryable": False}

    # 【静默失败修复】不再硬编码 success=True：向量构建部分失败（内容提取或推理异常
    # 导致资产被跳过）时必须如实告知，否则前端与用户都会把"部分失败"当成"全部成功"。
    vector_ok = bool(v_res.get("success"))
    result = {
        "success": vector_ok,
        "sync": sync_res,
        "vector": v_res,
    }
    if not vector_ok:
        result["warning"] = v_res.get("message") or "向量索引未完全构建成功"
        # 【确定性失败的处理】标记为"可重试"时，前端应暂停并询问用户
        # 中断 / 跳过语义索引继续 / 重试，而不是仅弹一条提示。
        result["retryable"] = bool(v_res.get("retryable"))
    return result


if os.path.exists(WEB_DIR):
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="static")