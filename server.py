# server.py
# -*- coding: utf-8 -*-

import os
import json
import uuid
import base64
import asyncio
import tempfile
import threading
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple, AsyncGenerator
from contextlib import asynccontextmanager

import requests
from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form, Query
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from langchain_core.messages import AIMessage, ToolMessage, HumanMessage

from core.security import SecurityManager, AssetSecurityManager
from core.model_factory import create_chat_model
from core.tokenizer import count_text_tokens, count_image_tokens, format_token_count
from core.agent_graph_web import build_web_file_agent_graph, WebThinkingStreamParser
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
        self.prompt_mgr = PromptManager(target_path=target_path)
        self.file_tool = FileManagerTool(APP_CONFIG_FILE)
        self.async_abort_event: asyncio.Event = asyncio.Event()
        self.thread_abort_event: threading.Event = threading.Event()
        self.current_hitl_item: Optional[HITLPendingItem] = None
        self.current_runner_task: Optional[asyncio.Task] = None
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


class AppStateManager:
    def __init__(self):
        self.app_config: Dict[str, Any] = {
            "theme": "dark",
            "target_path": os.path.expanduser("~"),
            "max_depth": 3,
            "blacklist_paths": [],
            "tool_token_warning_threshold": 10000,
            "enabled_persistent_files": [],
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
            await asyncio.to_thread(default_session.file_tool.build_vector_index)
            print("[启动自愈] 会话撤销流水已重置，SQLite 资产与 LanceDB 向量索引已对齐。")
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
    permanent_skip_sensitive: bool = False
    permanent_skip_destructive: bool = False


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
    session.abort()
    await asyncio.sleep(0.05)
    session.reset_abort()

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

        # 【核心修复】：聚合所有可能包含路径的参数字段，避免短路遗漏 parent_path 或 target_dir
        path_fields = [
            "files", "file_path", "parent_path", "target_dir",
            "dir_path", "output_zip", "zip_path"
        ]
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
        seen_files = set()
        deduped_file_list = []
        for f in file_list:
            if f not in seen_files:
                seen_files.add(f)
                deduped_file_list.append(f)

        for f_str in deduped_file_list:
            records = session.file_tool._resolve_file_records(f_str)
            resolved_p = records[0][1] if records else f_str
            involved_paths.append(resolved_p)

            is_safe, verified = session.file_tool._verify_sandbox_path(resolved_p)
            if is_safe and os.path.exists(verified):
                is_d = os.path.isdir(verified)
            else:
                is_d = f_str.endswith('/') or f_str.endswith('\\')

            eff_lvl = state_mgr.sec_mgr.asset_sec_mgr.get_effective_level(resolved_p, target_root)
            raw_items_meta.append({"path": resolved_p, "is_dir": is_d, "security_level": eff_lvl})

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

        # 1. 移动与复制时的冲突与降级综合预检
        if act_name in ["move_file", "copy_file"]:
            files = effective_params.get("files", [])
            target_dir = effective_params.get("target_dir", "")
            disk_issues = await asyncio.to_thread(session.file_tool.detect_transfer_conflicts, files, target_dir)

            source_issues = [i for i in disk_issues if i.get("type") in ("source_ambiguous", "source_unresolved")]
            if source_issues:
                return False, "源资产在库中匹配到多个对象或不存在，已终止操作。", effective_params

            downgrade_issues = [i for i in disk_issues if i.get("type") == "downgrade_risk"]
            if downgrade_issues:
                is_downgrade = True
                down_item = downgrade_issues[0]
                reason = (
                    f"⚠️【全员安全降级告警】：正在将原受【{down_item['src_level']}级】保护的资产移出至【{down_item['target_level']}级】目录！"
                    f"移出后该资产及其内部所有文件都会降级为【{down_item['target_level']}级】！"
                )
                if down_item['src_level'] == 3:
                    level = state_mgr.sec_mgr.LEVEL_DESTRUCTIVE
                else:
                    level = state_mgr.sec_mgr.LEVEL_SENSITIVE

            target_conflicts = [i for i in disk_issues if i.get("type") == "target_conflict"]
            if target_conflicts:
                is_conflict = True
                conflict_name = target_conflicts[0].get("file_name", "")
                reason = f"⚠️ 目标目录已存在同名资产 `{conflict_name}`！【更换名称】免密安全；【覆盖替换原有文件】属于高危操作，必须验证管理密码。"
                level = state_mgr.sec_mgr.LEVEL_SENSITIVE

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

        # 3. 重命名切面拦截与同名冲突检测（兼容 file_path 与 file_id）
        elif act_name == "rename_file":
            new_n = str(effective_params.get("new_name", "")).strip()
            new_n_clean = os.path.basename(new_n)
            t_input = effective_params.get("file_path") or effective_params.get("file_id")
            resolved_id, resolved_path = session.file_tool._resolve_file_record(t_input)

            if resolved_path and os.path.exists(resolved_path):
                old_p = os.path.normpath(resolved_path)
                parent_dir = os.path.dirname(old_p)
                target_new_p = os.path.normpath(os.path.join(parent_dir, new_n_clean))
                if os.path.normcase(old_p) != os.path.normcase(target_new_p) and os.path.lexists(target_new_p):
                    is_conflict = True
                    level = state_mgr.sec_mgr.LEVEL_SENSITIVE
                    reason = f"⚠️ 所在目录下已存在同名资产 `{new_n_clean}`！请在弹窗中重新指定一个新名称，或取消操作。"
            level = max_asset_level if max_asset_level > 1 else level

        elif act_name == "extract_archive":
            zp = effective_params.get("zip_path", "")
            td = effective_params.get("target_dir", "")
            if not td and zp:
                td = os.path.splitext(zp)[0]
            is_s_td, v_td = session.file_tool._verify_sandbox_path(td)
            if is_s_td and os.path.exists(v_td) and os.listdir(v_td):
                is_conflict = True
                level = state_mgr.sec_mgr.LEVEL_SENSITIVE
                reason = f"⚠️ 解压目标目录 `{os.path.basename(v_td)}` 已存在资产！【更换新目录】为常规操作；【覆盖同名文件】属于危险操作，需输入管理密码。"

        elif act_name == "delete_file":
            level = state_mgr.sec_mgr.LEVEL_DESTRUCTIVE
            reason = "将资产移入系统回收站【⚠️ 破坏性操作说明：此操作无法通过撤销按钮自动还原，若需找回请在系统回收站中手动拾回】"

        if not is_conflict and not is_downgrade and not is_asset_guarded:
            if state_mgr.sec_mgr.is_action_exempt(level, action_name=act_name, is_asset_guarded=False):
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
                session.prompt_mgr.chat_history.extend(turn_generated_messages)
                session.prompt_mgr.commit_turn_transaction()
                turn_success = True
                await event_queue.put(sse_pack("done", {"session_id": req.session_id, "status": "success"}))
            else:
                safe_msgs = _keep_only_complete_tool_turns(turn_generated_messages)
                if any(isinstance(m, ToolMessage) for m in safe_msgs):
                    session.prompt_mgr.chat_history.extend(safe_msgs)
                    session.prompt_mgr.commit_turn_transaction()
                else:
                    session.prompt_mgr.rollback_turn_transaction()

        except asyncio.CancelledError:
            safe_msgs = _keep_only_complete_tool_turns(turn_generated_messages)
            if any(isinstance(m, ToolMessage) for m in safe_msgs):
                session.prompt_mgr.chat_history.extend(safe_msgs)
                session.prompt_mgr.commit_turn_transaction()
            else:
                session.prompt_mgr.rollback_turn_transaction()
            await event_queue.put(sse_pack("abort", "🛑 操作已被强制撤销。"))
        except Exception as ex:
            if not turn_success:
                safe_msgs = _keep_only_complete_tool_turns(turn_generated_messages)
                if any(isinstance(m, ToolMessage) for m in safe_msgs):
                    session.prompt_mgr.chat_history.extend(safe_msgs)
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

    if req.target_level == 3 and not state_mgr.sec_mgr.has_password_set():
        raise HTTPException(
            status_code=428,
            detail="【未初始化主密码】将资产设为 3 级（机密）必须先设置主管理密码，请先完成密码初始化！"
        )

    updated_count = 0
    total_cleaned_sub = 0
    cleaned_details = []
    pairs_for_db = []

    for item in req.items:
        raw_path = item.get("path", "")
        if not raw_path:
            continue
        is_d = bool(item.get("is_dir", False))
        is_s, v_p = session.file_tool._verify_sandbox_path(raw_path)
        if not is_s:
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

    if pairs_for_db:
        await asyncio.to_thread(session.file_tool.core.batch_update_security_levels, pairs_for_db)

    hint_msg = f"成功更新 {updated_count} 项资产的安全等级为【{req.target_level}级】。"
    if total_cleaned_sub > 0:
        hint_msg += f"（提示：已自动将下属 {total_cleaned_sub} 项子资产重置为 1 级，统一由父级目录动态继承）"

    return {
        "success": True,
        "updated_count": updated_count,
        "cleaned_sub_count": total_cleaned_sub,
        "cleaned_details": cleaned_details,
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
    session = state_mgr.get_session(session_id)
    session.abort()
    return {"success": True, "message": "已发送中止信号并清理执行状态"}


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
        "app_config": state_mgr.app_config,
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

    sec = state_mgr.app_config.setdefault("security", {})
    sec["permanent_skip_sensitive"] = req.permanent_skip_sensitive
    sec["permanent_skip_destructive"] = req.permanent_skip_destructive

    if req.new_password:
        state_mgr.sec_mgr.set_master_password(req.new_password)

    state_mgr.save_app_config()

    for s in state_mgr.sessions.values():
        s.prompt_mgr.update_target_path(target_abs)
        s.file_tool.core.config.target_path = target_abs
        s.file_tool.core.config.blacklist_paths = req.blacklist_paths

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
    session = state_mgr.get_session(session_id)
    session.abort()
    session.prompt_mgr.clear_history()
    return {"success": True, "message": "会话上下文已清空"}


@app.post("/api/db/sync")
async def sync_database_manual(session_id: str = "default"):
    session = state_mgr.get_session(session_id)
    sync_res = await asyncio.to_thread(session.file_tool.sync_database)
    v_res = await asyncio.to_thread(session.file_tool.build_vector_index)
    return {"success": True, "sync": sync_res, "vector": v_res}


if os.path.exists(WEB_DIR):
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="static")