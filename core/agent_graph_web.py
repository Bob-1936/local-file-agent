# core/agent_graph_web.py
# -*- coding: utf-8 -*-

import re
import json
import uuid
import inspect
from typing import (
    Annotated,
    Sequence,
    TypedDict,
    List,
    Dict,
    Any,
    Optional,
    Callable,
    Union,
    Awaitable
)
from langchain_core.messages import BaseMessage, SystemMessage, AIMessage, HumanMessage, ToolMessage
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.tools import BaseTool
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages


# ==============================================================================
# 1. 状态契约定义（恢复强类型 is_interrupted 安全标志）
# ==============================================================================

class WebAgentState(TypedDict):
    """
    Web 异步 Agent 全局状态契约
    - messages: 承载整个执行生命周期的上下文消息序列（带累加 Reducer）
    - turn_count: 交互轮次计数器，防止长程死循环
    - is_interrupted: 核心强类型布尔标志，表征当前批次是否遭遇用户拒绝或主动终止
    """
    messages: Annotated[Sequence[BaseMessage], add_messages]
    turn_count: int
    is_interrupted: bool


# ==============================================================================
# 2. 思考模型辅助组件（DeepSeek-R1 / 开源模型适配）
# ==============================================================================

def extract_fallback_tool_call(text: str) -> Optional[Dict[str, Any]]:
    """
    针对某些开源思考模型（如 DeepSeek-R1），当其在思考/正文中以 Markdown 形式直接输出 JSON 时，
    进行严谨的括号深度容错提取，恢复为原生 tool_call。
    """
    if not text:
        return None
    # 剥离内部可能包裹的思考标签
    cleaned = re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.IGNORECASE).strip()
    code_blocks = re.findall(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned, re.IGNORECASE)
    candidates = code_blocks if code_blocks else [cleaned]

    for candidate in candidates:
        idx = 0
        n = len(candidate)
        while idx < n:
            start_pos = candidate.find('{', idx)
            if start_pos == -1:
                break
            depth = 0
            in_string = False
            escape = False
            end_pos = -1

            for i in range(start_pos, n):
                char = candidate[i]
                if escape:
                    escape = False
                    continue
                if char == '\\':
                    escape = True
                    continue
                if char == '"':
                    in_string = not in_string
                    continue
                if not in_string:
                    if char == '{':
                        depth += 1
                    elif char == '}':
                        depth -= 1
                        if depth == 0:
                            end_pos = i + 1
                            break

            if end_pos != -1:
                sub_str = candidate[start_pos:end_pos].strip()
                try:
                    obj = json.loads(sub_str)
                    if isinstance(obj, dict) and ("action" in obj or "name" in obj):
                        act = obj.get("action") or obj.get("name")
                        params = obj.get("parameters") or obj.get("args") or {}
                        return {
                            "id": f"call_{uuid.uuid4().hex[:8]}",
                            "name": str(act).strip(),
                            "args": params if isinstance(params, dict) else {},
                            "type": "tool_call"
                        }
                except Exception:
                    pass
                idx = start_pos + 1
            else:
                idx = start_pos + 1
    return None


class WebThinkingStreamParser:
    """
    工业级思考流与正文分流解析器：
    - 深度解包 Claude / Anthropic / OpenAI 原生复合 ContentBlock（包含 dict, text, signature 等）；
    - 坚决杜绝直接对 Python 原生列表/字典进行 str() 强转导致的前端乱码；
    - 分离提取思考过程 (<think>...</think>) 与纯净的最终 Markdown 文本。
    """
    def __init__(self):
        pass

    @classmethod
    def normalize_content_to_str(cls, content: Any) -> str:
        """递归解析复杂的多模态或分块 content，提取纯文本 Markdown，过滤 signature 等元数据"""
        if content is None:
            return ""
        if isinstance(content, str):
            clean_str = content.strip()
            # 容错：如果字符串本身就是 Python repr 格式的 list 字符串，进行安全恢复
            if clean_str.startswith("[{") and clean_str.endswith("}]") and ("'type'" in clean_str or '"type"' in clean_str):
                try:
                    import ast
                    evaluated = ast.literal_eval(clean_str)
                    if isinstance(evaluated, list):
                        return cls.normalize_content_to_str(evaluated)
                except Exception:
                    pass
            return content

        if isinstance(content, list):
            text_pieces = []
            for block in content:
                if isinstance(block, dict):
                    # 优先提取标准文本块
                    if block.get("type") == "text":
                        text_pieces.append(block.get("text", ""))
                    elif block.get("type") == "thinking":
                        # 保留思考标签格式，由后续正则统一分流
                        t_text = block.get("thinking", "")
                        text_pieces.append(f"<think>{t_text}</think>")
                    elif "text" in block:
                        text_pieces.append(str(block.get("text", "")))
                elif hasattr(block, "text"):
                    text_pieces.append(str(getattr(block, "text", "")))
                elif isinstance(block, str):
                    text_pieces.append(block)
            return "".join(text_pieces)

        if isinstance(content, dict):
            if content.get("type") == "text":
                return str(content.get("text", ""))
            if "text" in content:
                return str(content.get("text", ""))

        return str(content)

    def process_full_text(self, raw_input: Any) -> Dict[str, str]:
        """将任意类型的 raw_input 解包并拆分为思考链与最终正文"""
        text = self.normalize_content_to_str(raw_input)
        if not text:
            return {"thought": "", "text": ""}

        thought_match = re.search(r"<think>([\s\S]*?)(?:</think>|$)", text, flags=re.IGNORECASE)
        if thought_match:
            thought_part = thought_match.group(1)
            text_part = re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.IGNORECASE).strip()
            if "</think>" not in text.lower():
                text_part = ""
            return {"thought": thought_part, "text": text_part}
        else:
            return {"thought": "", "text": text}


# ==============================================================================
# 3. 异步工业级安全工具批处理节点（彻底修复原生 ToolNode 连环穿透问题）
# ==============================================================================

HIGH_RISK_TOOLS = {"delete_file", "move_file", "copy_file", "rename_file"}


class SafeAsyncToolBatchNode:
    """
    异步安全工具批处理节点（替代脆弱的原生 ToolNode）
    - 解决【连环弹窗轰炸/误写穿透】：单轮出现多个工具调用时，只要其中一个被用户拒绝/取消，
      后续所有未执行的工具立即熔断短路，绝不触碰后端磁盘、不唤起 Web 弹窗，并自动回填废弃说明。
    - 高危工具（delete_file/move_file/copy_file/rename_file）执行异常时同样熔断，避免基于错误假设继续改动文件。
    """
    def __init__(self, tools: List[BaseTool]):
        self.tool_map: Dict[str, BaseTool] = {t.name: t for t in tools}

    async def __call__(self, state: WebAgentState) -> Dict[str, Any]:
        messages = state.get("messages", [])
        last_message = messages[-1] if messages else None

        if not isinstance(last_message, AIMessage) or not getattr(last_message, "tool_calls", None):
            return {"messages": [], "is_interrupted": False}

        results: List[ToolMessage] = []
        batch_interrupted = False
        abort_reason = ""

        for tc in last_message.tool_calls:
            call_id = tc.get("id") or f"call_{uuid.uuid4().hex[:8]}"
            tool_name = tc.get("name", "")
            tool_args = tc.get("args", {})

            # 🛡️ 核心熔断机制：若前序工具已被拒绝或高危异常，本批次后续工具秒级阻断
            if batch_interrupted:
                results.append(ToolMessage(
                    content=f"⚠️ 前序操作已被用户拒绝或取消（原因: {abort_reason}），本操作已自动废弃执行。",
                    name=tool_name,
                    tool_call_id=call_id,
                    status="error",
                    additional_kwargs={"aborted_by_previous": True}
                ))
                continue

            tool_instance = self.tool_map.get(tool_name)
            if not tool_instance:
                results.append(ToolMessage(
                    content=f"❌ 未知或未注册的系统工具: `{tool_name}`",
                    name=tool_name,
                    tool_call_id=call_id,
                    status="error"
                ))
                continue

            try:
                # 兼容异步 ainvoke 与同步 invoke
                if hasattr(tool_instance, "ainvoke"):
                    tool_output = await tool_instance.ainvoke(tool_args)
                else:
                    tool_output = tool_instance.invoke(tool_args)

                # 结构化判定是否触发拒绝/中断，并清洗输出为纯文本
                is_rejected = False
                final_content = ""

                if isinstance(tool_output, dict):
                    if tool_output.get("__interrupt__") or tool_output.get("status") == "rejected":
                        is_rejected = True
                        abort_reason = tool_output.get("message", "用户拒绝操作")
                        final_content = str(tool_output.get("message", "操作已被安全拦截拒绝。"))
                    else:
                        final_content = str(tool_output.get("message") or tool_output.get("content") or tool_output)
                elif isinstance(tool_output, str):
                    final_content = tool_output
                    if any(flag in tool_output for flag in [
                        "🛑 操作已被安全拦截拒绝",
                        "用户在界面端拒绝了该操作",
                        "已被用户主动取消载入",
                        "🛑 扫描操作已被主动中止"
                    ]):
                        is_rejected = True
                        abort_reason = "用户在界面端拒绝或主动取消"
                else:
                    final_content = str(tool_output)

                if is_rejected:
                    batch_interrupted = True
                    results.append(ToolMessage(
                        content=final_content,
                        name=tool_name,
                        tool_call_id=call_id,
                        status="error",
                        additional_kwargs={"is_rejected": True}
                    ))
                else:
                    results.append(ToolMessage(
                        content=final_content,
                        name=tool_name,
                        tool_call_id=call_id,
                        status="success"
                    ))

            except Exception as ex:
                results.append(ToolMessage(
                    content=f"❌ 工具 `{tool_name}` 执行发生未捕获异常: {str(ex)}",
                    name=tool_name,
                    tool_call_id=call_id,
                    status="error"
                ))
                if tool_name in HIGH_RISK_TOOLS:
                    batch_interrupted = True
                    abort_reason = f"高危工具 `{tool_name}` 执行异常: {str(ex)}"

        return {
            "messages": results,
            "is_interrupted": batch_interrupted
        }


# ==============================================================================
# 4. 图构建器（兼具动态 Prompt 感知、步数硬防与异步调度）
# ==============================================================================

def build_web_file_agent_graph(
    model: BaseChatModel,
    tools: List[BaseTool],
    get_system_instruction: Optional[Union[str, Callable[[], str], Callable[[], Awaitable[str]]]] = None,
    max_turns: int = 8,
    checkpointer: Optional[Any] = None,
    system_instruction: Optional[Union[str, Callable[[], str], Callable[[], Awaitable[str]]]] = None,  # 👈 增加兼容入参
    **kwargs
):
    """
    构建高健壮性、防穿透的 Web 异步文件管理 Agent 状态图
    :param model: 标准 ChatModel 实例
    :param tools: 工具套件列表
    :param get_system_instruction: 动态系统指令（支持静态文本、同步回调或异步回调）
    :param max_turns: 交互轮次上限
    :param checkpointer: 状态持久化检查点
    """
    # 自动合并参数别名
    actual_sys_instruction = get_system_instruction or system_instruction

    model_with_tools = model.bind_tools(tools)
    valid_tool_names = {t.name for t in tools}

    async def _resolve_system_instruction() -> str:
        """动态解析最新的系统提示词"""
        if not actual_sys_instruction:
            return ""
        if callable(actual_sys_instruction):
            res = actual_sys_instruction()
            if inspect.isawaitable(res):
                return await res
            return str(res)
        return str(actual_sys_instruction)

    async def agent_node(state: WebAgentState) -> Dict[str, Any]:
        curr_turn = state.get("turn_count", 0) + 1
        raw_msgs = list(state.get("messages", []))

        # 🛡️ 解决【时空脱节】：每轮循环动态解析当前最新的 System Prompt（如工作区、上下文变更）
        current_sys_text = await _resolve_system_instruction()
        call_msgs: List[BaseMessage] = []
        if current_sys_text:
            call_msgs.append(SystemMessage(content=current_sys_text))

        for m in raw_msgs:
            if not isinstance(m, SystemMessage):
                call_msgs.append(m)

        # 步数上限硬防御：强制总结并剥离工具
        if curr_turn >= max_turns:
            call_msgs.append(HumanMessage(
                content="【系统提示】执行步骤已达安全上限。请立即根据目前已知的所有操作结果，直接向用户输出简短的最终总结，严禁再调用任何工具。"
            ))
            response = await model.ainvoke(call_msgs)
            if hasattr(response, "tool_calls"):
                response.tool_calls = []
            return {
                "messages": [response],
                "turn_count": curr_turn,
                "is_interrupted": False
            }

        response = await model_with_tools.ainvoke(call_msgs)

        # 针对思考模型正文内嵌 JSON 块进行容错提取恢复
        if (not hasattr(response, "tool_calls") or not response.tool_calls) and response.content:
            raw_text = response.content if isinstance(response.content, str) else str(response.content)
            fallback_call = extract_fallback_tool_call(raw_text)
            if fallback_call and fallback_call["name"] in valid_tool_names:
                response.tool_calls = [fallback_call]

        return {
            "messages": [response],
            "turn_count": curr_turn,
            "is_interrupted": False
        }

    # ================= 路由器 1：Agent 节点执行后的分流 =================
    def agent_router(state: WebAgentState) -> str:
        if state.get("turn_count", 0) >= max_turns:
            return END

        messages = state.get("messages", [])
        if not messages:
            return END

        last_message = messages[-1]
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            return "tools"

        return END

    # ================= 路由器 2：Tools 节点执行后的安全分流 =================
    def tools_post_router(state: WebAgentState) -> str:
        # 🛡️ 核心安全防线：强类型布尔判定，只要触发中断/拒绝/高危异常，无条件停止流转直达 END
        if state.get("is_interrupted", False):
            return END

        if state.get("turn_count", 0) >= max_turns:
            return END

        return "agent"

    # 构建并编译状态图
    workflow = StateGraph(WebAgentState)
    workflow.add_node("agent", agent_node)
    workflow.add_node("tools", SafeAsyncToolBatchNode(tools))

    workflow.add_edge(START, "agent")
    workflow.add_conditional_edges("agent", agent_router, {"tools": "tools", END: END})
    workflow.add_conditional_edges("tools", tools_post_router, {"agent": "agent", END: END})

    return workflow.compile(checkpointer=checkpointer)