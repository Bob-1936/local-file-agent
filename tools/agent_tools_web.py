# tools/agent_tools_web.py
# -*- coding: utf-8 -*-

import os
import asyncio
import threading
from typing import List, Optional, Any, Callable, Tuple, Dict, Union
from pydantic import BaseModel, Field
from langchain_core.tools import tool, BaseTool

from tools.file_manager_tool import FileManagerTool
from tools.scanner import execute_scan
from tools.scan_indexer import compress_scan_file, DEFAULT_COMPRESSED_FILE
from core.tokenizer import count_text_tokens, format_token_count


class EmptyInput(BaseModel):
    pass


class SearchFilesInput(BaseModel):
    query: Optional[str] = Field(default="", description="检索关键词或语义描述语句。若仅按后缀名或目录列出文件，可传空字符串或省略")
    ext: Optional[str] = Field(default=None, description="可选的文件后缀名过滤，如 'py'、'pdf'、'docx'")
    parent_path: Optional[str] = Field(default=None, description="可选的限定检索目录（文件夹绝对或相对路径）")
    min_size_mb: Optional[float] = Field(default=None, description="最小文件大小 (MB)")
    max_size_mb: Optional[float] = Field(default=None, description="最大文件大小 (MB)")
    limit: Optional[int] = Field(default=20, description="返回条数上限，默认为 20，最高 100")


class ReadFileContentInput(BaseModel):
    file_path: Optional[str] = Field(default=None, description="目标文件或文件夹路径（与 file_id 二选一）")
    file_id: Optional[int] = Field(default=None, description="目标资产在数据库中的数字主键 ID（与 file_path 二选一）")
    section: Optional[str] = Field(default="head", description="分段读取：'head'(前段，默认)、'middle'(中段)、'tail'(后段)")


class DeleteFileInput(BaseModel):
    files: List[str] = Field(description="待移入回收站的文件或文件夹绝对或相对路径列表。注意：破坏性操作不可撤回，需在系统回收站手动拾回。")


class MoveFileInput(BaseModel):
    files: List[str] = Field(description="需要移动/剪切的文件或文件夹路径列表（源文件将离开原路径）")
    target_dir: str = Field(description="目标目录的绝对或相对路径（必须是已存在的目录）")
    rename_to: Optional[str] = Field(default=None, description="若遇到同名冲突，用户指定的新文件名（仅单文件有效）")
    overwrite: Optional[bool] = Field(default=False, description="若目标目录下已存在同名资产，是否强制覆盖替换原有文件（默认为 False）")


class CopyFileInput(BaseModel):
    files: List[str] = Field(description="需要复制的文件或文件夹路径列表（源文件完好保留）")
    target_dir: str = Field(description="目标目录的绝对或相对路径（必须是已存在的目录）")
    rename_to: Optional[str] = Field(default=None, description="若遇到同名冲突，用户指定的新文件名（仅单文件有效）")
    overwrite: Optional[bool] = Field(default=False, description="若目标目录下已存在同名资产，是否强制覆盖替换原有文件（默认为 False）")


class RenameFileInput(BaseModel):
    file_path: Optional[str] = Field(default=None, description="目标文件或文件夹的相对或绝对路径（与 file_id 二选一，优先推荐传路径）")
    file_id: Optional[Union[int, str]] = Field(default=None, description="目标资产在数据库中的数字主键 ID（与 file_path 二选一）")
    new_name: str = Field(description="新文件名或新目录名（包含扩展名），严禁包含路径分隔符")


class SetSecurityLevelInput(BaseModel):
    file_path: Optional[str] = Field(default=None, description="目标资产（文件或目录）的相对或绝对路径（与 file_id 二选一）")
    file_id: Optional[Union[int, str]] = Field(default=None, description="目标资产的数字主键 ID（与 file_path 二选一）")
    target_level: int = Field(description="设定的目标安全等级：1(普通，默认)、2(敏感，操作需确认)、3(机密，受主密码保护)")


class CreateDirectoryInput(BaseModel):
    dir_path: str = Field(description="待创建的目录路径（支持相对于工作区的相对路径或绝对路径）")


class WriteFileInput(BaseModel):
    file_path: str = Field(description="目标文件路径（创建新文本文件或覆盖写入）")
    content: Optional[str] = Field(default="", description="待写入的文本正文内容（单次最大限额 5MB）")
    overwrite_name: Optional[str] = Field(default=None, description="若发生同名冲突，指定的新文件名以完成写入")
    overwrite: Optional[bool] = Field(default=False, description="目标已存在同名文件时，是否经用户授权后强制覆盖替换原有内容（默认 False）")


class CompressFilesInput(BaseModel):
    files: List[str] = Field(description="待打包压缩的文件或文件夹路径列表")
    output_zip: str = Field(description="输出的 ZIP 压缩包路径（必须位于工作区内，如 'backup.zip'）")
    rename_to: Optional[str] = Field(default=None, description="若输出压缩包存在命名冲突，指定的新包名")
    overwrite: Optional[bool] = Field(default=False, description="输出压缩包已存在时，是否经用户授权后强制覆盖替换（默认 False）")


class ExtractArchiveInput(BaseModel):
    zip_path: str = Field(description="待解压的 ZIP 压缩包绝对或相对路径")
    target_dir: Optional[str] = Field(default=None, description="解压目标目录（缺省则自动解压至同名子文件夹下）")
    overwrite: Optional[bool] = Field(default=False, description="若解压目标目录下存在同名资产，是否强制覆盖替换原有文件（默认为 False）")


class LocateOrOpenFileInput(BaseModel):
    file_id: Optional[int] = Field(default=None, description="目标资产 ID（与 file_path 二选一）")
    file_path: Optional[str] = Field(default=None, description="目标资产路径（与 file_id 二选一）")
    action: str = Field(default="locate", description="操作类型：'locate' 定位高亮；'open' 调用关联程序打开")


def _build_interrupt_payload(reason: str, display_message: str) -> Dict[str, Any]:
    return {
        "__interrupt__": True,
        "status": "rejected",
        "reason": reason,
        "message": display_message
    }


def get_agent_tools(
        file_tool: FileManagerTool,
        intercept_async_callback: Optional[Callable[[str, dict], Any]] = None,
        token_warning_async_callback: Optional[Callable[[str, int, int], Any]] = None,
        attach_scan_callback: Optional[Callable[[str, str], None]] = None,
        abort_event: Optional[threading.Event] = None,
        check_abort_func: Optional[Callable[[], bool]] = None,
        platform: str = "DeepSeek"
) -> List[BaseTool]:

    def _is_aborted() -> bool:
        if abort_event and abort_event.is_set():
            return True
        if check_abort_func and check_abort_func():
            return True
        return False

    async def _check_security(act_name: str, act_params: dict) -> Tuple[bool, str, dict]:
        if intercept_async_callback:
            return await intercept_async_callback(act_name, act_params)
        return True, "", act_params

    @tool("scan_directory", args_schema=EmptyInput)
    async def scan_directory_tool() -> Union[str, Dict[str, Any]]:
        """物理扫描本地授权工作区目录并重新生成压缩文件树全景。"""
        if _is_aborted():
            return _build_interrupt_payload("操作中止", "🛑 扫描操作已被主动中止。")

        passed, reason, _ = await _check_security("scan_directory", {})
        if not passed:
            return _build_interrupt_payload(reason=reason, display_message=f"🛑 操作已被安全策略拦截: {reason}")

        raw_output = await asyncio.to_thread(execute_scan, abort_event=abort_event)

        if _is_aborted():
            return _build_interrupt_payload("操作中止", "🛑 扫描操作已被主动中止。")

        if not raw_output or not os.path.exists(raw_output):
            return "❌ 扫描执行失败，请检查配置路径是否正确。"

        try:
            await asyncio.to_thread(file_tool.sync_database)
            await asyncio.to_thread(file_tool.build_vector_index, abort_event=abort_event)
        except Exception as e:
            print(f"[-] 扫描联动同步告警: {e}", flush=True)

        comp_file = await asyncio.to_thread(
            compress_scan_file,
            input_file=raw_output,
            output_file=DEFAULT_COMPRESSED_FILE
        )
        if not comp_file or not os.path.exists(comp_file):
            return "❌ 聚类压缩索引生成失败。"

        with open(comp_file, "r", encoding="utf-8") as f:
            markdown_tree = f.read()

        tree_tokens = count_text_tokens(markdown_tree, platform=platform)
        threshold = file_tool._get_token_warning_threshold()

        if tree_tokens > threshold and token_warning_async_callback:
            user_agreed = await token_warning_async_callback("scan_directory", tree_tokens, threshold)
            if not user_agreed:
                return _build_interrupt_payload(
                    reason="文件树Token超额且用户取消载入",
                    display_message=f"🛑 **已终止操作**：扫描生成的宏观文件树数据量过大 (~{format_token_count(tree_tokens)} Tokens)，已被用户取消载入。"
                )

        if attach_scan_callback:
            attach_scan_callback("工具数据: scan_directory", markdown_tree)

        return (
            "✅ 磁盘物理扫描与聚类压缩已顺利完成！\n"
            f"最新全景文件树 (~{format_token_count(tree_tokens)} Tokens) 已成功载入到当前上下文的【临时资料库】中。\n"
            "你可以直接基于该资料库中的文件树结构回答用户的提问与分析需求。"
        )

    @tool("search_files", args_schema=SearchFilesInput)
    async def search_files_tool(
            query: Optional[str] = "",
            ext: Optional[str] = None,
            parent_path: Optional[str] = None,
            min_size_mb: Optional[float] = None,
            max_size_mb: Optional[float] = None,
            limit: Optional[int] = 20
    ) -> Union[str, Dict[str, Any]]:
        """在数据库中检索本地资产。采用 RRF 融合算法整合向量语义、FTS5 全文倒排与文件名精确匹配。"""
        params = {"query": query, "ext": ext, "parent_path": parent_path}
        passed, reason, _ = await _check_security("search_files", params)
        if not passed:
            return _build_interrupt_payload(reason=reason, display_message=f"🛑 检索已被安全策略拦截: {reason}")

        res = await asyncio.to_thread(
            file_tool.search_files,
            query=query or "", ext=ext, parent_path=parent_path,
            min_size_mb=min_size_mb, max_size_mb=max_size_mb, limit=limit or 20
        )
        if not isinstance(res, dict) or not res.get("success"):
            return f"❌ 检索失败: {res.get('message', '未知错误') if isinstance(res, dict) else '服务异常'}"
        return file_tool.format_search_results_for_llm(res.get("data", []), res.get("count", 0))

    @tool("read_file_content", args_schema=ReadFileContentInput)
    async def read_file_content_tool(
            file_path: Optional[str] = None,
            file_id: Optional[int] = None,
            section: Optional[str] = "head"
    ) -> Union[str, Dict[str, Any]]:
        """
        安全读取沙箱内指定文本文件的内容。若目标为文件夹，则直接罗列其下直属子资产。
        【受资产安全等级保护】：读取 2 级资产需人工确认，读取 3 级机密资产强制验证主管理密码！
        """
        params = {"file_path": file_path, "file_id": file_id, "section": section}
        passed, reason, _ = await _check_security("read_file_content", params)
        if not passed:
            return _build_interrupt_payload(reason=reason, display_message=f"🛑 读取已被安全策略拦截: {reason}")

        res = await asyncio.to_thread(
            file_tool.read_file_content,
            file_path=file_path, file_id=file_id, section=section or "head"
        )
        if not isinstance(res, dict):
            return "❌ 读取失败: 底层读取服务返回了无效结果结构。"
        return res.get("message", "")

    @tool("delete_file", args_schema=DeleteFileInput)
    async def delete_file_tool(files: List[str]) -> Union[str, Dict[str, Any]]:
        """将指定名单的文件或目录移入系统回收站。注意：破坏性操作不可自动撤回，若需找回请用户在系统回收站手动拾回。"""
        params = {"files": files}
        passed, reason, final_params = await _check_security("delete_file", params)
        if not passed:
            return _build_interrupt_payload(reason=reason, display_message=f"🛑 操作已被安全拦截拒绝: {reason}")

        effective_files = final_params.get("files", files) if isinstance(final_params, dict) else files
        res = await asyncio.to_thread(file_tool.delete_file, files=effective_files)
        if not isinstance(res, dict):
            return "❌ 删除失败: 底层执行服务返回了无效结果结构。"
        return res.get("message", "")

    @tool("move_file", args_schema=MoveFileInput)
    async def move_file_tool(
            files: List[str],
            target_dir: str,
            rename_to: Optional[str] = None,
            overwrite: Optional[bool] = False
    ) -> Union[str, Dict[str, Any]]:
        """
        批量剪切移动文件到沙箱内的新目录（源文件将移走）。
        - 遇到同名冲突可由用户选择覆盖替换、换名或取消；
        - 遇到将资产从高安全等级移出至低等级目录，强制弹出安全降级警报。
        """
        params = {"files": files, "target_dir": target_dir, "rename_to": rename_to, "overwrite": bool(overwrite)}
        passed, reason, final_params = await _check_security("move_file", params)
        if not passed:
            return _build_interrupt_payload(reason=reason, display_message=f"🛑 操作已被安全拦截拒绝: {reason}")

        eff_params = final_params if isinstance(final_params, dict) else params
        eff_rename = eff_params.get("rename_to", rename_to)
        eff_overwrite = bool(eff_params.get("overwrite", overwrite))

        res = await asyncio.to_thread(
            file_tool.move_file,
            files=files,
            target_dir=target_dir,
            rename_to=eff_rename,
            overwrite=eff_overwrite
        )
        if not isinstance(res, dict):
            return "❌ 移动失败: 底层服务返回了无效结果结构。"
        if res.get("is_conflict"):
            return _build_interrupt_payload("命名冲突", res.get("message", "目标存在同名资产，已终止覆盖"))
        return res.get("message", "")

    @tool("copy_file", args_schema=CopyFileInput)
    async def copy_file_tool(
            files: List[str],
            target_dir: str,
            rename_to: Optional[str] = None,
            overwrite: Optional[bool] = False
    ) -> Union[str, Dict[str, Any]]:
        """批量复制文件/目录到沙箱内的新目录（源资产完好保留）。遇到同名冲突可由用户选择覆盖替换、换名或取消。"""
        params = {"files": files, "target_dir": target_dir, "rename_to": rename_to, "overwrite": bool(overwrite)}
        passed, reason, final_params = await _check_security("copy_file", params)
        if not passed:
            return _build_interrupt_payload(reason=reason, display_message=f"🛑 操作已被安全拦截拒绝: {reason}")

        eff_params = final_params if isinstance(final_params, dict) else params
        eff_rename = eff_params.get("rename_to", rename_to)
        eff_overwrite = bool(eff_params.get("overwrite", overwrite))

        res = await asyncio.to_thread(
            file_tool.copy_file,
            files=files,
            target_dir=target_dir,
            rename_to=eff_rename,
            overwrite=eff_overwrite
        )
        if not isinstance(res, dict):
            return "❌ 复制失败: 底层服务返回了无效结果结构。"
        if res.get("is_conflict"):
            return _build_interrupt_payload("命名冲突", res.get("message", "目标存在同名资产，已终止覆盖"))
        return res.get("message", "")

    @tool("create_directory", args_schema=CreateDirectoryInput)
    async def create_directory_tool(dir_path: str) -> Union[str, Dict[str, Any]]:
        """在沙箱工作区内新建目录文件夹。遇同名存在则直接拦截报错，记录可撤销流水。"""
        params = {"dir_path": dir_path}
        passed, reason, final_params = await _check_security("create_directory", params)
        if not passed:
            return _build_interrupt_payload(reason=reason, display_message=f"🛑 新建目录已被安全策略拦截: {reason}")

        target_dir = final_params.get("dir_path", dir_path) if isinstance(final_params, dict) else dir_path
        res = await asyncio.to_thread(file_tool.create_directory, dir_path=target_dir)
        if not isinstance(res, dict):
            return "❌ 创建目录失败: 底层服务返回了无效结构。"
        if res.get("is_conflict"):
            return _build_interrupt_payload("命名冲突", res.get("message", "目录已存在"))
        return res.get("message", "")

    @tool("write_file", args_schema=WriteFileInput)
    async def write_file_tool(
            file_path: str,
            content: Optional[str] = "",
            overwrite_name: Optional[str] = None,
            overwrite: Optional[bool] = False
    ) -> Union[str, Dict[str, Any]]:
        """新建或写入文本文件。同名冲突直接拦截询问换名，经用户授权后可覆盖替换。单次限额 5MB。"""
        params = {"file_path": file_path, "overwrite_name": overwrite_name, "overwrite": bool(overwrite)}
        passed, reason, final_params = await _check_security("write_file", params)
        if not passed:
            return _build_interrupt_payload(reason=reason, display_message=f"🛑 写入已被安全策略拦截: {reason}")

        eff_p = final_params if isinstance(final_params, dict) else params
        eff_ow_name = eff_p.get("overwrite_name", overwrite_name)
        eff_ow = bool(eff_p.get("overwrite", overwrite))
        res = await asyncio.to_thread(
            file_tool.write_file,
            file_path=file_path, content=content or "",
            overwrite_name=eff_ow_name, overwrite=eff_ow
        )
        if not isinstance(res, dict):
            return "❌ 写入失败: 底层服务返回了无效结构。"
        if res.get("is_conflict"):
            return _build_interrupt_payload("命名冲突", res.get("message", "目标文件已存在"))
        return res.get("message", "")

    @tool("compress_files", args_schema=CompressFilesInput)
    async def compress_files_tool(
            files: List[str],
            output_zip: str,
            rename_to: Optional[str] = None,
            overwrite: Optional[bool] = False
    ) -> Union[str, Dict[str, Any]]:
        """将指定的文件或文件夹打包制作成 ZIP 压缩文件。若输出压缩包存在则拦截换名，经用户授权后可覆盖替换。"""
        params = {"files": files, "output_zip": output_zip, "rename_to": rename_to, "overwrite": bool(overwrite)}
        passed, reason, final_params = await _check_security("compress_files", params)
        if not passed:
            return _build_interrupt_payload(reason=reason, display_message=f"🛑 打包已被安全策略拦截: {reason}")

        eff_p = final_params if isinstance(final_params, dict) else params
        eff_rn = eff_p.get("rename_to", rename_to)
        eff_ow = bool(eff_p.get("overwrite", overwrite))
        res = await asyncio.to_thread(
            file_tool.compress_files,
            files=files, output_zip=output_zip, rename_to=eff_rn, overwrite=eff_ow
        )
        if not isinstance(res, dict):
            return "❌ 压缩失败: 底层服务返回了无效结构。"
        if res.get("is_conflict"):
            return _build_interrupt_payload("命名冲突", res.get("message", "目标压缩包已存在"))
        return res.get("message", "")

    @tool("extract_archive", args_schema=ExtractArchiveInput)
    async def extract_archive_tool(
            zip_path: str,
            target_dir: Optional[str] = None,
            overwrite: Optional[bool] = False
    ) -> Union[str, Dict[str, Any]]:
        """安全解压 ZIP 压缩包至目标目录（受 Zip Slip 路径穿越防御、压缩炸弹预检与同名冲突阻断保护）。支持 overwrite 覆盖模式。"""
        params = {"zip_path": zip_path, "target_dir": target_dir, "overwrite": bool(overwrite)}
        passed, reason, final_params = await _check_security("extract_archive", params)
        if not passed:
            return _build_interrupt_payload(reason=reason, display_message=f"🛑 解压已被安全策略拦截: {reason}")

        eff_params = final_params if isinstance(final_params, dict) else params
        eff_target = eff_params.get("target_dir", target_dir)
        eff_overwrite = bool(eff_params.get("overwrite", overwrite))

        res = await asyncio.to_thread(
            file_tool.extract_archive,
            zip_path=zip_path,
            target_dir=eff_target,
            overwrite=eff_overwrite
        )
        if not isinstance(res, dict):
            return "❌ 解压失败: 底层服务返回了无效结构。"
        if res.get("is_conflict"):
            return _build_interrupt_payload("解压命名冲突", res.get("message", "目标存在同名资产，已终止覆盖"))
        return res.get("message", "")

    @tool("find_duplicate_files", args_schema=EmptyInput)
    async def find_duplicate_files_tool() -> Union[str, Dict[str, Any]]:
        """基于 SHA-256 哈希排查当前工作区已被索引的重复内容文件。"""
        passed, reason, _ = await _check_security("find_duplicate_files", {})
        if not passed:
            return _build_interrupt_payload(reason=reason, display_message=f"🛑 排查已被安全策略拦截: {reason}")

        res = await asyncio.to_thread(file_tool.find_duplicate_files)
        if not isinstance(res, dict) or not res.get("success"):
            return f"❌ 排查失败: {res.get('message', '') if isinstance(res, dict) else '服务异常'}"
        return file_tool.format_duplicates_for_llm(res.get("data", {}))

    @tool("get_storage_insights", args_schema=EmptyInput)
    async def get_storage_insights_tool() -> Union[str, Dict[str, Any]]:
        """获取工作区磁盘存储空间透视体检报告。"""
        passed, reason, _ = await _check_security("get_storage_insights", {})
        if not passed:
            return _build_interrupt_payload(reason=reason, display_message=f"🛑 体检已被安全策略拦截: {reason}")

        res = await asyncio.to_thread(file_tool.get_storage_insights)
        if not isinstance(res, dict) or not res.get("success"):
            return f"❌ 体检失败: {res.get('message', '') if isinstance(res, dict) else '服务异常'}"
        return file_tool.format_storage_insights_for_llm(res.get("data", {}))

    @tool("rename_file", args_schema=RenameFileInput)
    async def rename_file_tool(
            new_name: str,
            file_path: Optional[str] = None,
            file_id: Optional[Union[int, str]] = None
    ) -> Union[str, Dict[str, Any]]:
        """
        根据路径或数字主键 ID 对指定文件或目录进行重命名。
        - 优先推荐直接传入 file_path（相对工作区路径或绝对路径）；
        - 遇同名冲突直接弹出窗口提示重新命名或取消，绝不直接物理踩踏。
        """
        params = {"file_path": file_path, "file_id": file_id, "new_name": new_name}
        passed, reason, final_params = await _check_security("rename_file", params)
        if not passed:
            return _build_interrupt_payload(reason=reason, display_message=f"🛑 重命名已被安全拦截拒绝: {reason}")

        eff_params = final_params if isinstance(final_params, dict) else params
        eff_new_name = eff_params.get("new_name", new_name)
        eff_path = eff_params.get("file_path", file_path)
        eff_id = eff_params.get("file_id", file_id)

        res = await asyncio.to_thread(file_tool.rename_file, file_path=eff_path, file_id=eff_id, new_name=eff_new_name)
        if not isinstance(res, dict):
            return "❌ 重命名失败: 底层服务返回了无效结构。"
        if not res.get("success"):
            return _build_interrupt_payload("重命名失败", res.get("message", "重命名遇到错误"))
        return res.get("message", "")

    @tool("set_security_level", args_schema=SetSecurityLevelInput)
    async def set_security_level_tool(
            target_level: int,
            file_path: Optional[str] = None,
            file_id: Optional[Union[int, str]] = None
    ) -> Union[str, Dict[str, Any]]:
        """
        设置特定文件或文件夹的安全等级 (1普通 / 2敏感 / 3机密)。
        - 升为 3 级（机密）：系统强制要求验证主管理密码；
        - 升为 2 级（敏感）：系统挂起弹窗由用户确认；
        - 降级操作：无论降至几级，均触发安全降级警报；原为 3 级降级时强制验证主密码。
        """
        params = {"file_path": file_path, "file_id": file_id, "target_level": target_level}
        passed, reason, final_params = await _check_security("set_security_level", params)
        if not passed:
            return _build_interrupt_payload(reason=reason, display_message=f"🛑 安全等级调整已被安全策略拦截: {reason}")

        eff_params = final_params if isinstance(final_params, dict) else params
        eff_path = eff_params.get("file_path", file_path)
        eff_id = eff_params.get("file_id", file_id)
        eff_lvl = int(eff_params.get("target_level", target_level))

        res = await asyncio.to_thread(file_tool.set_security_level, file_path=eff_path, file_id=eff_id, target_level=eff_lvl)
        if not isinstance(res, dict):
            return "❌ 等级修改失败: 底层服务返回了无效结构。"
        if not res.get("success"):
            return _build_interrupt_payload("安全等级调整未生效", res.get("message", "调整遇到错误"))
        return res.get("message", "")

    @tool("locate_or_open_file", args_schema=LocateOrOpenFileInput)
    async def locate_or_open_file_tool(
            file_id: Optional[int] = None,
            file_path: Optional[str] = None,
            action: Optional[str] = "locate"
    ) -> Union[str, Dict[str, Any]]:
        """在系统资源管理器中高亮定位选中文件，或直接调用系统默认程序打开文件。"""
        params = {"file_id": file_id, "file_path": file_path, "action": action}
        passed, reason, _ = await _check_security("locate_or_open_file", params)
        if not passed:
            return _build_interrupt_payload(reason=reason, display_message=f"🛑 系统调用已被安全策略拦截: {reason}")

        res = await asyncio.to_thread(
            file_tool.open_or_locate_file,
            file_path=file_path, file_id=file_id, action=action or "locate"
        )
        if not isinstance(res, dict):
            return "❌ 打开/定位失败: 底层服务返回了无效结构。"
        return res.get("message", "")

    return [
        scan_directory_tool, search_files_tool, read_file_content_tool,
        delete_file_tool, move_file_tool, copy_file_tool,
        create_directory_tool, write_file_tool, compress_files_tool, extract_archive_tool,
        find_duplicate_files_tool, get_storage_insights_tool,
        rename_file_tool, set_security_level_tool, locate_or_open_file_tool
    ]


get_web_agent_tools = get_agent_tools