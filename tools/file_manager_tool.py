# tools/file_manager_tool.py
# -*- coding: utf-8 -*-

import os
import json
import shutil
import subprocess
import platform
import sqlite3
import re
import uuid
import time
import zipfile
import logging
import threading
import itertools
import unicodedata
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger("FileManagerTool")

from core.indexer_engine import (
    IndexerCore,
    get_local_text_model,
    tokenize_text,
    _EMBED_INFERENCE_LOCK
)
from core.tokenizer import count_text_tokens
from core.security import SecurityManager, AssetSecurityManager


class FileManagerTool:
    """
    Agent 资产全功能管理套件 (2026 Web 工业级增强与安全等级扩展版)
    - 全局单例安全等级管理器绑定：识别 1/2/3 级生效安全等级，精准探测跨目录移动降级风险；
    - 原地移动自愈反馈：检测到源与目标完全相同时显式返回成功说明，消除模型试错重试行为；
    - 降级真生效：用户批准降级后，物理抹除旧显式等级，级联同步 SQLite 数据库；
    - 5 维物理安全预检：磁盘容量、路径穿越、覆盖冲突换名、符号链接、压缩炸弹；
    - 制作压缩包 (ZIP) 与安全解压 (防 Zip Slip / 炸弹 / 软链接攻击)；
    - 新建目录 (mkdir) 与安全文本写入 (write_file)；
    - 命名冲突与降级严格阻断：区分【覆盖替换】与【换名】，禁止盲目覆盖；
    - 覆盖安全备份：覆盖替换前产生物理暂存快照，支持原子撤回原样还原；
    - 原生原子撤销引擎 (Undo Stack)：支持连续多步撤销、深层目录级联恢复与精细变动追踪；
    - 破坏性操作提示：明确告知移入回收站后不可自动还原，需用户手动拾回；
    - 【新增】AI 资产安全等级调整套件 (set_security_level)：支持物理灾备、数据库级联与原子撤销；
    - 【重构】AI 重命名文件/文件夹自愈解析：彻底兼容 file_path 与 file_id，支持未索引自愈入库。
    """

    def __init__(self, config_path: str = None):
        self.core = IndexerCore(config_path)
        data_dir = os.path.join(self.core.config.base_dir, "data")
        # 始终通过单例工厂获取全局共享的资产安全管理器
        self.asset_sec_mgr = AssetSecurityManager.get_instance(data_dir)

    # ==================== 沙箱安全基线与辅助校验 ====================

    def _verify_sandbox_path(self, target_file_path: str, respect_blacklist: bool = True) -> Tuple[bool, str]:
        """路径沙箱安全校验与黑名单拦截：严格锚定至授权工作区，绝不越界，严格过滤黑名单

        :param respect_blacklist: 是否叠加黑名单判定。覆盖快照目录
            (`.local_agent_undo_backups`) 属于"沙箱内但必须永不入库"的系统保护目录，
            它需要归属校验通过、却必须跳过黑名单判定，因此单独提供此开关。
        """
        if not target_file_path:
            return False, "路径不能为空。"

        try:
            norm_root = os.path.realpath(os.path.normpath(os.path.abspath(self.core.config.target_path)))
            raw_path_str = str(target_file_path).strip()
            raw_path_str = unicodedata.normalize('NFC', raw_path_str)

            is_posix_root_style = (raw_path_str.startswith('/') or raw_path_str.startswith('\\')) and not (
                len(raw_path_str) > 1 and raw_path_str[1] == ':'
            )
            if is_posix_root_style:
                clean_rel = raw_path_str.lstrip('/\\')
                candidate_path = os.path.join(norm_root, clean_rel)
                norm_target = os.path.realpath(os.path.normpath(candidate_path))
            elif not os.path.isabs(raw_path_str):
                candidate_path = os.path.join(norm_root, raw_path_str)
                norm_target = os.path.realpath(os.path.normpath(candidate_path))
            else:
                norm_target = os.path.realpath(os.path.normpath(raw_path_str))

            common = os.path.commonpath([norm_target, norm_root])
            if os.path.normcase(common) != os.path.normcase(norm_root):
                return False, f"安全拒绝：访问路径 [{target_file_path}] 超出授权工作区边界 [{self.core.config.target_path}]。"

            if respect_blacklist and self.core.is_blacklisted(norm_target):
                return False, f"安全拒绝：目标路径 [{target_file_path}] 属于系统配置的受保护黑名单范围，禁止访问或操作。"

            return True, norm_target
        except Exception as e:
            return False, f"路径有效性校验失败: {str(e)}"

    def _get_token_warning_threshold(self) -> int:
        """读取扫描文件树的 Token 告警阈值。

        【P2-8 修复】兜底值必须与 server.py / config.json 的真实默认（10000）一致，
        否则配置缺失时不同模块会给出不同阈值。
        """
        try:
            if os.path.exists(self.core.config.config_file):
                with open(self.core.config.config_file, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    val = cfg.get("tool_token_warning_threshold")
                    if val is not None:
                        return int(val)
        except Exception:
            pass
        return 10000

    def _get_read_token_limit(self) -> int:
        """读取单个文件时的 Token 预算（默认 30000）。

        与 `tool_token_warning_threshold`（扫描文件树的告警阈值）解耦，避免语义混用（P2-7）。
        如需覆盖，可在 config.json 增加 `read_content_token_limit`。
        """
        try:
            if os.path.exists(self.core.config.config_file):
                with open(self.core.config.config_file, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    val = cfg.get("read_content_token_limit")
                    if val is not None:
                        return max(1000, int(val))
        except Exception:
            pass
        return 30000

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f}{unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f}TB"

    @staticmethod
    def _send_to_recycle_bin(file_path: str) -> Tuple[bool, str]:
        """将物理文件安全放入操作系统原生回收站"""
        try:
            import send2trash
            send2trash.send2trash(file_path)
            return True, "已移入系统回收站"
        except ImportError:
            pass
        except Exception as e:
            return False, f"send2trash 移入回收站失败: {str(e)}"

        sys_name = platform.system()
        try:
            if sys_name == "Windows":
                import ctypes
                from ctypes import wintypes

                class SHFILEOPSTRUCTW(ctypes.Structure):
                    _fields_ = [
                        ("hwnd", wintypes.HWND),
                        ("wFunc", wintypes.UINT),
                        ("pFrom", wintypes.LPCWSTR),
                        ("pTo", wintypes.LPCWSTR),
                        ("fFlags", wintypes.WORD),
                        ("fAnyOperationsAborted", wintypes.BOOL),
                        ("hNameMappings", wintypes.LPVOID),
                        ("lpszProgressTitle", wintypes.LPCWSTR)
                    ]

                FO_DELETE = 3
                FOF_ALLOWUNDO = 0x0040
                FOF_NOCONFIRMATION = 0x0010
                FOF_SILENT = 0x0004

                double_null_path = os.path.abspath(file_path) + "\0\0"
                fileop = SHFILEOPSTRUCTW()
                fileop.hwnd = 0
                fileop.wFunc = FO_DELETE
                fileop.pFrom = double_null_path
                fileop.pTo = None
                fileop.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT

                res = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(fileop))
                if res == 0 and not fileop.fAnyOperationsAborted:
                    return True, "已通过系统 API 移入回收站"
                else:
                    return False, f"Windows Shell 删除调用返回错误码: {res}"

            elif sys_name == "Darwin":
                esc_path = file_path.replace('"', '\\"')
                cmd = f'osascript -e \'tell application "Finder" to delete POSIX file "{esc_path}"\''
                subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True, "已移入访达废纸篓"

            else:
                subprocess.run(["gio", "trash", file_path], check=True, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
                return True, "已通过 gio 移入回收站"

        except Exception as fallback_e:
            return False, f"系统回收站通道调用失败: {str(fallback_e)}"

    def _collect_subtree_ids(self, path: str) -> List[int]:
        ids = []
        try:
            norm_p = os.path.normpath(path)
            with self.core.db.session() as conn:
                cursor = conn.cursor()
                # 【BUG-LIKE】前缀已转义，路径中的 % / _ 不再当通配符
                cursor.execute(
                    "SELECT id FROM files WHERE file_path = ? "
                    "OR file_path LIKE ? ESCAPE '!' "
                    "OR file_path LIKE ? ESCAPE '!'",
                    (norm_p, self._like_prefix(norm_p, "\\"), self._like_prefix(norm_p, "/"))
                )
                ids = [r[0] for r in cursor.fetchall()]
        except Exception as e:
            logger.error(f"收集子树 ID 失败: {e}")
        return list(set(ids))

    def _cleanup_db_records(self, ids: List[int], status: str = "deleted"):
        if not ids:
            return
        unique_ids = list(set(ids))
        try:
            self.core.vdb.delete_by_file_ids(unique_ids)
        except Exception as e:
            logger.error(f"删除向量索引失败: {e}")

        try:
            with self.core.db.session() as conn:
                with conn:
                    q = ','.join(['?'] * len(unique_ids))
                    conn.execute(
                        f"UPDATE files SET is_deleted = 1, status = ?, vector_indexed = 0, "
                        f"updated_at = CURRENT_TIMESTAMP WHERE id IN ({q})",
                        [status] + unique_ids
                    )
                    conn.execute(
                        f"DELETE FROM files_fts WHERE file_id IN ({q})",
                        [str(x) for x in unique_ids]
                    )
        except Exception as e:
            logger.error(f"清理数据库索引失败: {e}")

    BACKUP_DIR_NAME = ".local_agent_undo_backups"

    def _backup_dir(self) -> Optional[str]:
        """覆盖写入前物理暂存快照目录（覆盖备份统一落在此处，便于撤销时消费）。

        【SEC-03 修复】快照目录必须同时满足三个条件，否则返回 None 拒绝使用：
        1. **不得是符号链接**：旧实现只在 `target_path` 下按名字拼接，若该名字已被预先
           创建为指向工作区外的软链接，所有覆盖快照会被写到沙箱之外；
        2. **真实路径必须仍落在授权工作区内**：经 realpath 解析后重新做沙箱归属校验，
           阻断"父级软链接 + 子目录"之类的间接逃逸；
        3. **不得命中黑名单**：`IndexerCore.is_blacklisted` 必须能拦住它，否则
           `.local_agent_undo_backups` 会被 `sync()` 当作普通资产索引进库，
           导致被覆盖的 2/3 级机密内容以 1 级普通资产身份长期驻留且可免密读取。
        """
        candidate = os.path.join(self.core.config.target_path, self.BACKUP_DIR_NAME)

        # 1. 先做静态判定（此时可能尚不存在，realpath 会回退到父目录解析）
        if os.path.islink(candidate):
            logger.error("拒绝使用备份目录：%s 是符号链接，存在沙箱逃逸风险。", candidate)
            return None

        try:
            os.makedirs(candidate, exist_ok=True)
        except Exception as e:
            logger.error("创建备份目录失败: %s", e)
            return None

        # 2. 创建后再确认它不是软链接（防 TOCTOU：os.makedirs 可能被预先植入链接）
        if os.path.islink(candidate):
            logger.error("拒绝使用备份目录：%s 在创建后仍被判定为符号链接。", candidate)
            return None

        # 3. 走统一沙箱校验（含 realpath 归属校验；快照目录本身属于"内置保护目录"，
        #    必须跳过黑名单判定，否则会自己把自己拒绝掉）
        is_safe, verified = self._verify_sandbox_path(candidate, respect_blacklist=False)
        if not is_safe:
            logger.error("拒绝使用备份目录：%s", verified)
            return None

        return verified

    def _cleanup_undo_backups(self, keep: int = 200) -> int:
        """【SEC-03 配套】裁剪覆盖快照目录，避免被覆盖的机密内容无限期驻留。

        撤销链路依赖快照，因此不能直接清空；此处在"保留最近 keep 个快照"的前提下
        删除更早的文件，既保住近期可撤销性，又给敏感内容一个有限的留存窗口。
        """
        backup_dir = os.path.join(self.core.config.target_path, self.BACKUP_DIR_NAME)
        if not os.path.isdir(backup_dir) or os.path.islink(backup_dir):
            return 0

        try:
            entries = [
                os.path.join(backup_dir, n)
                for n in os.listdir(backup_dir)
                if os.path.isfile(os.path.join(backup_dir, n))
            ]
            if len(entries) <= keep:
                return 0
            entries.sort(key=lambda p: os.path.getmtime(p))
            removed = 0
            for old in entries[: len(entries) - keep]:
                try:
                    os.remove(old)
                    removed += 1
                except OSError:
                    continue
            if removed:
                logger.info("已裁剪 %d 个过期覆盖快照（保留最近 %d 个）。", removed, keep)
            return removed
        except Exception as e:
            logger.error("裁剪覆盖快照目录异常: %s", e)
            return 0

    @staticmethod
    def _norm_new_name(raw_name: Optional[str]) -> str:
        """把用户/AI 提供的『新名称』参数归一化为纯文件名（阻断 ../ 越界与路径穿越）"""
        if raw_name is None:
            return ""
        return os.path.basename(str(raw_name).strip().replace("\\", "/")).strip()

    def _sandbox_filtered_records(self, rows: Any) -> List[Tuple[int, str]]:
        """【SEC-01/SEC-02 修复】把"来自数据库"的候选记录逐条重新做沙箱归属校验。

        旧实现在多处直接 `return [(r[0], os.path.normpath(r[1])) for r in rows]`，
        等于把 `files.file_path` 当成可信权威。一旦索引中存在指向工作区外（或因历史
        bug 被写坏）的路径，该路径就会被当作"合法的沙箱内资产"继续流转到打包、重命名、
        设级、移动等后续环节，形成沙箱逃逸与内容外泄通道。

        此过滤器保证：**解析结果永远不会包含越出授权工作区或命中黑名单的路径**。
        """
        out: List[Tuple[int, str]] = []
        for r in rows:
            try:
                raw_p = r[1]
                if not raw_p:
                    continue
                is_safe, verified = self._verify_sandbox_path(str(raw_p))
                if not is_safe:
                    logger.warning("已丢弃越界/黑名单索引记录 id=%s path=%s（%s）", r[0], raw_p, verified)
                    continue
                out.append((r[0], os.path.normpath(verified)))
            except Exception as e:
                logger.error("索引记录沙箱校验异常，已丢弃: %s", e)
                continue
        return out

    @staticmethod
    def _like_escape(text: str) -> str:
        r"""转义 SQL LIKE 模式中的通配符，使传入的**字面量**按字面匹配。

        【BUG-LIKE 修复】SQLite 的 LIKE 中 `%` 匹配任意长度、`_` 匹配任意单字符。
        项目里大量"子树/前缀匹配"直接把**文件系统路径**拼进模式串：

            file_path LIKE ?   --  参数为  norm_p + "\\%"

        而路径是**完全可能包含 `_` 和 `%` 的**（`my_folder`、`100%_done`、
        `a_b/c`……）。此时 `_` 会被当作单字符通配，导致：

          * 误匹配到**无关记录**（`a_b` 同时匹配 `axb`、`a1b`……），
            这些记录会被当成"该目录的子项"参与路径级联改写 / 等级清理 / 注销，
            即**静默破坏索引**；
          * 前缀锚定失效，安全等级清理可能波及沙箱内其它资产。

        【为什么用 `!` 而不是反斜杠做转义符】
        本项目的路径是 Windows 风格，`\` 是路径分隔符、出现频率极高。
        SQLite 的 LIKE **默认没有转义符**（不同于某些方言默认 `\`），
        若选 `\` 作转义符，就必须把路径里的每个 `\` 都写成 `\\`；
        一旦漏转义或重复转义，整条前缀都会失配——这正是首版实现踩到的坑
        （实测 `with-escape -> []`，即所有子项都查不出来）。
        改用几乎不会出现在文件名中的 `!` 作转义符后，路径中的 `\` 保持原样，
        既不需要转义也不会被误解，鲁棒性最好。

        配套要求：SQL 中必须显式声明 `ESCAPE '!'`。
        """
        return (
            str(text)
            .replace("!", "!!")
            .replace("%", "!%")
            .replace("_", "!_")
        )

    @staticmethod
    def _like_prefix(path: str, sep: str) -> str:
        """构造"某目录下所有子项"的 LIKE 前缀模式（已转义）。

        等价于旧写法 `path + sep + "%"`，但路径中的 `%` / `_` 不再被当成通配符。
        """
        return FileManagerTool._like_escape(path) + sep + "%"

    def _resolve_file_records(self, file_identifier: Any) -> List[Tuple[int, str]]:
        """全能型资产标识反查：支持 ID、相对路径、绝对路径、纯文件名与模糊词干查询

        解析纪律（BUG-04/05 修复）：
        1. 显式物理路径优先 —— 只要入参在沙箱内能落到一个**真实存在**的物理对象上，就以它为准，
           绝不再退化成全局同名词干匹配（否则会把 `pick/m.txt` 解析成 `other/m.txt`）；
        2. 带路径分隔符但被沙箱拒绝的入参 —— 直接判定为不可解析（返回空），不参与模糊匹配；
        3. 只有"不带任何路径语义"的纯名称/词干才允许进入模糊匹配通道。

        【SEC-01/SEC-02 修复】所有来自数据库的结果一律经 `_sandbox_filtered_records`
        二次校验，绝不把数据库内容当作可信路径直接返回。
        """
        if file_identifier is None:
            return []

        try:
            fid = int(file_identifier)
            with self.core.db.session() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, file_path FROM files WHERE id = ? AND is_deleted = 0", (fid,))
                row = cursor.fetchone()
                if row:
                    return self._sandbox_filtered_records([row])
        except (ValueError, TypeError):
            pass

        raw_str = str(file_identifier).strip()
        if not raw_str:
            return []

        raw_nfc = unicodedata.normalize('NFC', raw_str)
        raw_nfd = unicodedata.normalize('NFD', raw_str)

        candidate_abs = None
        candidate_dir = None
        stem_candidate = ""

        has_sep = ('/' in raw_str) or ('\\' in raw_str)
        is_safe_path, verified_path = self._verify_sandbox_path(raw_str)
        if is_safe_path:
            if os.path.exists(verified_path):
                # 【第一优先级】显式物理路径存在即终局：就地取用，绝不跨目录替换
                return [(-1, os.path.normpath(verified_path))]
            if has_sep:
                candidate_abs = verified_path
                candidate_dir = os.path.dirname(verified_path)
                name_part = os.path.basename(verified_path)
                stem_candidate, _ = os.path.splitext(name_part)
        elif has_sep:
            # 带路径语义却越出沙箱：拒绝解析，交由上层给出明确的安全错误
            return []

        if not has_sep:
            stem_candidate, _ = os.path.splitext(raw_str)

        if candidate_abs:
            posix_p = candidate_abs.replace('\\', '/')
            win_p = candidate_abs.replace('/', '\\')
            with self.core.db.session() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, file_path FROM files WHERE (file_path = ? OR file_path = ? OR file_path = ? OR file_path = ?) AND is_deleted = 0",
                    (posix_p, win_p, unicodedata.normalize('NFD', posix_p), unicodedata.normalize('NFD', win_p))
                )
                rows = cursor.fetchall()
                if rows:
                    return self._sandbox_filtered_records(rows)

        with self.core.db.session() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, file_path FROM files WHERE (file_path = ? OR file_path = ?) AND is_deleted = 0",
                (raw_nfc, raw_nfd)
            )
            rows = cursor.fetchall()
            if rows:
                return self._sandbox_filtered_records(rows)

        name_candidate = os.path.basename(raw_str.replace('\\', '/').rstrip('/'))
        if name_candidate:
            name_nfc = unicodedata.normalize('NFC', name_candidate)
            name_nfd = unicodedata.normalize('NFD', name_candidate)
            with self.core.db.session() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, file_path FROM files WHERE (file_name = ? OR file_name = ?) AND is_deleted = 0 ORDER BY is_dir DESC",
                    (name_nfc, name_nfd)
                )
                rows = cursor.fetchall()
                if rows:
                    return self._sandbox_filtered_records(rows)

                cursor.execute(
                    "SELECT id, file_path FROM files WHERE file_name = ? COLLATE NOCASE AND is_deleted = 0 ORDER BY is_dir DESC",
                    (name_nfc,)
                )
                rows = cursor.fetchall()
                if rows:
                    return self._sandbox_filtered_records(rows)

        if stem_candidate:
            stem_nfc = unicodedata.normalize('NFC', stem_candidate)
            if candidate_dir:
                dir_posix = candidate_dir.replace('\\', '/')
                dir_win = candidate_dir.replace('/', '\\')
                with self.core.db.session() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT id, file_path FROM files WHERE "
                        "(file_path LIKE ? ESCAPE '!' OR file_path LIKE ? ESCAPE '!') "
                        "AND file_name LIKE ? ESCAPE '!' AND is_deleted = 0 ORDER BY is_dir DESC",
                        (self._like_prefix(dir_posix, "/"), self._like_prefix(dir_win, "\\"),
                         self._like_escape(stem_nfc) + ".%")
                    )
                    rows = cursor.fetchall()
                    if rows:
                        return self._sandbox_filtered_records(rows)

                if os.path.exists(candidate_dir):
                    try:
                        for entry in os.listdir(candidate_dir):
                            e_stem, _ = os.path.splitext(entry)
                            if unicodedata.normalize('NFC', e_stem) == stem_nfc:
                                full_entry = os.path.normpath(os.path.join(candidate_dir, entry))
                                if os.path.exists(full_entry):
                                    return [(-1, full_entry)]
                    except Exception:
                        pass

            if not has_sep:
                with self.core.db.session() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT id, file_path FROM files WHERE "
                        "file_name LIKE ? ESCAPE '!' AND is_deleted = 0 ORDER BY is_dir DESC",
                        (self._like_escape(stem_nfc) + ".%",)
                    )
                    rows = cursor.fetchall()
                    if rows:
                        return self._sandbox_filtered_records(rows)

        return []

    def _resolve_file_record(self, file_identifier: Any) -> Tuple[Optional[int], Optional[str]]:
        """单数版反查。返回的路径**必然**位于授权工作区内，否则返回 (None, None)。

        【SEC-02 修复】旧实现在全部解析失败时 `return None, path_str`，把调用方传入的
        原始字符串原样回吐。该字符串从未经过 `_verify_sandbox_path`，于是
        `E:/secret/x.txt` 之类的**越界路径会被下游当作"合法目标"**继续参与
        `os.path.dirname` / 安全等级判定 / 冲突预检 —— 解析失败反而被降级为信任。
        现改为：解析不到就返回空，让调用方走"资产不存在/不可定位"的正常错误分支。
        """
        if file_identifier is None:
            return None, None

        records = self._resolve_file_records(file_identifier)
        if len(records) == 1:
            fid, fpath = records[0]
            return (None if fid == -1 else fid), os.path.normpath(fpath)

        path_str = str(file_identifier).strip()
        if len(records) > 1:
            is_safe, verified = self._verify_sandbox_path(path_str)
            if is_safe and os.path.exists(verified):
                return None, os.path.normpath(verified)
            return None, None

        is_safe, verified = self._verify_sandbox_path(path_str)
        if is_safe and os.path.exists(verified):
            return None, os.path.normpath(verified)

        # 解析失败且沙箱校验未通过：绝不回吐未经校验的原始入参
        return None, None

    # ==================== 冲突与降级探测引擎 ====================

    def compute_transfer_facts(self, verified_src: str, target_dir: str,
                               effective_name: str) -> Dict[str, Any]:
        """计算**单个源项**在移动/复制时的安全事实。纯读、不改任何东西。

        【阶段 3 单一来源】这份判断过去被写了两遍（预检一处、执行准备循环一处），
        而且口径不一致 —— SEC-04 / D1 / D3 / ② 都出在这段。现在两处**都调用本函数**，
        避免"改一处漏一处"。

        说明：本函数只产出**事实**，不产出结论。
        「要不要报冲突」这一步由调用方决定，因为两处口径本就不同且都有理由：
          · 预检（网关消费）：首次下发时用户还没选，必须一律报冲突去问用户；
          · 执行层：`overwrite=True` 说明用户已授权覆盖，不能再报冲突。
        """
        norm_src = os.path.normpath(verified_src)
        dest_path = os.path.normpath(os.path.join(target_dir, effective_name))

        is_dest_inside, verified_dest = self._verify_sandbox_path(dest_path)
        dest_within_sandbox = bool(is_dest_inside) and \
            os.path.normcase(verified_dest) == os.path.normcase(dest_path)

        src_level = self.asset_sec_mgr.get_effective_level(norm_src, self.core.config.target_path)
        target_dir_level = self.asset_sec_mgr.get_effective_level(target_dir, self.core.config.target_path)
        is_same_place = (os.path.normcase(norm_src) == os.path.normcase(dest_path))
        dest_exists = os.path.lexists(dest_path)
        is_downgrade = src_level > target_dir_level

        # 降级告警文案随事实一起产出，避免调用方再算一遍
        downgrade_message = ""
        if is_downgrade:
            downgrade_message = (
                f"⚠️ 安全降级风险告警：当前资产生效等级为【{src_level}级】，"
                f"目标目录仅受【{target_dir_level}级】保护。"
                f"移出后该资产及内部所有文件都会降级为【{target_dir_level}级】！"
            )

        return {
            "src_path": norm_src,
            "dest_path": dest_path,
            "is_dir": os.path.isdir(norm_src),
            "dest_within_sandbox": dest_within_sandbox,
            "is_same_place": is_same_place,
            "dest_exists": dest_exists,
            # 仅当目标确实存在、且不是原地时才算"会覆盖"
            "would_overwrite": bool(dest_exists and not is_same_place),
            "src_level": src_level,
            "target_dir_level": target_dir_level,
            "is_downgrade": is_downgrade,
            "downgrade_message": downgrade_message,
        }

    def _resolve_rename_target(self, file_path: Any, file_id: Any) -> Optional[str]:
        """重命名用的**只读**目标解析：尽力而为，不触发索引写入（预检阶段无副作用）。"""
        target = file_id if file_id is not None else file_path
        if target is None or str(target).strip() == "":
            return None
        records = self._resolve_file_records(target)
        if records and records[0][1]:
            return os.path.normpath(records[0][1])
        is_safe, verified = self._verify_sandbox_path(str(target))
        if is_safe:
            return os.path.normpath(verified)
        return None

    def describe_action(self, action_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """产出**动作级安全事实**：这次操作到底是"新建"还是"覆盖/销毁"。

        这是移动/复制之外各动作的统一事实来源，供网关计算风险等级。
        【阶段 3 单一来源】网关不再自己探磁盘、自己解读等级，一律消费本函数。

        设计口径（对应用户原则：按"会造成什么"而非"是哪个工具"分档）：
          · creates_new=True  → 什么都没被破坏 → 基础风险 SAFE（免打扰）
          · would_overwrite=True → 既有内容将被替换 → 基础风险 SENSITIVE（需确认）
          · 涉及 2/3 级资产或造成降级 → 由调用方(网关)按资产等级强制升级
        """
        base = {
            "action": action_name,
            "resolved": True,
            "creates_new": False,
            "would_overwrite": False,
            "is_downgrade": False,
            "src_level": 1,
            "target_dir_level": 1,
            "detail": {},
        }

        if action_name in ("move_file", "copy_file"):
            files = params.get("files", [])
            target_dir = params.get("target_dir", "")
            rename_to = params.get("rename_to") or None
            items = self.describe_transfer_sources(files, target_dir, rename_to)
            blocking = [i for i in items if i.get("type") != "ok"]
            ok_items = [i for i in items if i.get("type") == "ok"]
            downs = [i for i in ok_items if i.get("is_downgrade")]
            overs = [i for i in ok_items if i.get("would_overwrite")]
            base.update({
                "resolved": not blocking,
                "creates_new": not overs and not downs,
                "would_overwrite": bool(overs),
                "is_downgrade": bool(downs),
                "src_level": downs[0]["src_level"] if downs else 1,
                "target_dir_level": downs[0]["target_dir_level"] if downs else 1,
                "detail": {
                    "items": items,
                    "blocking": blocking,
                    "name": overs[0]["name"] if overs else (downs[0]["name"] if downs else ""),
                },
            })
            return base

        if action_name == "rename_file":
            new_name = os.path.basename(str(params.get("new_name", "")).strip())
            src = self._resolve_rename_target(params.get("file_path"), params.get("file_id"))
            if not src or not new_name:
                base["resolved"] = False
                return base
            target_new = os.path.normpath(os.path.join(os.path.dirname(src), new_name))
            # 仅大小写变化不算"覆盖"：磁盘上还是同一个对象
            is_case_only = os.path.normcase(src) == os.path.normcase(target_new)
            overwrite = (not is_case_only) and os.path.lexists(target_new)
            base.update({
                "creates_new": not overwrite,
                "would_overwrite": overwrite,
                "detail": {"src": src, "target": target_new, "name": new_name,
                           "is_case_only": is_case_only},
            })
            return base

        if action_name == "write_file":
            fp = params.get("file_path", "")
            ow_name = self._norm_new_name(params.get("overwrite_name")) or ""
            if not fp:
                base["resolved"] = False
                return base
            final = os.path.join(os.path.dirname(str(fp)), ow_name) if ow_name else str(fp)
            is_safe, verified = self._verify_sandbox_path(final)
            if not is_safe:
                base["resolved"] = False
                return base
            verified = os.path.normpath(verified)
            # 用户已换名 ⇒ 落点是个新名字，不构成覆盖
            overwrite = os.path.lexists(verified) and not ow_name
            base.update({
                "creates_new": not overwrite,
                "would_overwrite": overwrite,
                "detail": {"target": verified, "name": os.path.basename(verified)},
            })
            return base

        if action_name == "extract_archive":
            zip_path = params.get("zip_path", "")
            target_dir = params.get("target_dir", "") or ""
            if not zip_path:
                base["resolved"] = False
                return base
            _, resolved_zip = self._resolve_file_record(zip_path)
            if not resolved_zip:
                base["resolved"] = False
                return base
            if not target_dir:
                target_dir = os.path.join(os.path.dirname(resolved_zip),
                                          os.path.splitext(os.path.basename(resolved_zip))[0])
            is_safe, verified_dir = self._verify_sandbox_path(target_dir)
            if not is_safe:
                base["resolved"] = False
                return base
            verified_dir = os.path.normpath(verified_dir)
            # 精确判据：只在**真的存在同名文件**时才算覆盖（"目录非空"是过近似）
            collisions = []
            try:
                with zipfile.ZipFile(resolved_zip, "r") as zf:
                    for member in zf.infolist():
                        if member.is_dir():
                            continue
                        rel = member.filename.replace("\\", "/")
                        dest = os.path.normpath(os.path.join(verified_dir, rel))
                        if os.path.isfile(dest):
                            collisions.append(dest)
            except Exception:
                # 压缩包不可读等情况交给执行层报错，这里不伪装成"无冲突"
                base["resolved"] = False
                return base
            base.update({
                "creates_new": not collisions,
                "would_overwrite": bool(collisions),
                "detail": {"target_dir": verified_dir, "collisions": collisions[:10]},
            })
            return base

        # 其他动作（delete / create_directory / compress / set_security_level 等）
        # 沿用策略表的基础定级，不受本函数影响。
        return {"action": action_name, "handled": False}

    def describe_transfer_sources(self, files: Any, target_dir: str,
                                  rename_to: Optional[str] = None) -> List[Dict[str, Any]]:
        """解析源项并产出**逐项安全事实**，供网关决策使用。纯读、不改任何东西。

        【阶段 3 单一来源】网关此前自己判"目标是否存在"、自己读等级、自己拼文案，
        与工具层口径不一致（② 就出在这里）。现在网关**只消费**本函数的产出，
        不再自行重算。

        这是移动/复制安全事实的**唯一来源**。原先另有一个 `detect_transfer_conflicts`
        预检做同样的事，与执行准备循环口径不一致（SEC-04 / D1 / D3 / ② 的共同病根），
        已删除；其"首次下发一律报冲突"的语义由网关按 `rename_to` 是否为空自行决定 ——
        事实层只如实描述磁盘状态，不做拦截决策。

        每项事实字段：
          type             : ok | source_ambiguous | source_unresolved | target_invalid
          src/name         : 源路径与文件名
          dest             : 真正会落到的目标路径
          dest_exists      : 目标是否已存在（非原地）
          is_same_place    : 源与目标是否同一路径（原地操作）
          is_downgrade     : 是否发生安全降级
          src_level        : 源生效等级
          target_dir_level : 目标目录生效等级
          would_overwrite  : 是否真的会覆盖既有文件
        """
        items: List[Dict[str, Any]] = []
        if not files or not target_dir:
            return items

        file_list = files if isinstance(files, list) else [files]

        is_safe_target, verified_target_dir = self._verify_sandbox_path(target_dir)
        if not is_safe_target or not os.path.exists(verified_target_dir):
            for item in file_list:
                items.append({
                    "type": "target_invalid",
                    "src": str(item),
                    "name": os.path.basename(str(item).replace("\\", "/").rstrip("/")),
                    "dest": "",
                    "dest_exists": False,
                    "is_downgrade": False,
                    "src_level": 1,
                    "target_dir_level": 1,
                    "would_overwrite": False,
                })
            return items

        verified_target_dir = os.path.normpath(verified_target_dir)

        # 换名只在"单目标"时有效，与 `_execute_transfer` 的口径保持一致
        file_list = file_list if isinstance(file_list, list) else [file_list]
        rename_single = self._norm_new_name(rename_to) if (rename_to and len(file_list) == 1) else ""

        for item in file_list:
            resolved = self._resolve_transfer_source(item)
            if resolved["error"] is not None:
                items.append({
                    "type": resolved["error"],
                    "src": str(item),
                    "name": resolved["name"],
                    "dest": "",
                    "dest_exists": False,
                    "is_downgrade": False,
                    "src_level": 1,
                    "target_dir_level": 1,
                    "would_overwrite": False,
                })
                continue

            src_path = resolved["src_path"]
            effective_name = rename_single or resolved["name"]
            facts = self.compute_transfer_facts(src_path, verified_target_dir, effective_name)
            items.append({
                "type": "ok",
                "src": src_path,
                "name": effective_name,
                "dest": facts["dest_path"],
                "dest_exists": bool(facts["dest_exists"] and not facts["is_same_place"]),
                "is_same_place": facts["is_same_place"],
                "is_downgrade": facts["is_downgrade"],
                "src_level": facts["src_level"],
                "target_dir_level": facts["target_dir_level"],
                "would_overwrite": facts["would_overwrite"],
            })

        return items

    def _resolve_transfer_source(self, item: Any) -> Dict[str, Any]:
        """把单个源入参解析成可用的工作区内绝对路径。已沙箱校验。

        :return {"src_path": str|None, "name": str, "error": str|None}
        """
        records = self._resolve_file_records(item)

        if len(records) > 1:
            path_str = str(item).strip()
            is_safe_src, verified_src = self._verify_sandbox_path(path_str)
            if is_safe_src and os.path.exists(verified_src):
                src_path = os.path.normpath(verified_src)
            else:
                return {
                    "src_path": None,
                    "name": os.path.basename(path_str.replace('\\', '/').rstrip('/')),
                    "error": "source_ambiguous",
                    "matches": [{"id": r[0], "path": r[1]} for r in records],
                }
        elif len(records) == 0:
            is_safe_src, verified_src = self._verify_sandbox_path(str(item))
            if not is_safe_src or not os.path.exists(verified_src):
                return {
                    "src_path": None,
                    "name": os.path.basename(str(item).replace("\\", "/").rstrip("/")),
                    "error": "source_unresolved",
                    "matches": [],
                }
            src_path = os.path.normpath(verified_src)
        else:
            src_path = os.path.normpath(records[0][1])

        return {"src_path": src_path, "name": os.path.basename(src_path),
                "error": None, "matches": []}

    # ==================== 1. 新建目录 (mkdir) ====================

    def create_directory(self, dir_path: str) -> Dict[str, Any]:
        """在沙箱内新建目录文件夹。遇同名存在则直接拦截报错，记录可撤销流水。"""
        if not dir_path or not str(dir_path).strip():
            return {"success": False, "message": "必须提供有效的目标文件夹路径。"}

        is_safe, verified_path = self._verify_sandbox_path(dir_path)
        if not is_safe:
            return {"success": False, "message": verified_path}

        verified_path = os.path.normpath(verified_path)
        if os.path.lexists(verified_path):
            return {
                "success": False,
                "is_conflict": True,
                "conflict_path": verified_path,
                "message": f"命名冲突拦截：目标目录或文件已存在: `{verified_path}`。请更换名称重试或取消操作。"
            }

        ok_space, space_err = SecurityManager.precheck_disk_space(os.path.dirname(verified_path), 1024 * 1024)
        if not ok_space:
            return {"success": False, "message": space_err}

        try:
            os.makedirs(verified_path, exist_ok=False)
            self.core.index_single_asset_or_tree(verified_path)

            op_id = str(uuid.uuid4())[:8]
            self.core.record_operation_journal(
                operation_id=op_id,
                action_type="create_dir",
                operator="agent",
                src_path="",
                dest_path=verified_path,
                extra_meta={"dir_path": verified_path},
                can_undo=True
            )
            self.core.log_audit_event("create_directory", operator="agent", level="SAFE",
                                      target_paths=[verified_path], status="SUCCESS", details="成功新建文件夹目录")

            return {
                "success": True,
                "operation_id": op_id,
                "dir_path": verified_path,
                "message": f"✅ 成功新建目录文件夹: `{verified_path}`"
            }
        except Exception as e:
            self.core.log_audit_event("create_directory", operator="agent", level="SAFE",
                                      target_paths=[verified_path], status="FAILED", details=str(e))
            return {"success": False, "message": f"创建目录失败: {str(e)}"}

    # ==================== 2. 新建空文件 / 写入文本文件 (write_file) ====================

    def write_file(self, file_path: str, content: str = "", overwrite_name: Optional[str] = None,
                   overwrite: bool = False) -> Dict[str, Any]:
        """
        新建空文件/文本文件并写入正文。
        - 若目标同名存在且未提供 overwrite_name / overwrite，严格提示冲突并弹窗要求换名或确认；
        - 支持传入 overwrite_name 规避冲突；
        - 支持 overwrite=True 覆盖替换（HITL 授权通道），覆盖前生成可撤销快照；
        - 文本单次限额 5MB，预检磁盘容量；
        - 支持本地原子撤销（删除新建文件并清理索引；覆盖写入则还原被覆盖内容）。
        """
        if not file_path or not str(file_path).strip():
            return {"success": False, "message": "必须提供目标文件路径。"}

        target_input = file_path
        clean_overwrite_name = self._norm_new_name(overwrite_name)
        if clean_overwrite_name:
            parent = os.path.dirname(file_path)
            target_input = os.path.join(parent, clean_overwrite_name)

        is_safe, verified_path = self._verify_sandbox_path(target_input)
        if not is_safe:
            return {"success": False, "message": verified_path}

        verified_path = os.path.normpath(verified_path)
        ok_sym, sym_err = SecurityManager.check_symlink_safety(verified_path)
        if not ok_sym:
            return {"success": False, "message": sym_err}

        already_exists = os.path.lexists(verified_path)
        if already_exists and not clean_overwrite_name and not overwrite:
            return {
                "success": False,
                "is_conflict": True,
                "conflict_path": verified_path,
                "file_name": os.path.basename(verified_path),
                "message": f"⚠️ 命名冲突拦截：目标文件 `{verified_path}` 已存在！请在弹窗中选择确认或更换新文件名。"
            }

        if already_exists and os.path.isdir(verified_path):
            return {"success": False, "message": f"目标路径 `{verified_path}` 是目录，无法作为文本文件写入。"}

        encoded_bytes = content.encode("utf-8", errors="replace") if content else b""
        if len(encoded_bytes) > 5 * 1024 * 1024:
            return {"success": False, "message": "安全拦截：单次文本写入体积超出 5MB 硬上限保护。"}

        ok_space, space_err = SecurityManager.precheck_disk_space(os.path.dirname(verified_path), len(encoded_bytes) + 1024 * 1024)
        if not ok_space:
            return {"success": False, "message": space_err}

        is_new_file = not already_exists
        is_overwriting = bool(already_exists)
        overwritten_backups: Dict[str, str] = {}

        try:
            os.makedirs(os.path.dirname(verified_path), exist_ok=True)

            if is_overwriting:
                # 覆盖写入前必须生成可还原快照，失败则中止写入，绝不造成不可逆内容丢失
                backup_dir = self._backup_dir()
                if not backup_dir:
                    return {"success": False, "message": "安全拦截：覆盖备份目录不可用（未通过沙箱校验或命中黑名单），为避免不可逆覆盖已中止写入。"}
                bak_path = os.path.join(backup_dir, f"bak_write_{uuid.uuid4().hex}_{os.path.basename(verified_path)}")
                shutil.copy2(verified_path, bak_path)
                overwritten_backups[verified_path] = bak_path

            with open(verified_path, "wb") as f:
                f.write(encoded_bytes)

            self.core.index_single_asset_or_tree(verified_path)

            op_id = str(uuid.uuid4())[:8]
            self.core.record_operation_journal(
                operation_id=op_id,
                action_type="write_create" if is_new_file else "write_modify",
                operator="agent",
                src_path="",
                dest_path=verified_path,
                extra_meta={
                    "file_path": verified_path,
                    "size": len(encoded_bytes),
                    "is_new": is_new_file,
                    "overwritten_backups": overwritten_backups
                },
                can_undo=True
            )

            self.core.log_audit_event("write_file", operator="agent", level="SENSITIVE",
                                      target_paths=[verified_path], status="SUCCESS",
                                      details=f"写入文件 ({self._format_size(len(encoded_bytes))})")

            return {
                "success": True,
                "operation_id": op_id,
                "file_path": verified_path,
                "file_size": len(encoded_bytes),
                "message": f"✅ 文件写入成功: `{verified_path}` ({self._format_size(len(encoded_bytes))})"
            }
        except Exception as e:
            self.core.log_audit_event("write_file", operator="agent", level="SENSITIVE",
                                      target_paths=[verified_path], status="FAILED", details=str(e))
            return {"success": False, "message": f"物理写入文件失败: {str(e)}"}

    # ==================== 3. 制作压缩包 (compress_files) ====================

    def compress_files(self, files: Any, output_zip: str, rename_to: Optional[str] = None,
                       overwrite: bool = False) -> Dict[str, Any]:
        """制作 ZIP 压缩包，防覆盖冲突，支持 overwrite 覆盖替换（含可撤销快照）与本地原子撤销。"""
        if not files or not output_zip:
            return {"success": False, "message": "必须提供待打包的文件名单 (files) 与输出压缩包路径 (output_zip)。"}

        clean_rename = self._norm_new_name(rename_to)
        target_zip_name = output_zip
        if clean_rename:
            parent = os.path.dirname(output_zip)
            target_zip_name = os.path.join(parent, clean_rename)

        if not target_zip_name.lower().endswith(".zip"):
            target_zip_name += ".zip"

        is_safe_out, verified_out = self._verify_sandbox_path(target_zip_name)
        if not is_safe_out:
            return {"success": False, "message": verified_out}

        verified_out = os.path.normpath(verified_out)
        if os.path.isdir(verified_out):
            return {"success": False, "message": f"输出路径 `{verified_out}` 已存在且是目录，无法作为压缩包写入。"}
        if os.path.lexists(verified_out) and not clean_rename and not overwrite:
            return {
                "success": False,
                "is_conflict": True,
                "conflict_path": verified_out,
                "file_name": os.path.basename(verified_out),
                "message": f"⚠️ 命名冲突拦截：目标压缩包 `{verified_out}` 已存在！请更换名称或取消操作。"
            }

        file_list = files if isinstance(files, list) else [files]
        verified_sources: List[Tuple[str, str]] = []
        estimated_source_bytes = 0

        for item in file_list:
            records = self._resolve_file_records(item)
            src_p = None
            if len(records) >= 1:
                src_p = records[0][1]
            else:
                is_s, ver_s = self._verify_sandbox_path(str(item))
                if is_s and os.path.exists(ver_s):
                    src_p = ver_s

            if not src_p or not os.path.exists(src_p):
                return {"success": False, "message": f"待压缩的源资产不存在或无法定位: `{item}`"}

            src_p = os.path.normpath(src_p)

            # 【SEC-01 修复】无论源路径来自"调用方入参"还是"数据库反查结果"，
            # 在触碰磁盘之前都必须重新做一次沙箱归属校验。
            # 旧实现在 records 命中时直接采信 `files.file_path`，把数据库当成可信权威：
            # 只要索引中残留一行指向工作区外的陈旧/被污染记录，就能把工作区外的文件
            # 打包进 ZIP（构成内容外泄通道），且全程照常通过安全网关。
            is_safe_src, verified_src = self._verify_sandbox_path(src_p)
            if not is_safe_src:
                return {
                    "success": False,
                    "message": f"安全拒绝：待压缩源资产 `{item}` 未通过沙箱归属校验（{verified_src}），已终止打包。"
                }
            if self.core.is_blacklisted(verified_src):
                return {
                    "success": False,
                    "message": f"安全拒绝：待压缩源资产 `{item}` 命中受保护黑名单范围，已终止打包。"
                }
            src_p = verified_src

            ok_sym, sym_err = SecurityManager.check_symlink_safety(src_p)
            if not ok_sym:
                return {"success": False, "message": sym_err}

            base_name = os.path.basename(src_p)
            if os.path.isdir(src_p):
                for r, _, f_names in os.walk(src_p):
                    for fn in f_names:
                        fp = os.path.join(r, fn)
                        if not os.path.islink(fp) and os.path.exists(fp):
                            estimated_source_bytes += os.path.getsize(fp)
            else:
                estimated_source_bytes += os.path.getsize(src_p)

            verified_sources.append((src_p, base_name))

        ok_space, space_err = SecurityManager.precheck_disk_space(os.path.dirname(verified_out), estimated_source_bytes // 2 + 1024 * 1024)
        if not ok_space:
            return {"success": False, "message": space_err}

        out_key = os.path.normcase(os.path.abspath(verified_out))
        overwritten_backups: Dict[str, str] = {}

        try:
            os.makedirs(os.path.dirname(verified_out), exist_ok=True)

            if os.path.lexists(verified_out):
                # 覆盖既有压缩包前先留快照，保证撤销可还原
                backup_dir = self._backup_dir()
                if not backup_dir:
                    return {"success": False, "message": "安全拦截：覆盖备份目录不可用（未通过沙箱校验或命中黑名单），为避免不可逆覆盖已中止打包。"}
                bak_path = os.path.join(backup_dir, f"bak_compress_{uuid.uuid4().hex}_{os.path.basename(verified_out)}")
                shutil.copy2(verified_out, bak_path)
                overwritten_backups[verified_out] = bak_path

            packed_count = 0
            with zipfile.ZipFile(verified_out, 'w', compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
                for src_path, arc_root_name in verified_sources:
                    if os.path.isdir(src_path):
                        for root, _, filenames in os.walk(src_path):
                            for fn in filenames:
                                full_f = os.path.join(root, fn)
                                if os.path.islink(full_f):
                                    continue
                                # 【BUG-10 修复】绝不把正在生成的输出压缩包自身打进包里
                                if os.path.normcase(os.path.abspath(full_f)) == out_key:
                                    continue
                                rel_in_dir = os.path.relpath(full_f, src_path)
                                arcname = os.path.join(arc_root_name, rel_in_dir)
                                zf.write(full_f, arcname=arcname)
                                packed_count += 1
                    else:
                        if os.path.normcase(os.path.abspath(src_path)) == out_key:
                            continue
                        zf.write(src_path, arcname=arc_root_name)
                        packed_count += 1

            if packed_count == 0:
                try:
                    os.remove(verified_out)
                except Exception:
                    pass
                return {"success": False,
                        "message": "打包终止：有效待打包条目为 0（输出压缩包自身已被自动排除，请提供其它源资产）。"}

            final_zip_size = os.path.getsize(verified_out)
            self.core.index_single_asset_or_tree(verified_out)

            op_id = str(uuid.uuid4())[:8]
            self.core.record_operation_journal(
                operation_id=op_id,
                action_type="compress",
                operator="agent",
                src_path=json.dumps([s[0] for s in verified_sources], ensure_ascii=False),
                dest_path=verified_out,
                extra_meta={
                    "output_zip": verified_out,
                    "size": final_zip_size,
                    "packed_count": packed_count,
                    "overwritten_backups": overwritten_backups
                },
                can_undo=True
            )
            self.core.log_audit_event("compress_files", operator="agent", level="SAFE",
                                      target_paths=[verified_out], status="SUCCESS",
                                      details=f"制作压缩包成功 (体积: {self._format_size(final_zip_size)})")

            return {
                "success": True,
                "operation_id": op_id,
                "output_zip": verified_out,
                "file_size": final_zip_size,
                "message": f"✅ 压缩包制作完成: `{verified_out}` (体积: {self._format_size(final_zip_size)})"
            }
        except Exception as e:
            self.core.log_audit_event("compress_files", operator="agent", level="SAFE",
                                      target_paths=[verified_out], status="FAILED", details=str(e))
            return {"success": False, "message": f"制作压缩包失败: {str(e)}"}

    # ==================== 4. 解压压缩包 (extract_archive) ====================

    def extract_archive(self, zip_path: str, target_dir: Optional[str] = None, overwrite: bool = False) -> Dict[str, Any]:
        """
        解压 ZIP 压缩包（强制 Zip Slip 防御、压缩炸弹预检与同名冲突阻断，支持 overwrite 覆盖替换与批量原子撤回）。
        """
        if not zip_path:
            return {"success": False, "message": "必须提供待解压的 ZIP 文件路径。"}

        resolved_id, resolved_zip = self._resolve_file_record(zip_path)
        if not resolved_zip:
            return {"success": False, "message": f"未找到待解压的压缩包资产: `{zip_path}`"}

        is_safe_zip, verified_zip = self._verify_sandbox_path(resolved_zip)
        if not is_safe_zip:
            return {"success": False, "message": verified_zip}

        verified_zip = os.path.normpath(verified_zip)
        if not os.path.exists(verified_zip) or os.path.isdir(verified_zip):
            return {"success": False, "message": f"目标不是有效的物理 ZIP 文件: `{verified_zip}`"}

        ok_bomb, bomb_err, uncompressed_size, entry_cnt = SecurityManager.precheck_zip_bomb(verified_zip)
        if not ok_bomb:
            return {"success": False, "message": f"🛑 安全预检熔断: {bomb_err}"}

        if not target_dir:
            base_stem = os.path.splitext(os.path.basename(verified_zip))[0]
            target_dir = os.path.join(os.path.dirname(verified_zip), base_stem)

        is_safe_dest, verified_dest_dir = self._verify_sandbox_path(target_dir)
        if not is_safe_dest:
            return {"success": False, "message": verified_dest_dir}

        verified_dest_dir = os.path.normpath(verified_dest_dir)
        ok_space, space_err = SecurityManager.precheck_disk_space(verified_dest_dir, uncompressed_size)
        if not ok_space:
            return {"success": False, "message": space_err}

        extracted_file_paths: List[str] = []
        conflicts = []
        backup_dir = self._backup_dir()
        overwritten_backups: Dict[str, str] = {}
        # 记录解压前该目录下既有的已入库资产，撤销时只注销本次新产生的记录，绝不波及无关既有文件
        pre_existing_ids = set(self._collect_subtree_ids(verified_dest_dir)) if os.path.exists(verified_dest_dir) else set()

        try:
            with zipfile.ZipFile(verified_zip, 'r') as zf:
                for member in zf.infolist():
                    filename = member.filename.replace('\\', '/')
                    dest_file_path = os.path.realpath(os.path.normpath(os.path.join(verified_dest_dir, filename)))
                    # 【Zip Slip 纵深防御修复】前缀比较必须带上路径分隔符，避免 "<目标目录名>_evil" 类同前缀绕过
                    norm_dest_root = os.path.realpath(verified_dest_dir)
                    if dest_file_path != norm_dest_root and not dest_file_path.startswith(norm_dest_root + os.sep):
                        return {
                            "success": False,
                            "message": f"🛑 Zip Slip 路径穿越致命攻击拦截：检测到非法条目 `{member.filename}`，已中止解压！"
                        }

                    if (member.external_attr >> 16) & 0o170000 == 0o120000:
                        return {
                            "success": False,
                            "message": f"🛑 软链接安全拦截：条目 `{member.filename}` 属于符号链接，拒绝解压！"
                        }

                    if os.path.exists(dest_file_path) and not member.is_dir():
                        conflicts.append(dest_file_path)

            if conflicts and not overwrite:
                return {
                    "success": False,
                    "is_conflict": True,
                    "conflicts": conflicts[:10],
                    "message": f"⚠️ 解压命名冲突：解压目标目录下已存在 {len(conflicts)} 项同名资产！请指定新目录、选择【覆盖替换原有文件】或取消操作。"
                }

            if conflicts and overwrite:
                # 【SEC-03 修复】备份目录不可用时，必须先判定是否真的需要写快照：
                # 若冲突项全为目录（不会被文件写入覆盖），则无需快照、放行；
                # 否则一律中止，绝不做"无法撤销的覆盖"。
                needs_snapshot = any(os.path.isfile(c) for c in conflicts)
                if needs_snapshot and not backup_dir:
                    return {"success": False, "message": "安全拦截：覆盖备份目录不可用（未通过沙箱校验或命中黑名单），为避免不可逆覆盖已中止解压。"}
                if backup_dir:
                    os.makedirs(backup_dir, exist_ok=True)
                for cf in conflicts:
                    # 目录冲突不会被文件写入覆盖，且 shutil.copy2 无法复制目录，故跳过快照
                    if not os.path.isfile(cf):
                        continue
                    bak_name = f"bak_extract_{uuid.uuid4().hex}_{os.path.basename(cf)}"
                    bak_path = os.path.join(backup_dir, bak_name)
                    # 覆盖前快照失败则整体中止，绝不留下"被覆盖却无备份"的不可逆状态
                    shutil.copy2(cf, bak_path)
                    overwritten_backups[cf] = bak_path

            os.makedirs(verified_dest_dir, exist_ok=True)
            with zipfile.ZipFile(verified_zip, 'r') as zf:
                for member in zf.infolist():
                    filename = member.filename.replace('\\', '/')
                    dest_file = os.path.normpath(os.path.join(verified_dest_dir, filename))

                    if member.is_dir():
                        os.makedirs(dest_file, exist_ok=True)
                    else:
                        os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                        with zf.open(member) as src, open(dest_file, 'wb') as dst:
                            shutil.copyfileobj(src, dst)
                        extracted_file_paths.append(dest_file)

            self.core.index_single_asset_or_tree(verified_dest_dir)

            op_id = str(uuid.uuid4())[:8]
            self.core.record_operation_journal(
                operation_id=op_id,
                action_type="extract",
                operator="agent",
                src_path=verified_zip,
                dest_path=verified_dest_dir,
                extra_meta={
                    "extracted_files": extracted_file_paths,
                    "target_dir": verified_dest_dir,
                    "overwritten_backups": overwritten_backups,
                    "pre_existing_ids": sorted(pre_existing_ids)
                },
                can_undo=True
            )
            self.core.log_audit_event("extract_archive", operator="agent", level="SENSITIVE",
                                      target_paths=[verified_zip, verified_dest_dir], status="SUCCESS",
                                      details=f"解压完成，释放 {len(extracted_file_paths)} 个文件 ({self._format_size(uncompressed_size)})" + (f"，覆盖替换了 {len(conflicts)} 个同名文件" if conflicts and overwrite else ""))

            coverage_hint = f"\n- **覆盖说明**: 已强制覆盖替换原有 {len(conflicts)} 项同名文件（已生成安全回退快照）。" if (conflicts and overwrite) else ""
            return {
                "success": True,
                "operation_id": op_id,
                "target_dir": verified_dest_dir,
                "extracted_count": len(extracted_file_paths),
                "uncompressed_size": uncompressed_size,
                "message": (
                    f"✅ 压缩包安全解压完成！\n"
                    f"- **解压目录**: `{verified_dest_dir}`\n"
                    f"- **释放文件总数**: {len(extracted_file_paths)} 个 (总计: {self._format_size(uncompressed_size)}){coverage_hint}\n"
                    f"- 所有新解压资产已即时登记入库并建立检索索引。"
                )
            }
        except Exception as e:
            self.core.log_audit_event("extract_archive", operator="agent", level="SENSITIVE",
                                      target_paths=[verified_zip], status="FAILED", details=str(e))
            return {"success": False, "message": f"解压执行失败: {str(e)}"}

    # ==================== 5. 删除文件（破坏性操作：不可撤销，去回收站拾回） ====================

    def delete_file(self, files: Any) -> Dict[str, Any]:
        """将资产移入系统回收站。破坏性高危动作：明确提示无法自动撤回，需在系统回收站中手动拾回。"""
        if not files:
            return {"success": False, "message": "未提供待删除的资产名单。"}

        file_list = files if isinstance(files, list) else [files]
        execution_results = []
        synced_db_ids = []
        deleted_paths = []

        for item in file_list:
            resolved_id, resolved_path = self._resolve_file_record(item)
            if not resolved_path:
                execution_results.append({"item": item, "success": False, "message": "无法解析有效路径或 ID。"})
                continue

            is_safe, verified_path = self._verify_sandbox_path(resolved_path)
            if not is_safe:
                execution_results.append({"item": item, "success": False, "message": verified_path})
                continue

            verified_path = os.path.normpath(verified_path)
            if not os.path.exists(verified_path):
                execution_results.append({"item": item, "success": False, "message": "物理对象在磁盘上已不存在。"})
                continue

            is_target_dir = os.path.isdir(verified_path)
            success_trash, trash_msg = self._send_to_recycle_bin(verified_path)
            if not success_trash:
                execution_results.append({"item": item, "success": False, "message": f"移入回收站失败: {trash_msg}"})
                continue

            deleted_paths.append(verified_path)
            if resolved_id is not None:
                synced_db_ids.append(resolved_id)

            if is_target_dir:
                synced_db_ids.extend(self._collect_subtree_ids(verified_path))
            else:
                try:
                    with self.core.db.session() as conn:
                        cursor = conn.cursor()
                        cursor.execute("SELECT id FROM files WHERE file_path = ?", (verified_path,))
                        for r in cursor.fetchall():
                            synced_db_ids.append(r[0])
                except Exception:
                    pass

            execution_results.append({
                "item": item,
                "success": True,
                "message": f"{trash_msg} -> {verified_path} (提示：若需恢复请在操作系统回收站中手动拾回)"
            })

        if synced_db_ids:
            self._cleanup_db_records(synced_db_ids, status="deleted")

        # 【P2-12】一个文件都没真正删除时不留流水记录，避免污染审计与撤销栈语义
        if deleted_paths:
            op_id = str(uuid.uuid4())[:8]
            self.core.record_operation_journal(
                operation_id=op_id,
                action_type="delete",
                operator="agent",
                src_path=json.dumps(deleted_paths, ensure_ascii=False),
                dest_path="",
                extra_meta={"paths": deleted_paths},
                can_undo=False
            )

        self.core.log_audit_event("delete_file", operator="agent", level="DESTRUCTIVE",
                                  target_paths=deleted_paths, status="SUCCESS",
                                  details=f"移入系统回收站 (共 {len(deleted_paths)} 项，不可自动撤回)")

        md_report = self.format_delete_results_for_llm(execution_results)
        return {
            "success": any(r["success"] for r in execution_results),
            "results": execution_results,
            "message": md_report + "\n\n> ⚠️ **提示**：资产已安全移入系统回收站。本操作无法通过“撤销”按钮自动还原，若误删请打开操作系统回收站/废纸篓手动拾回。"
        }

    # ==================== 6. 剪切与复制（支持原地操作自愈、安全等级降级真抹标） ====================

    def _execute_transfer(self, files: Any, target_dir: str, mode: str = "cut",
                          rename_to: Optional[str] = None, overwrite: bool = False) -> Dict[str, Any]:
        is_cut = (mode == "cut")
        op_name = "剪切" if is_cut else "复制"

        if not files or not target_dir:
            return {"success": False, "message": f"必须提供待{op_name}的名单 (files) 以及目标目录 (target_dir)。"}

        file_list = files if isinstance(files, list) else [files]
        is_safe_target, verified_target_dir = self._verify_sandbox_path(target_dir)
        if not is_safe_target:
            return {"success": False, "message": f"目标目录拒绝: {verified_target_dir}"}

        verified_target_dir = os.path.normpath(verified_target_dir)
        if not os.path.exists(verified_target_dir):
            return {"success": False, "message": f"目标目录不存在: `{verified_target_dir}`。"}

        prepared_items = []
        conflicts = []
        # 执行结果按**真实处理过的源项**累计：跳过的源项也要在这里留下失败记录，
        # 使 `results` 的长度意义等于"入参项数"，而不是"碰巧能执行的那几项"。
        transfer_results: List[Dict[str, Any]] = []
        successful_reversals: List[Dict[str, Any]] = []
        root_path = self.core.config.target_path
        target_dir_level = self.asset_sec_mgr.get_effective_level(verified_target_dir, root_path)

        # 只在"单目标"时才允许整体换名，避免批量场景下多个源互相覆盖
        rename_single = self._norm_new_name(rename_to) if (rename_to and len(file_list) == 1) else ""
        if rename_to and str(rename_to).strip() and len(file_list) != 1:
            return {"success": False,
                    "message": f"换名参数 rename_to 仅在单文件{op_name}时有效，当前提供了 {len(file_list)} 个源资产。"}

        def _skip(item: Any, reason: str):
            """把"没资格进入执行阶段"的源项如实记为一条失败。

            【P2-13 修复】此前这里直接 `continue` 静默丢弃：该源项既不在
            `transfer_results`（用户看到的报告）里，也不在 `prepared_items`
            里，但它**仍在 `file_list` 中**。于是「传入 3 项、实际只处理 1 项」
            这件事对用户和审计完全不可见 —— 报告与审计都只统计剩下那一项，
            看起来像"全部成功"。现在它必须成为一条显式失败。
            """
            transfer_results.append({
                "src_path": str(item),
                "dest_path": "",
                "success": False,
                "message": f"未执行：{reason}",
            })

        def _write_transfer_audit():
            """审计流水：只记**真实发生过**的事实。

            【P2-13 修复】旧实现无条件写 `status="SUCCESS"`，`details` 用
            `len(prepared_items)`（**尝试数**）当成功数，`target_paths` 取
            **全部** prepared 项 —— 包括备份失败后被中止覆盖、根本没落盘的那些。
            后果是审计日志会记录不存在的事实：一份"3 项资产移动成功"的流水里，
            可能有 2 项从未被移动。对一个以"三级资产防护"为卖点的产品来说，
            审计不可信等于防护不可举证。

            现在三项分别对齐真实结果：
              · target_paths / 成功计数 ← successful_reversals（真正完成的项）
              · status ← 由 results 汇总；有失败则记 PARTIAL / FAILED
              · details ← 同时写明成功数与失败数，失败项在报告表格里逐条列出

            【必须在"一个源项都没执行"的提前返回路径上也调用】否则会出现
            "用户下了移动指令、系统一条流水都没记"的审计盲区。
            """
            ok_count = sum(1 for r in transfer_results if r.get("success"))
            fail_count = len(transfer_results) - ok_count
            if fail_count == 0:
                audit_status = "SUCCESS"
            elif ok_count == 0:
                audit_status = "FAILED"
            else:
                audit_status = "PARTIAL"

            audit_details = f"成功 {ok_count} 项资产{op_name}"
            if fail_count:
                audit_details += f"，失败 {fail_count} 项（详见操作报告）"

            self.core.log_audit_event(
                f"{op_name}_file",
                operator="agent",
                level="SENSITIVE" if is_cut else "SAFE",
                # 只登记**确实完成**的目标路径；原地保持（未落盘）的项不计入。
                target_paths=[x["dest"] for x in successful_reversals],
                status=audit_status,
                details=audit_details,
            )

        for item in file_list:
            records = self._resolve_file_records(item)

            if not records:
                _skip(item, f"无法在索引中定位该资产，也不是工作区内存在的物理路径（{op_name}未执行）")
                continue

            resolved_id, resolved_path = records[0]
            if not resolved_path or not os.path.exists(resolved_path):
                _skip(item, f"物理对象在磁盘上已不存在（{op_name}未执行）")
                continue

            is_safe_src, verified_src_path = self._verify_sandbox_path(resolved_path)
            if not is_safe_src:
                _skip(item, verified_src_path)
                continue

            verified_src_path = os.path.normpath(verified_src_path)
            base_name = os.path.basename(verified_src_path)
            effective_name = rename_single or base_name

            # 【阶段 3 单一来源】安全事实统一由 compute_transfer_facts 产出
            facts = self.compute_transfer_facts(verified_src_path, verified_target_dir, effective_name)
            dest_path = facts["dest_path"]

            # 【安全加固】换名结果必须仍然落在已授权的目标目录之内，杜绝 ../ 越界与覆盖工作区外文件
            if not facts["dest_within_sandbox"]:
                return {"success": False,
                        "message": f"安全拒绝：换名后的目标路径 `{dest_path}` 超出授权工作区或非法的目录边界。"}
            if os.path.basename(dest_path) != effective_name:
                return {"success": False,
                        "message": f"安全拒绝：新名称 `{rename_to}` 不允许包含路径分隔符或上级目录引用。"}

            is_same_place = facts["is_same_place"]
            # 口径：用户已授权覆盖（overwrite=True）时不再计入冲突
            if facts["would_overwrite"] and not overwrite:
                conflicts.append({"src": facts["src_path"], "dest": dest_path, "file_name": effective_name})

            prepared_items.append({
                "fid": resolved_id,
                "src_path": facts["src_path"],
                "dest_path": dest_path,
                "file_name": effective_name,
                "is_dir": facts["is_dir"],
                "is_same_place": is_same_place,
                "is_downgrade": facts["is_downgrade"],
                "original_level": facts["src_level"],
                "target_level": facts["target_dir_level"],
                "is_overwriting": bool(facts["would_overwrite"] and overwrite)
            })

        if conflicts:
            return {
                "success": False,
                "is_conflict": True,
                "conflicts": conflicts,
                "message": f"⚠️ 命名冲突：目标目录已存在同名资产 `{conflicts[0]['file_name']}`！请选择【覆盖替换原有文件】、【更换新名称】或【取消操作】。"
            }

        # 一个源项都没能进入执行阶段：如实记审计 + 如实返回失败，
        # 不再生成"完成 0 项"的假成功，也不再出现"操作过但无流水"的盲区。
        if not prepared_items:
            _write_transfer_audit()
            md_report = self.format_transfer_results_for_llm(transfer_results, verified_target_dir, op_name, overwrite)
            return {
                "success": False,
                "results": transfer_results,
                "message": md_report,
            }

        backup_dir = self._backup_dir()

        for p in prepared_items:
            src = p["src_path"]
            dest = p["dest_path"]
            fid = p["fid"]
            fname = p["file_name"]
            is_d = p["is_dir"]
            is_same = p.get("is_same_place", False)
            is_down = p.get("is_downgrade", False)
            orig_lvl = p.get("original_level", 1)
            tgt_lvl = p.get("target_level", 1)
            is_ovw = p.get("is_overwriting", False)
            backup_file_path = None

            if is_same:
                transfer_results.append({
                    "src_path": src,
                    "dest_path": dest,
                    "success": True,
                    "message": f"资产已在目标目录下（路径未改变），无需物理{op_name}（原地保持成功）"
                })
                continue

            if is_ovw:
                try:
                    # 【SEC-03 修复】备份目录必须通过沙箱校验；不可用则直接抛错走下方
                    # 既有的"中止本次覆盖"分支，绝不退化成无快照覆盖。
                    if not backup_dir:
                        raise RuntimeError("覆盖备份目录不可用（未通过沙箱校验或命中黑名单）")
                    backup_file_path = os.path.join(backup_dir, f"bak_{uuid.uuid4().hex}_{fname}")
                    if os.path.isdir(dest):
                        shutil.copytree(dest, backup_file_path)
                    else:
                        shutil.copy2(dest, backup_file_path)
                except Exception as bak_err:
                    # 覆盖替换必须先拿到可还原快照，否则宁可中止本次覆盖，也不做不可逆破坏
                    logger.error(f"备份被覆盖文件失败，已中止本次覆盖: {bak_err}")
                    backup_file_path = None
                    transfer_results.append({
                        "src_path": src, "dest_path": dest, "success": False,
                        "message": f"覆盖前安全快照生成失败，已中止覆盖以保护原有数据: {bak_err}"
                    })
                    continue

            try:
                if is_cut:
                    if is_ovw:
                        if os.path.isdir(dest):
                            shutil.rmtree(dest)
                        else:
                            os.remove(dest)
                    try:
                        os.replace(src, dest)
                    except OSError:
                        shutil.move(src, dest)

                    transfer_info = self.asset_sec_mgr.handle_transfer_security_levels(
                        old_src=src,
                        new_dest=dest,
                        target_root=root_path,
                        is_dir=is_d,
                        is_downgrade=is_down
                    )

                    succ_msg = "剪切移动成功" + (" (已覆盖原有同名文件)" if is_ovw else "")
                    if is_down:
                        succ_msg += f"（已按降级规则降为目标目录的【{tgt_lvl}级】）"

                    transfer_results.append({"src_path": src, "dest_path": dest, "success": True, "message": succ_msg})
                    successful_reversals.append({
                        "src": src, "dest": dest, "fid": fid, "is_dir": is_d,
                        "file_name": fname, "is_overwritten": is_ovw, "backup_path": backup_file_path,
                        "is_copy": False, "is_downgrade": is_down, "original_level": orig_lvl
                    })
                else:
                    if is_ovw:
                        if os.path.isdir(dest):
                            shutil.rmtree(dest)
                        else:
                            os.remove(dest)
                    # 先把源复制到临时邻接文件，再原子替换，避免复制中断导致目标目录残缺
                    tmp_dest = dest + f".__agent_tmp_{uuid.uuid4().hex[:8]}"
                    try:
                        if is_d:
                            shutil.copytree(src, tmp_dest)
                        else:
                            shutil.copy2(src, tmp_dest)
                        os.replace(tmp_dest, dest)
                    except Exception:
                        if os.path.isdir(tmp_dest):
                            shutil.rmtree(tmp_dest, ignore_errors=True)
                        elif os.path.exists(tmp_dest):
                            try:
                                os.remove(tmp_dest)
                            except Exception:
                                pass
                        raise
                    # 【D3 修复（订正）】复制**不得降低保护等级**。
                    #
                    # 旧修复只补了告警与流水，等级照降：把 3 级机密复制进 1 级目录，
                    # 副本会落到"根级别"（1 级 = 无任何显式记录），
                    # 而 copy_file 本身是免密动作 → 等于提供了一条"顺手复制一份
                    # 免密普通副本"的绕行通道，把机密原样留在低保护目录里。
                    #
                    # 复制与移动的语义本来就不该相同：
                    #   · 移动：源文件不在了，跟着目标目录走是合理的（降级成立）；
                    #   · 复制：源文件仍受原级保护，新副本没有理由比源更弱。
                    # 因此副本等级取 **源与目标中更高的那个**，并且只要高于 1 级
                    # 就必须**显式落键**（1 级在本项目里等于"无标记"，不可审计，
                    # 不能作为机密资产的存在形式）。
                    #
                    # 需要"把机密降级成普通"时，唯一合法通道是 set_security_level
                    # ——那条路径已被网关定为破坏性操作、强制校验主密码。
                    dest_service_level = max(orig_lvl, target_dir_level)
                    if dest_service_level > 1:
                        try:
                            self.asset_sec_mgr.set_asset_level(
                                dest, dest_service_level, root_path, is_dir=is_d
                            )
                        except Exception as lvl_err:
                            logger.error(f"复制后安全等级映射失败（副本可能落到默认等级）: {lvl_err}")

                    copied_msg = "副本复制成功" + (" (已覆盖原有同名文件)" if is_ovw else "")
                    if is_down:
                        copied_msg += (
                            f"（⚠️ 源资产原为【{orig_lvl}级】，目标目录仅受"
                            f"【{target_dir_level}级】保护；副本**不随目标降级**，"
                            f"仍按【{dest_service_level}级】保护。"
                            f"如需将机密降级为普通资产，请显式执行「设置安全等级」并校验主密码）"
                        )

                    transfer_results.append({"src_path": src, "dest_path": dest, "success": True, "message": copied_msg})
                    successful_reversals.append({
                        "src": src, "dest": dest, "fid": fid, "is_dir": is_d,
                        "file_name": fname, "is_overwritten": is_ovw, "backup_path": backup_file_path,
                        "is_copy": True, "is_downgrade": is_down, "original_level": orig_lvl
                    })
                    self.core.index_single_asset_or_tree(dest)
            except Exception as e:
                transfer_results.append({"src_path": src, "dest_path": dest, "success": False, "message": f"{op_name}失败: {str(e)}"})

        if successful_reversals:
            op_id = str(uuid.uuid4())[:8]
            if is_cut:
                for item in successful_reversals:
                    src, dest, fid, is_d, fname = item["src"], item["dest"], item["fid"], item["is_dir"], item["file_name"]
                    is_down_item = item.get("is_downgrade", False)
                    new_ext = "" if is_d else os.path.splitext(fname)[1].lower()

                    try:
                        with self.core.db.session() as conn:
                            with conn:
                                # 【D1 修复】降级移动不再在这里写死 `security_level = target_dir_level`。
                                # 该列的语义是"派生缓存"，真相源是 data/asset_security_levels.json 的
                                # 显式标记 + 父目录动态继承。旧实现写入的 target_dir_level 只是
                                # "此刻碰巧等于生效等级"的快照：一旦目标目录等级变化就过期，
                                # 且与 JSON 语义（"删掉显式标记、靠继承"）相互矛盾。
                                # 现在统一交给 IndexerCore.recompute_effective_security_levels()
                                # 从真相源重建，避免多处各自维护导致漂移。
                                sec_lvl_sql = ""
                                sec_lvl_params = []

                                if fid is not None and fid != -1:
                                    conn.execute(
                                        f"UPDATE files SET {sec_lvl_sql}file_path = ?, file_name = ?, file_extension = ?, vector_indexed = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                                        sec_lvl_params + [dest, fname, new_ext, fid]
                                    )
                                    conn.execute("DELETE FROM files_fts WHERE file_id = ?", (str(fid),))
                                else:
                                    conn.execute(
                                        f"UPDATE files SET {sec_lvl_sql}file_path = ?, file_name = ?, file_extension = ?, vector_indexed = 0, updated_at = CURRENT_TIMESTAMP WHERE file_path = ?",
                                        sec_lvl_params + [dest, fname, new_ext, src]
                                    )

                                if is_d:
                                    cursor = conn.cursor()
                                    # 【BUG-LIKE】src 是真实目录路径，前缀必须转义
                                    cursor.execute(
                                        "SELECT id, file_path FROM files WHERE "
                                        "(file_path LIKE ? ESCAPE '!' OR file_path LIKE ? ESCAPE '!') "
                                        "AND is_deleted = 0",
                                        (self._like_prefix(src, "\\"), self._like_prefix(src, "/"))
                                    )
                                    sub_rows = cursor.fetchall()
                                    old_len = len(src)
                                    sub_ids = []
                                    for s_id, s_path in sub_rows:
                                        s_new_p = os.path.normpath(dest + s_path[old_len:])
                                        conn.execute(
                                            f"UPDATE files SET {sec_lvl_sql}file_path = ?, vector_indexed = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                                            sec_lvl_params + [s_new_p, s_id]
                                        )
                                        sub_ids.append(s_id)
                                    if sub_ids:
                                        q_marks = ','.join(['?'] * len(sub_ids))
                                        conn.execute(f"DELETE FROM files_fts WHERE file_id IN ({q_marks})", [str(x) for x in sub_ids])
                                        self.core.vdb.delete_by_file_ids(sub_ids)

                        if fid is not None and fid != -1:
                            self.core.vdb.delete_by_file_ids([fid])
                    except Exception as sync_err:
                        logger.error(f"移动后数据库路径级联更新异常: {sync_err}")

            # 【D1 修复】原 D3 修复在此为"降级复制"显式写入 DB security_level。
            # 现统一交由 IndexerCore.recompute_effective_security_levels() 从灾备真相源
            # 重建该派生列，避免"每个操作各写一份"导致的多头维护与漂移。
            # 复制动作本身仍会（由上面的复制分支）为副本补记目标目录的生效等级到 JSON，
            # 因此真相源是完整的；派生列在启动/需要时重建即可。

            self.core.record_operation_journal(
                operation_id=op_id,
                action_type="move" if is_cut else "copy",
                operator="agent",
                src_path=json.dumps([x["src"] for x in successful_reversals], ensure_ascii=False),
                dest_path=json.dumps([x["dest"] for x in successful_reversals], ensure_ascii=False),
                extra_meta={"items": successful_reversals, "target_dir": verified_target_dir},
                can_undo=True
            )

            try:
                threading.Thread(target=self.core.build_vector_index, kwargs={"batch_size": 32}, daemon=True).start()
            except Exception:
                pass

        _write_transfer_audit()

        md_report = self.format_transfer_results_for_llm(transfer_results, verified_target_dir, op_name, overwrite)
        return {
            # 只有**全部**源项都成功才算成功：旧实现用 any(...)，
            # 10 项里成功 1 项也会对外宣告成功。
            "success": bool(transfer_results) and all(r["success"] for r in transfer_results),
            "results": transfer_results,
            "message": md_report
        }

    def move_file(self, files: Any, target_dir: str, rename_to: Optional[str] = None, overwrite: bool = False) -> Dict[str, Any]:
        return self._execute_transfer(files=files, target_dir=target_dir, mode="cut", rename_to=rename_to, overwrite=overwrite)

    def copy_file(self, files: Any, target_dir: str, rename_to: Optional[str] = None, overwrite: bool = False) -> Dict[str, Any]:
        return self._execute_transfer(files=files, target_dir=target_dir, mode="copy", rename_to=rename_to, overwrite=overwrite)

    # ==================== 7. 重命名文件/文件夹 (强化版：支持智能自愈与路径解析) ====================

    def rename_file(self, target_identifier: Any = None, new_name: str = "",
                    file_id: Optional[Any] = None, file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        根据数字 ID 或文件/文件夹路径执行安全重命名。
        - 彻底兼容 AI 传入 file_path 字符串或 file_id 整型；
        - 若目标存在于物理磁盘但尚未建表索引，自动即时入库后完成重命名；
        - 同步更新数据库 files、倒排表 files_fts、向量库 LanceDB、安全等级灾备映射；
        - 记录可逆向回转的操作流水。
        """
        clean_new_name = os.path.basename(str(new_name).strip())
        if not clean_new_name or clean_new_name != str(new_name).strip():
            return {"success": False, "message": "新名称非法：禁止包含路径分隔符或首尾留白。"}

        invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        if any(c in clean_new_name for c in invalid_chars):
            return {"success": False, "message": f"新名称包含系统保留非法字符: {clean_new_name}"}

        target = file_id if file_id is not None else (file_path if file_path is not None else target_identifier)
        if target is None or str(target).strip() == "":
            return {"success": False, "message": "未提供有效的文件标识 (请提供 file_path 或 file_id)。"}

        resolved_fid, resolved_path = None, None
        records = self._resolve_file_records(target)
        if records:
            resolved_fid, resolved_path = records[0]

        if not resolved_path or not os.path.exists(resolved_path):
            is_safe, v_p = self._verify_sandbox_path(str(target))
            if is_safe and os.path.exists(v_p):
                self.core.index_single_asset_or_tree(v_p)
                resolved_path = v_p
                with self.core.db.session() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT id FROM files WHERE file_path = ? AND is_deleted = 0", (resolved_path,))
                    row = cursor.fetchone()
                    if row:
                        resolved_fid = row[0]

        if not resolved_path or not os.path.exists(resolved_path):
            return {"success": False, "message": f"待重命名的物理资产在工作区内不存在: `{target}`"}

        resolved_path = os.path.normpath(resolved_path)
        is_safe_src, verified_old_path = self._verify_sandbox_path(resolved_path)
        if not is_safe_src:
            return {"success": False, "message": verified_old_path}

        old_name = os.path.basename(verified_old_path)
        if clean_new_name == old_name:
            return {"success": True, "message": f"资产名称已为 `{clean_new_name}`，无需修改。"}

        is_d = os.path.isdir(verified_old_path)
        parent_dir = os.path.dirname(verified_old_path)
        target_new_path = os.path.normpath(os.path.join(parent_dir, clean_new_name))

        is_case_only = (os.path.normcase(verified_old_path) == os.path.normcase(target_new_path))
        if not is_case_only and os.path.lexists(target_new_path):
            return {
                "success": False,
                "is_conflict": True,
                "conflict_path": target_new_path,
                "file_name": clean_new_name,
                "message": f"⚠️ 命名冲突：所在目录下已存在同名资产 `{clean_new_name}`！已阻断覆盖。"
            }

        if resolved_fid is None or resolved_fid == -1:
            self.core.index_single_asset_or_tree(verified_old_path)
            with self.core.db.session() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM files WHERE file_path = ? AND is_deleted = 0", (verified_old_path,))
                r = cursor.fetchone()
                if r:
                    resolved_fid = r[0]

        if resolved_fid is None or resolved_fid == -1:
            return {"success": False, "message": f"无法为资产建立有效数据库主键进行受控重命名: {verified_old_path}"}

        success, msg = self.core.rename_file(resolved_fid, clean_new_name)
        if not success:
            return {"success": False, "message": msg}

        new_actual_path = msg
        root_p = self.core.config.target_path

        # 【D5 修复】必须检查灾备是否真的落盘成功。若 JSON 写失败而这里静默放过，
        # 结果是"磁盘与 DB 已是新路径，但灾备清单里仍留着旧路径的等级标记"；
        # 下次冷启动 reseed 会把该等级灌到一个**已不存在的路径**上，
        # 被重命名的资产于是静默掉级（3 级机密变成普通资产）而无人察觉。
        remap_info = self.asset_sec_mgr.remap_paths_after_transfer(
            verified_old_path, new_actual_path, root_p, is_dir=is_d
        )
        sec_persist_warning = ""
        if isinstance(remap_info, dict) and remap_info.get("persisted") is False:
            sec_persist_warning = (
                "⚠️ 安全等级灾备清单落盘失败：重命名已在磁盘与数据库完成，但 "
                "data/asset_security_levels.json 未能写入。请立即检查该文件可写性，"
                "否则重启后该资产的显式安全等级会丢失（可能静默降级）。"
            )
            logger.error(
                "重命名后灾备落盘失败: %s -> %s (action=%s)",
                verified_old_path, new_actual_path, remap_info.get("action")
            )

        op_id = str(uuid.uuid4())[:8]
        self.core.record_operation_journal(
            operation_id=op_id,
            action_type="rename",
            operator="agent",
            src_path=old_name,
            dest_path=new_actual_path,
            extra_meta={
                "file_id": resolved_fid,
                "old_name": old_name,
                "new_name": clean_new_name,
                "old_path": verified_old_path,
                "new_path": new_actual_path,
                "is_dir": is_d
            },
            can_undo=True
        )

        self.core.log_audit_event(
            action_name="rename_file",
            operator="agent",
            level="SENSITIVE",
            target_paths=[verified_old_path, new_actual_path],
            status="SUCCESS",
            details=f"重命名成功: `{old_name}` -> `{clean_new_name}`"
        )

        asset_type = "目录文件夹" if is_d else "文件"
        ok_msg = (
            f"✅ {asset_type}重命名成功: `{old_name}` -> `{clean_new_name}`\n"
            f"完整物理路径已更新为: `{new_actual_path}`"
        )
        if sec_persist_warning:
            ok_msg += f"\n\n{sec_persist_warning}"
        return {
            "success": True,
            "operation_id": op_id,
            "old_name": old_name,
            "new_name": clean_new_name,
            "path": new_actual_path,
            "message": ok_msg
        }

    # ==================== 8. 调整资产安全等级 (新增：支持 AI 调度与原子撤回) ====================

    def set_security_level(self, target_identifier: Any = None, target_level: int = 1,
                           file_id: Optional[Any] = None, file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        让 AI 或业务调整工作区特定文件或目录的安全等级 (1普通 / 2敏感 / 3机密)。
        - 联动 AssetSecurityManager 原子持久化到 data/asset_security_levels.json 灾备文件；
        - 级联更新 SQLite files.security_level；若将目录设为 2/3 级，自动将下属子资产标记清理为 1（恢复动态继承）；
        - 产生可撤销流水 (Undo Journal)，撤回时无损还原回先前的显式安全等级。
        """
        try:
            target_lvl = int(target_level)
            if target_lvl not in (1, 2, 3):
                return {"success": False, "message": "无效的目标安全等级，必须为 1(普通)、2(敏感) 或 3(机密)。"}
        except (ValueError, TypeError):
            return {"success": False, "message": "目标安全等级参数解析失败，必须为整型 (1/2/3)。"}

        target = file_id if file_id is not None else (file_path if file_path is not None else target_identifier)
        if target is None or str(target).strip() == "":
            return {"success": False, "message": "必须提供待调整安全级别的资产标识 (file_path 或 file_id)。"}

        records = self._resolve_file_records(target)
        resolved_fid, resolved_path = None, None
        if records:
            resolved_fid, resolved_path = records[0]

        if not resolved_path or not os.path.exists(resolved_path):
            is_safe, v_p = self._verify_sandbox_path(str(target))
            if is_safe and os.path.exists(v_p):
                self.core.index_single_asset_or_tree(v_p)
                resolved_path = v_p
                records = self._resolve_file_records(v_p)
                if records:
                    resolved_fid = records[0][0]

        if not resolved_path or not os.path.exists(resolved_path):
            return {"success": False, "message": f"目标资产在物理磁盘或沙箱工作区中不存在: `{target}`"}

        resolved_path = os.path.normpath(resolved_path)
        is_safe_src, verified_path = self._verify_sandbox_path(resolved_path)
        if not is_safe_src:
            return {"success": False, "message": verified_path}

        root_path = self.core.config.target_path
        rel_p = self.asset_sec_mgr.to_rel_path(verified_path, root_path)
        old_explicit_lvl = self.asset_sec_mgr.get_explicit_level(rel_p)
        old_effective_lvl = self.asset_sec_mgr.get_effective_level(verified_path, root_path)
        is_d = os.path.isdir(verified_path)

        if target_lvl == old_explicit_lvl:
            return {
                "success": True,
                "message": f"资产 `{os.path.basename(verified_path)}` 的显式安全等级已经是【{target_lvl}级】，无需调整。"
            }

        # 【BUG-07 修复】目录设级会清理子项显式标记，必须先把子项显式等级完整快照下来，
        # 否则撤销时父目录回退了，子项原有等级却永久丢失。
        prev_child_levels: Dict[str, int] = {}
        if is_d:
            rel_prefix = (rel_p + "/") if rel_p else ""
            if rel_prefix:
                prev_child_levels = {
                    k: v for k, v in self.asset_sec_mgr.get_all_records().items()
                    if k.startswith(rel_prefix)
                }

        res = self.asset_sec_mgr.set_asset_level(
            abs_or_rel_path=verified_path,
            level=target_lvl,
            target_root=root_path,
            is_dir=is_d
        )
        if not res.get("success"):
            return {"success": False, "message": f"持久化安全等级灾备失败: {res.get('message')}"}

        cleaned_sub = res.get("cleaned_sub_items", [])

        # 【D4 修复】DB 侧写入失败必须回滚 JSON 灾备并明确报错。
        # 旧实现把 DB 写入放在 JSON 落盘之后、且不检查结果、也不写流水：
        # 一旦 DB 写失败（锁超时 / busy / 磁盘异常），就会出现
        # "JSON 已改、DB 未改、且没有任何流水记录"的三重不一致状态 ——
        # 既不可撤销，也不会有任何报错，用户完全无感。
        try:
            db_res = self.core.update_asset_security_level(verified_path, target_lvl, is_dir=is_d)
            if isinstance(db_res, dict) and db_res.get("success") is False:
                raise RuntimeError(db_res.get("message", "未知错误"))
        except Exception as db_err:
            logger.error("安全等级 DB 同步失败，正在回滚灾备 JSON: %s", db_err)
            try:
                # 【D4 补完】回滚必须"整体还原"，不能只还原被操作的那个目录。
                # 成功路径上 set_asset_level(目录, 2/3) 已按业务规则清掉了其下所有子项的
                # 显式标记（见上方 prev_child_levels 快照的用途）；若回滚只写回父目录，
                # 那些子项标记就永久消失了 —— 用户侧表现为"一个已失败、且提示
                # '未产生任何变更'的操作，静默把机密子文件降成了普通文件"。
                # 因此这里把"操作前的完整显式标记快照"一次性写回（不触发级联清理）。
                rollback_levels: Dict[str, int] = {}
                if rel_p:
                    rollback_levels[rel_p] = old_explicit_lvl
                for k, v in prev_child_levels.items():
                    rollback_levels[k] = v
                restored_ok = self.asset_sec_mgr.restore_levels(rollback_levels)
                if not restored_ok:
                    raise RuntimeError("灾备文件写盘失败")
                return {
                    "success": False,
                    "message": (f"安全等级写入失败（数据库同步异常），已回滚灾备记录，未产生任何变更: {db_err}")
                }
            except Exception as rollback_err:
                return {
                    "success": False,
                    "message": (f"安全等级写入失败，且灾备回滚亦失败，请人工核查 "
                                f"data/asset_security_levels.json 与数据库一致性: "
                                f"db={db_err}, rollback={rollback_err}")
                }

        op_id = str(uuid.uuid4())[:8]
        self.core.record_operation_journal(
            operation_id=op_id,
            action_type="set_security_level",
            operator="agent",
            src_path=str(old_explicit_lvl),
            dest_path=str(target_lvl),
            extra_meta={
                "abs_path": verified_path,
                "rel_path": rel_p,
                "is_dir": is_d,
                "old_explicit_level": old_explicit_lvl,
                "old_effective_level": old_effective_lvl,
                "new_level": target_lvl,
                "cleaned_sub_items": cleaned_sub,
                "prev_child_levels": prev_child_levels
            },
            can_undo=True
        )

        lvl_names = {1: "1级 (普通)", 2: "2级 (敏感)", 3: "3级 (机密)"}
        audit_lvl = "DESTRUCTIVE" if (target_lvl == 3 or old_effective_lvl == 3) else ("SENSITIVE" if (target_lvl == 2 or old_effective_lvl == 2) else "SAFE")
        self.core.log_audit_event(
            action_name="set_security_level",
            operator="agent",
            level=audit_lvl,
            target_paths=[verified_path],
            status="SUCCESS",
            details=f"将安全级别由【{lvl_names.get(old_effective_lvl)}】调整为【{lvl_names.get(target_lvl)}】"
        )

        sub_clean_hint = f"（注：已自动将其下 {len(cleaned_sub)} 项子资产重置为 1 级，统一由本目录动态继承）" if cleaned_sub else ""
        return {
            "success": True,
            "operation_id": op_id,
            "target": verified_path,
            "old_level": old_effective_lvl,
            "new_level": target_lvl,
            "cleaned_sub_count": len(cleaned_sub),
            "message": (
                f"🛡️ 成功将资产 `{os.path.basename(verified_path)}` 的安全等级调整为【{lvl_names.get(target_lvl)}】！\n"
                f"- **物理路径**: `{verified_path}`\n"
                f"- **先前生效等级**: {lvl_names.get(old_effective_lvl)}\n"
                f"- **当前生效等级**: {lvl_names.get(target_lvl)} {sub_clean_hint}\n"
                f"- 数据已同步写入灾备清单与底层索引，支持点击顶栏“↩ 撤销”进行原样回退。"
            )
        }

    # ==================== 9. 原生原子撤销引擎 (多步可逆与变动自愈) ====================

    def get_undo_status(self) -> Dict[str, Any]:
        """查询当前会话是否还有可撤销操作，供前端按钮置灰控制"""
        last_op = self.core.get_last_undoable_operation()
        if not last_op:
            return {"can_undo": False, "last_action": "", "formatted_time": ""}
        return {
            "can_undo": True,
            "last_action": last_op.get("action_type", ""),
            "formatted_time": last_op.get("formatted_time", "")
        }

    def undo_last_operation(self) -> Dict[str, Any]:
        """
        硬性原子撤销操作：结构化返回撤销动作与资产清单，精准同步物理磁盘、SQLite/FTS5、安全等级灾备与 LanceDB。
        """
        last_op = self.core.get_last_undoable_operation()
        if not last_op:
            return {
                "success": False,
                "can_undo": False,
                "message": "当前没有可撤回的操作记录。"
            }

        rec_id = last_op["id"]
        action = last_op["action_type"]
        meta = json.loads(last_op.get("extra_meta", "{}"))
        root_path = self.core.config.target_path

        affected_items = []
        action_summary = ""

        try:
            if action in ("move", "copy"):
                items = meta.get("items", [])
                reverted_count = 0
                for it in items:
                    src = os.path.normpath(it["src"])
                    dest = os.path.normpath(it["dest"])
                    is_d = it.get("is_dir", False)
                    fname = it.get("file_name", os.path.basename(src))
                    is_ovw = it.get("is_overwritten", False)
                    bak_path = it.get("backup_path")
                    is_copy = it.get("is_copy", (action == "copy"))
                    is_down = it.get("is_downgrade", False)
                    orig_lvl = it.get("original_level", 1)

                    if is_copy:
                        dest_ids = self._collect_subtree_ids(dest)
                        if os.path.exists(dest):
                            if is_d:
                                shutil.rmtree(dest)
                            else:
                                os.remove(dest)
                        if dest_ids:
                            self._cleanup_db_records(dest_ids, status="undone")
                        # 【D3 修复配套】撤销复制时必须把副本路径上的显式等级标记一并抹除。
                        # 否则会残留一条指向"已不存在的副本路径"的灾备记录：
                        # 冷启动 reseed 时该幽灵路径会被反复重灌，并有被后续同名新文件
                        # 意外继承该等级的风险。1 级即从灾备清单中移除。
                        # 注意：被覆盖的既有文件随后会从快照还原并重新入库，其等级由
                        # 还原流程自行决定，故此处不干预该情形。
                        self.asset_sec_mgr.set_asset_level(dest, 1, root_path, is_dir=is_d)
                        affected_items.append(f"清理复制副本并注销索引: {dest}")
                    else:
                        os.makedirs(os.path.dirname(src), exist_ok=True)
                        try:
                            os.replace(dest, src)
                        except OSError:
                            shutil.move(dest, src)

                        self.asset_sec_mgr.handle_transfer_security_levels(
                            old_src=dest, new_dest=src, target_root=root_path, is_dir=is_d, is_downgrade=False
                        )
                        if is_down and orig_lvl > 1:
                            self.asset_sec_mgr.set_asset_level(src, orig_lvl, root_path, is_dir=is_d)

                        dest_ids = self._collect_subtree_ids(dest)
                        if dest_ids:
                            self._cleanup_db_records(dest_ids, status="undone")

                        affected_items.append(f"移回原位: {dest} -> {src}")

                    if is_ovw and bak_path and os.path.exists(bak_path):
                        try:
                            if os.path.isdir(bak_path):
                                shutil.copytree(bak_path, dest)
                                shutil.rmtree(bak_path)
                            else:
                                shutil.copy2(bak_path, dest)
                                os.remove(bak_path)
                            self.core.index_single_asset_or_tree(dest)
                            affected_items.append(f"恢复被覆盖的原文件并重新入库: {dest}")
                        except Exception as r_err:
                            logger.error(f"还原被覆盖文件失败: {r_err}")

                    if not is_copy:
                        self.core.index_single_asset_or_tree(src)

                    reverted_count += 1

                action_summary = f"撤销【{'移动' if action == 'move' else '复制'}】：恢复了 {reverted_count} 项资产"

            elif action in ("write_create", "write_modify"):
                target_f = os.path.normpath(meta.get("file_path", last_op.get("dest_path", "")))
                backups = meta.get("overwritten_backups") or {}
                if backups:
                    # 覆盖写入：还原被覆盖前的原文内容，绝不删除既有资产
                    target_f = os.path.normpath(list(backups.keys())[0])
                    bak_p = backups[list(backups.keys())[0]]
                    restored = False
                    if os.path.exists(bak_p):
                        os.makedirs(os.path.dirname(target_f), exist_ok=True)
                        shutil.copy2(bak_p, target_f)
                        try:
                            os.remove(bak_p)
                        except Exception:
                            pass
                        self.core.index_single_asset_or_tree(target_f)
                        restored = True
                    affected_items.append(
                        f"还原被覆盖写入前的原文件内容: {target_f}" if restored
                        else f"未能还原被覆盖文件（快照缺失）: {target_f}"
                    )
                    action_summary = f"撤销【覆盖写入】：已还原 `{os.path.basename(target_f)}` 原有内容"
                else:
                    ids = self._collect_subtree_ids(target_f)
                    if os.path.exists(target_f):
                        os.remove(target_f)
                    if ids:
                        self._cleanup_db_records(ids, status="undone")
                    affected_items.append(f"删除新建文件并注销索引: {target_f}")
                    action_summary = f"撤销【新建文件】：清理了 `{os.path.basename(target_f)}`"

            elif action == "create_dir":
                target_d = os.path.normpath(meta.get("dir_path", last_op.get("dest_path", "")))
                if os.path.exists(target_d):
                    try:
                        os.rmdir(target_d)
                    except OSError:
                        # 目录已被后续操作写入内容：不做破坏性删除，仅注销索引并允许继续撤销更早操作
                        try:
                            left = len(os.listdir(target_d))
                        except Exception:
                            left = -1
                        affected_items.append(
                            f"目录 `{target_d}` 已非空（残留 {left} 项），已保留物理文件不再删除；仅注销其索引记录"
                        )
                        action_summary = f"撤销【新建目录】：`{os.path.basename(target_d)}` 已非空，已保留并注销索引"
                        ids = self._collect_subtree_ids(target_d)
                        if ids:
                            self._cleanup_db_records(ids, status="undone")
                        self.core.mark_operation_undone(rec_id)
                        remaining_can_undo = self.core.has_undoable_operations()
                        self.core.log_audit_event("undo_operation", operator="user_manual", level="SAFE",
                                                  target_paths=[target_d], status="SUCCESS", details=action_summary)
                        return {
                            "success": True,
                            "can_undo": remaining_can_undo,
                            "action_type": action,
                            "summary": action_summary,
                            "affected_items": affected_items,
                            "message": f"✅ {action_summary}。\n变动明细：\n" + "\n".join([f"- {it}" for it in affected_items])
                        }
                ids = self._collect_subtree_ids(target_d)
                if ids:
                    self._cleanup_db_records(ids, status="undone")
                affected_items.append(f"删除新建目录并注销索引: {target_d}")
                action_summary = f"撤销【新建目录】：移除了 `{os.path.basename(target_d)}`"

            elif action == "compress":
                out_zip = os.path.normpath(meta.get("output_zip", last_op.get("dest_path", "")))
                backups = meta.get("overwritten_backups") or {}
                ids = self._collect_subtree_ids(out_zip)
                if os.path.exists(out_zip):
                    os.remove(out_zip)
                # 若本次打包是覆盖替换，撤销时还原被覆盖的旧压缩包
                for orig_p, bak_p in backups.items():
                    try:
                        if os.path.exists(bak_p):
                            os.makedirs(os.path.dirname(orig_p), exist_ok=True)
                            shutil.copy2(bak_p, orig_p)
                            os.remove(bak_p)
                            self.core.index_single_asset_or_tree(orig_p)
                            affected_items.append(f"还原被覆盖的原有压缩包: {orig_p}")
                    except Exception as r_err:
                        logger.error(f"还原被覆盖压缩包失败: {r_err}")
                if ids:
                    self._cleanup_db_records(ids, status="undone")
                affected_items.append(f"删除压缩包并注销索引: {out_zip}")
                action_summary = f"撤销【打包】：删除了 `{os.path.basename(out_zip)}`"

            elif action == "extract":
                extracted = meta.get("extracted_files", [])
                target_d = os.path.normpath(meta.get("target_dir", last_op.get("dest_path", "")))
                pre_existing_ids = set(meta.get("pre_existing_ids") or [])
                del_count = 0
                for ef in extracted:
                    ef_norm = os.path.normpath(ef)
                    if os.path.exists(ef_norm) and os.path.isfile(ef_norm):
                        try:
                            os.remove(ef_norm)
                            del_count += 1
                        except Exception:
                            pass

                restored = 0
                for orig_p, bak_p in (meta.get("overwritten_backups") or {}).items():
                    try:
                        if os.path.exists(bak_p):
                            os.makedirs(os.path.dirname(orig_p), exist_ok=True)
                            shutil.copy2(bak_p, orig_p)
                            os.remove(bak_p)
                            self.core.index_single_asset_or_tree(orig_p)
                            restored += 1
                    except Exception as r_err:
                        logger.error(f"还原被解压覆盖文件失败: {r_err}")

                # 【BUG-08/09 修复】只注销"本次解压新产生"的库记录：
                #   - 不再 rmtree 整个目标目录（否则会连解压前就存在的无关文件一起删掉）；
                #   - 目录若仍非空则保留，绝不破坏用户既有数据。
                post_ids = set(self._collect_subtree_ids(target_d))
                new_ids = [i for i in post_ids if i not in pre_existing_ids]
                if new_ids:
                    self._cleanup_db_records(new_ids, status="undone")
                for ef in extracted:
                    if ef and os.path.exists(os.path.normpath(ef)):
                        self.core.index_single_asset_or_tree(os.path.normpath(ef))

                if os.path.exists(target_d):
                    for r, dirs, _ in os.walk(target_d, topdown=False):
                        for d in dirs:
                            try:
                                os.rmdir(os.path.join(r, d))
                            except OSError:
                                pass
                    try:
                        os.rmdir(target_d)
                    except OSError:
                        pass

                affected_items.append(
                    f"清理本次释放的文件({del_count}个)"
                    + (f"，并还原被覆盖文件 {restored} 个" if restored else "")
                    + (f"；目标目录保留: {target_d}" if os.path.exists(target_d) else "")
                )
                action_summary = (f"撤销【解压】：清理了 {del_count} 个释放文件"
                                  + (f"，还原 {restored} 个被覆盖文件" if restored else ""))

            elif action == "rename":
                old_name = meta.get("old_name")
                file_id = meta.get("file_id")
                new_path = meta.get("new_path")
                old_path = meta.get("old_path")
                is_d = meta.get("is_dir", False)
                if file_id and old_name:
                    success, msg = self.core.rename_file(file_id, old_name)
                    if success:
                        self.asset_sec_mgr.remap_paths_after_transfer(new_path, old_path, root_path, is_dir=is_d)
                        affected_items.append(f"改回原名称并同步索引: `{old_name}`")
                        action_summary = f"撤销【重命名】：恢复为 `{old_name}`"
                    else:
                        return {"success": False, "can_undo": True, "message": f"撤销重命名失败: {msg}"}
                else:
                    return {"success": False, "can_undo": True, "message": "撤回重命名失败：元数据缺失"}

            elif action == "set_security_level":
                abs_p = meta.get("abs_path")
                old_lvl = meta.get("old_explicit_level", 1)
                is_d = meta.get("is_dir", False)
                if abs_p and os.path.exists(abs_p):
                    self.asset_sec_mgr.set_asset_level(abs_p, old_lvl, root_path, is_dir=is_d)
                    self.core.update_asset_security_level(abs_p, old_lvl, is_dir=is_d)

                    # 【BUG-07 修复】连同快照中的子项显式等级一并还原，做到真正的无损回退
                    restored_children = 0
                    for ck, cv in (meta.get("prev_child_levels") or {}).items():
                        ck_abs = os.path.normpath(os.path.join(root_path, ck.replace("/", os.sep)))
                        if not os.path.exists(ck_abs):
                            continue
                        self.asset_sec_mgr.set_asset_level(ck_abs, int(cv), root_path, is_dir=False)
                        self.core.update_asset_security_level(ck_abs, int(cv), is_dir=False)
                        restored_children += 1

                    affected_items.append(f"将 `{os.path.basename(abs_p)}` 恢复为原显式等级【{old_lvl}级】")
                    if restored_children:
                        affected_items.append(f"同时还原其下 {restored_children} 项子资产的原显式安全等级")
                    action_summary = f"撤销【修改安全等级】：恢复为【{old_lvl}级】" + (
                        f"，并还原 {restored_children} 项子资产等级" if restored_children else "")
                else:
                    return {"success": False, "can_undo": True, "message": "撤销安全等级失败：目标物理资产已不存在"}

            else:
                return {"success": False, "can_undo": True, "message": f"不支持撤销的操作类型: {action}"}

            self.core.mark_operation_undone(rec_id)
            self.core.log_audit_event("undo_operation", operator="user_manual", level="SAFE",
                                      target_paths=[last_op.get("dest_path", ""), last_op.get("src_path", "")],
                                      status="SUCCESS", details=action_summary)

            remaining_can_undo = self.core.has_undoable_operations()
            return {
                "success": True,
                "can_undo": remaining_can_undo,
                "action_type": action,
                "summary": action_summary,
                "affected_items": affected_items,
                "message": f"✅ {action_summary}。\n变动明细：\n" + "\n".join([f"- {it}" for it in affected_items])
            }

        except Exception as e:
            return {"success": False, "can_undo": True, "message": f"执行撤回异常: {str(e)}"}

    # ==================== 10. 文本阅读、RRF检索与其它常规工具 ====================

    def read_file_content(self, file_path: Optional[str] = None, file_id: Optional[Any] = None, section: str = "head") -> Dict[str, Any]:
        target_input = file_id or file_path or self.core.config.target_path
        resolved_id, resolved_path = self._resolve_file_record(target_input)
        if not resolved_path:
            return {"success": False, "message": "未提供有效的文件或文件夹路径/ID。"}

        is_safe, verified_path = self._verify_sandbox_path(resolved_path)
        if not is_safe:
            return {"success": False, "message": verified_path}

        verified_path = os.path.normpath(verified_path)
        if not os.path.exists(verified_path):
            return {"success": False, "message": f"目标物理对象不存在: {verified_path}"}

        eff_sec_level = self.asset_sec_mgr.get_effective_level(verified_path, self.core.config.target_path)

        if os.path.isdir(verified_path):
            try:
                entries = os.listdir(verified_path)
                entries.sort()
                preview = []
                for e in entries[:200]:
                    full_sub = os.path.join(verified_path, e)
                    if self.core.is_blacklisted(full_sub):
                        continue
                    sub_lvl = self.asset_sec_mgr.get_effective_level(full_sub, self.core.config.target_path)
                    lvl_badge = f" [L{sub_lvl}]" if sub_lvl > 1 else ""
                    if os.path.isdir(full_sub):
                        preview.append(f"📁 [目录]{lvl_badge} {e}")
                    else:
                        sz_str = self._format_size(os.path.getsize(full_sub)) if os.path.exists(full_sub) else "-"
                        preview.append(f"📄 [文件]{lvl_badge} {e} ({sz_str})")

                content_text = "\n".join(preview) if preview else "(当前文件夹为空或包含项受保护)"
                info = {
                    "file_id": resolved_id,
                    "file_name": os.path.basename(verified_path) or os.path.basename(self.core.config.target_path),
                    "file_path": verified_path,
                    "is_dir": True,
                    "security_level": eff_sec_level,
                    "child_count": len(preview),
                    "content": content_text
                }
                return {"success": True, "data": info, "message": self.format_read_content_for_llm(info)}
            except Exception as e:
                return {"success": False, "message": f"查看文件夹子项列表失败: {str(e)}"}

        file_size = os.path.getsize(verified_path)
        max_bytes_budget = 30 * 1024
        max_lines_budget = 500
        # 【P2-7 修复】读取截断必须用"读取专用预算"，不能把"扫描文件树的 Token 告警阈值"
        # 直接当作硬截断阈值：用户为了提前告警把它调小，就会连带把文件读取切得更短。
        token_limit = self._get_read_token_limit()

        try:
            total_lines, start_idx, end_idx, sec_desc, raw_content, selected_lines = self._read_text_section(
                verified_path, section, max_lines_budget=max_lines_budget
            )
        except Exception as e:
            return {"success": False, "message": f"文件读取异常: {str(e)}"}

        truncated = False
        truncate_reason = ""

        if len(raw_content.encode("utf-8", errors="ignore")) > max_bytes_budget:
            truncated = True
            truncate_reason = "已达单次 30KB 物理传输上限并截断"
            encoded = raw_content.encode("utf-8", errors="ignore")[:max_bytes_budget]
            raw_content = encoded.decode("utf-8", errors="ignore")

        current_tokens = count_text_tokens(raw_content)
        if current_tokens > token_limit:
            truncated = True
            truncate_reason = f"已触发单次读取的 Token 预算 ({token_limit}) 截断"
            acc_lines = []
            acc_token = 0
            for line in raw_content.splitlines(keepends=True):
                line_tokens = count_text_tokens(line)
                if acc_token + line_tokens > token_limit - 50:
                    break
                acc_lines.append(line)
                acc_token += line_tokens
            raw_content = "".join(acc_lines) + f"\n\n[...因超出单次读取 Token 预算 ({token_limit})，已自动截断...]"
            current_tokens = count_text_tokens(raw_content)

        file_name = os.path.basename(verified_path)
        ext = os.path.splitext(file_name)[1].lower()

        info = {
            "file_id": resolved_id,
            "file_name": file_name,
            "file_path": verified_path,
            "file_size": file_size,
            "is_dir": False,
            "security_level": eff_sec_level,
            "total_lines": total_lines,
            "start_line": start_idx + 1 if total_lines > 0 else 0,
            "end_line": min(start_idx + len(selected_lines), total_lines),
            "section_desc": sec_desc,
            "token_count": current_tokens,
            "truncated": truncated,
            "truncate_reason": truncate_reason,
            "ext": ext,
            "content": raw_content
        }

        return {"success": True, "data": info, "message": self.format_read_content_for_llm(info)}

    @staticmethod
    def _read_text_section(verified_path: str, section: str, max_lines_budget: int = 500) -> Tuple[int, int, int, str, str, List[str]]:
        file_size = os.path.getsize(verified_path)
        section_mode = (section or "head").strip().lower()

        if file_size <= 2 * 1024 * 1024:
            with open(verified_path, "r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
            total_lines = len(all_lines)

            if section_mode in ("tail", "后段", "后"):
                start_idx = max(0, total_lines - max_lines_budget)
                end_idx = total_lines
                sec_desc = "后段"
            elif section_mode in ("middle", "mid", "中段", "中"):
                start_idx = max(0, (total_lines - max_lines_budget) // 2)
                end_idx = min(total_lines, start_idx + max_lines_budget)
                sec_desc = "中段"
            else:
                start_idx = 0
                end_idx = min(total_lines, max_lines_budget)
                sec_desc = "前段"

            selected_lines = all_lines[start_idx:end_idx]
            return total_lines, start_idx, end_idx, sec_desc, "".join(selected_lines), selected_lines

        with open(verified_path, "r", encoding="utf-8", errors="replace") as f:
            total_lines = sum(1 for _ in f)
        start_idx = 0
        end_idx = min(total_lines, max_lines_budget)
        sec_desc = "前段"
        with open(verified_path, "r", encoding="utf-8", errors="replace") as f:
            selected_lines = list(itertools.islice(f, start_idx, end_idx))
        return total_lines, start_idx, end_idx, sec_desc, "".join(selected_lines), selected_lines

    def search_files(self, query: Optional[str] = None, ext: Optional[str] = None, parent_path: Optional[str] = None,
                     min_size_mb: Optional[float] = None, max_size_mb: Optional[float] = None, limit: int = 30) -> Dict[str, Any]:
        try:
            search_text = (query or "").strip()
            clean_limit = max(1, min(int(limit or 30), 100))

            min_bytes = int(float(min_size_mb) * 1024 * 1024) if min_size_mb is not None else None
            max_bytes = int(float(max_size_mb) * 1024 * 1024) if max_size_mb is not None else None
            clean_ext = f".{ext.strip().lower().lstrip('.')}" if ext else None

            clean_parent = None
            if parent_path:
                _, v_p = self._resolve_file_record(parent_path)
                clean_parent = (v_p or parent_path).rstrip('/\\')

            root_p = self.core.config.target_path

            if not search_text:
                clauses = ["is_deleted = 0"]
                params = []
                if clean_parent:
                    clauses.append(
                        "(file_path LIKE ? ESCAPE '!' OR file_path LIKE ? ESCAPE '!')"
                    )
                    params.extend([
                        self._like_prefix(clean_parent, "/"),
                        self._like_prefix(clean_parent, "\\"),
                    ])
                if clean_ext:
                    clauses.append("file_extension = ? COLLATE NOCASE")
                    params.append(clean_ext)
                if min_bytes is not None:
                    clauses.append("file_size >= ?")
                    params.append(min_bytes)
                if max_bytes is not None:
                    clauses.append("file_size <= ?")
                    params.append(max_bytes)

                where_sql = " AND ".join(clauses)
                with self.core.db.session() as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    cursor.execute(f"SELECT * FROM files WHERE {where_sql} ORDER BY is_dir DESC, updated_at DESC LIMIT ?", params + [clean_limit])
                    rows = [dict(r) for r in cursor.fetchall()]

                for r in rows:
                    r["match_source"] = "🕒 属性/目录过滤"
                    r["_final_score"] = 1.0
                    r["effective_security_level"] = self.asset_sec_mgr.get_effective_level(r["file_path"], root_p)

                return {"success": True, "count": len(rows), "data": rows, "message": f"检索到 {len(rows)} 项资产"}

            dense_rank_list, sparse_rank_list, exact_rank_list = [], [], []
            try:
                model = get_local_text_model()
                with _EMBED_INFERENCE_LOCK:
                    query_vec = list(model.embed([search_text]))[0].tolist()
                raw_hits = self.core.vdb.search_similar_file_ids(query_vec, top_k=150)
                dense_rank_list = [fid for fid, dist in raw_hits if dist <= 1.28]
            except Exception:
                pass

            fts_tokens = tokenize_text(search_text)
            if fts_tokens:
                safe_toks = [f'"{t.replace(chr(34), chr(34)+chr(34))}"' for t in fts_tokens.split() if t.strip()]
                if safe_toks:
                    with self.core.db.session() as conn:
                        cursor = conn.cursor()
                        try:
                            cursor.execute("SELECT file_id FROM files_fts WHERE files_fts MATCH ? LIMIT 150", (" OR ".join(safe_toks),))
                            sparse_rank_list = [int(r[0]) for r in cursor.fetchall()]
                        except Exception:
                            pass

            with self.core.db.session() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM files WHERE (file_name LIKE ? OR file_path LIKE ?) AND is_deleted = 0 LIMIT 100", (f"%{search_text}%", f"%{search_text}%"))
                exact_rank_list = [int(r[0]) for r in cursor.fetchall()]

            candidate_ids = set(dense_rank_list) | set(sparse_rank_list) | set(exact_rank_list)
            if not candidate_ids:
                return {"success": True, "count": 0, "data": [], "message": "未检索到匹配项"}

            candidate_map = {}
            id_list = list(candidate_ids)
            with self.core.db.session() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                for i in range(0, len(id_list), 200):
                    chunk = id_list[i:i + 200]
                    q = ','.join(['?'] * len(chunk))
                    cursor.execute(f"SELECT * FROM files WHERE id IN ({q}) AND is_deleted = 0", chunk)
                    for r in cursor.fetchall():
                        candidate_map[r["id"]] = dict(r)

            K = 60.0
            dense_ranks = {fid: idx + 1 for idx, fid in enumerate(dense_rank_list)}
            sparse_ranks = {fid: idx + 1 for idx, fid in enumerate(sparse_rank_list)}
            exact_ranks = {fid: idx + 1 for idx, fid in enumerate(exact_rank_list)}

            scored = []
            for fid, item in candidate_map.items():
                score = 0.0
                if fid in exact_ranks:
                    score += 1.3 / (K + exact_ranks[fid])
                if fid in sparse_ranks:
                    score += 1.1 / (K + sparse_ranks[fid])
                if fid in dense_ranks:
                    score += 1.0 / (K + dense_ranks[fid])
                item["_final_score"] = score
                item["match_source"] = "🎯 综合匹配"
                item["effective_security_level"] = self.asset_sec_mgr.get_effective_level(item["file_path"], root_p)
                scored.append(item)

            scored.sort(key=lambda x: x["_final_score"], reverse=True)
            res = scored[:clean_limit]
            return {"success": True, "count": len(res), "data": res, "message": f"成功召回 {len(res)} 项资产"}
        except Exception as e:
            return {"success": False, "count": 0, "data": [], "message": f"检索异常: {str(e)}"}

    def sync_database(self) -> Dict[str, Any]:
        try:
            stats = self.core.sync()
            return {"success": True, "data": stats, "message": f"同步完成: 扫描 {stats['total_scanned']} 项"}
        except Exception as e:
            return {"success": False, "message": f"同步失败: {str(e)}"}

    def build_vector_index(self, abort_event: Optional[threading.Event] = None) -> Dict[str, Any]:
        success, msg = self.core.build_vector_index(abort_event=abort_event)
        # 【确定性失败的处理】嵌入模型加载失败属于"必然复发"的情况，
        # 需要上层暂停工作流并询问用户（中断 / 跳过向量索引继续 / 重试）。
        # 这里用 IndexerCore 的常量识别，避免上下游各自硬编码标记字符串。
        retryable = (not success) and (
            getattr(self.core, "MODEL_UNAVAILABLE_MARK", "[MODEL_UNAVAILABLE]") in msg
        )
        return {"success": success, "message": msg, "retryable": retryable}

    def find_duplicate_files(self) -> Dict[str, Any]:
        duplicates = self.core.find_duplicates()
        return {"success": True, "group_count": len(duplicates), "data": duplicates, "message": "排重完成"}

    def get_storage_insights(self) -> Dict[str, Any]:
        return {"success": True, "data": self.core.get_storage_insights(), "message": "分析完成"}

    def open_or_locate_file(self, file_path: Optional[str] = None, file_id: Optional[Any] = None, action: str = "locate") -> Dict[str, Any]:
        target_path = None
        if file_id is not None:
            try:
                fid = int(file_id)
                with self.core.db.session() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT file_path FROM files WHERE id = ? AND is_deleted = 0", (fid,))
                    row = cursor.fetchone()
                    if row:
                        target_path = row[0]
            except Exception:
                pass

        if not target_path:
            target_path = file_path

        if not target_path:
            return {"success": False, "message": "未提供有效的文件路径或 ID。"}

        is_safe, verified_path = self._verify_sandbox_path(target_path)
        if not is_safe or not os.path.exists(verified_path):
            return {"success": False, "message": f"物理对象不存在: {verified_path}"}

        system = platform.system()
        try:
            if action == "locate":
                if system == "Windows":
                    subprocess.run(f'explorer.exe /select,"{os.path.normpath(verified_path)}"', shell=True, check=False)
                elif system == "Darwin":
                    subprocess.run(["open", "-R", verified_path], check=True)
                else:
                    subprocess.run(["xdg-open", os.path.dirname(verified_path)], check=True)
                return {"success": True, "message": f"已在管理器中高亮定位: {verified_path}"}

            elif action == "open":
                if system == "Windows":
                    os.startfile(verified_path)
                elif system == "Darwin":
                    subprocess.run(["open", verified_path], check=True)
                else:
                    subprocess.run(["xdg-open", verified_path], check=True)
                return {"success": True, "message": f"已调用系统关联程序打开: {verified_path}"}

            return {"success": False, "message": f"未知的操作系统动作: {action}"}
        except Exception as e:
            return {"success": False, "message": f"调用操作系统通道失败: {str(e)}"}

    # ==================== LLM 格式化报告 ====================

    @classmethod
    def format_search_results_for_llm(cls, results: List[Dict[str, Any]], total_count: int) -> str:
        if not results:
            return "未检索到匹配的本地资产记录。"
        lines = [
            f"**检索结果 (展示 {len(results)}/{total_count} 项)**:",
            "| ID | 类型 | 安全等级 | 名称 | 匹配特征 | 大小 | 路径 |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
        ]
        for r in results:
            fid = r.get("id", "")
            fname = r.get("file_name", "")
            is_d = bool(r.get("is_dir", 0))
            type_tag = "📁 目录" if is_d else "📄 文件"
            eff_lvl = r.get("effective_security_level", 1)
            lvl_badge = "🔴 3级机密" if eff_lvl == 3 else ("🟡 2级敏感" if eff_lvl == 2 else "🟢 1级普通")
            source = r.get("match_source", "匹配")
            size_str = "-" if is_d else cls._format_size(r.get("file_size", 0))
            fpath = r.get("file_path", "")
            display_path = ("..." + fpath[-38:]) if len(fpath) > 42 else fpath
            lines.append(f"| `{fid}` | {type_tag} | {lvl_badge} | `{fname}` | {source} | {size_str} | `{display_path}` |")
        return "\n".join(lines)

    @classmethod
    def format_duplicates_for_llm(cls, duplicates: Dict[str, List[Dict[str, Any]]]) -> str:
        if not duplicates:
            return "✅ 未发现重复哈希文件。"
        total_wasted = 0
        group_lines = []
        for idx, (fhash, flist) in enumerate(duplicates.items(), 1):
            if not flist:
                continue
            unit_size = flist[0].get("file_size", 0)
            wasted = unit_size * (len(flist) - 1)
            total_wasted += wasted
            group_lines.append(f"**第 {idx} 组** (共 {len(flist)} 份相同文件，浪费空间: {cls._format_size(wasted)}):")
            for f in flist:
                group_lines.append(f"  - `[ID: {f.get('id')}]` {f.get('file_path')}")
        header = f"⚠️ **共检测到 {len(duplicates)} 组重复文件，累计可释放空间: {cls._format_size(total_wasted)}**\n"
        return header + "\n".join(group_lines)

    @classmethod
    def format_storage_insights_for_llm(cls, insights: Dict[str, Any]) -> str:
        ext_stats = insights.get("extension_stats", [])
        large_files = insights.get("largest_files", [])
        lines = ["### 📊 磁盘存储透视体检报告", "\n**1. 空间占用最高的文件类型 (Top 10)**:"]
        if ext_stats:
            lines.append("| 后缀 | 文件数量 | 占用总大小 |\n| :--- | :--- | :--- |")
            for item in ext_stats:
                lines.append(f"| `{item.get('file_extension') or '[无后缀]'}` | {item.get('count', 0)} | {cls._format_size(item.get('total_size', 0))} |")
        lines.append("\n**2. 体积最大的前 10 个巨石文件 (Top 10)**:\n| ID | 文件名 | 体积 | 绝对路径 |\n| :--- | :--- | :--- | :--- |")
        for f in large_files:
            lines.append(f"| `{f.get('id')}` | `{f.get('file_name')}` | {cls._format_size(f.get('file_size', 0))} | `{f.get('file_path')}` |")
        return "\n".join(lines)

    @classmethod
    def format_read_content_for_llm(cls, file_info: Dict[str, Any]) -> str:
        eff_lvl = file_info.get("security_level", 1)
        lvl_str = "🔴 3级机密 (受主密码保护)" if eff_lvl == 3 else ("🟡 2级敏感 (人工确认)" if eff_lvl == 2 else "🟢 1级普通")
        if file_info.get("is_dir"):
            return (
                f"### 📁 文件夹内容详情: `{file_info['file_name']}`\n"
                f"- **安全级别**: {lvl_str}\n"
                f"- **完整绝对路径**: `{file_info['file_path']}`\n"
                f"- **包含直接子资产清单** (共 {file_info.get('child_count', 0)} 项):\n"
                f"```text\n{file_info['content']}\n```"
            )
        lines = [
            f"### 📄 文件内容查看: `{file_info['file_name']}`",
            f"- **安全级别**: {lvl_str}",
            f"- **路径**: `{file_info['file_path']}`",
            f"- **体积分段**: 共 {file_info['total_lines']} 行 ({cls._format_size(file_info['file_size'])})，当前展示 **{file_info['section_desc']}** (第 {file_info['start_line']} - {file_info['end_line']} 行)",
            f"- **Token 占用**: 约 {file_info['token_count']} Tokens"
        ]
        if file_info.get("truncated"):
            lines.append(f"⚠️ *注: {file_info['truncate_reason']}*")
        lines.append(f"\n```\n{file_info['content']}\n```")
        return "\n".join(lines)

    @classmethod
    def format_delete_results_for_llm(cls, results: List[Dict[str, Any]]) -> str:
        success_count = sum(1 for r in results if r["success"])
        fail_count = len(results) - success_count
        lines = [f"### 🗑️ 文件/目录回收站操作报告 (成功: {success_count} / 失败: {fail_count})", "| 标识/路径 | 状态 | 详情信息 |", "| :--- | :--- | :--- |"]
        for r in results:
            lines.append(f"| `{r['item']}` | {'✅ 成功' if r['success'] else '❌ 失败'} | {r['message']} |")
        return "\n".join(lines)

    @classmethod
    def format_transfer_results_for_llm(cls, results: List[Dict[str, Any]], target_dir: str, operation_name: str, overwrite: bool) -> str:
        success_count = sum(1 for r in results if r["success"])
        fail_count = len(results) - success_count
        lines = [
            f"### 📦 批量资产{operation_name}报告" + (" (覆盖替换模式)" if overwrite else " (换名模式)"),
            f"- **目标目录**: `{target_dir}`",
            f"- **概览**: 成功 {success_count} 项，失败 {fail_count} 项\n",
            "| 源路径 | 状态 | 目标路径 / 详情 |",
            "| :--- | :--- | :--- |"
        ]
        for r in results:
            dest_or_err = f"`{r['dest_path']}`" if r["success"] else r["message"]
            lines.append(f"| `{r['src_path']}` | {'✅ 完成' if r['success'] else '❌ 失败'} | {dest_or_err} |")
        return "\n".join(lines)