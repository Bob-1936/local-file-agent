# core/security.py
# -*- coding: utf-8 -*-

import os
import json
import base64
import hashlib
import secrets
import shutil
import zipfile
import time
import tempfile
import unicodedata
from datetime import datetime
from typing import Tuple, Dict, Any, Optional, List, Set


class SecurityPreCheckError(Exception):
    """安全预检拦截异常"""
    pass


class AssetSecurityManager:
    """
    资产安全等级专职管理器 (1级普通 / 2级敏感 / 3级高危机密) - 工业级单例与热感知增强版
    1. 进程级单例：同一 data_dir 下全局共享唯一实例，彻底杜绝双实例内存状态割裂；
    2. 磁盘热重载感知：每次查询自动比对文件 mtime，若外部有写入则纳秒级刷新缓存；
    3. 全平台 Windows 路径规范化：内部使用归一化键值比对，彻底杜绝盘符大小写和斜杠引起的失配；
    4. 降级真生效机制：当高等级资产移动到低等级目录时，自动抹除原有显式标记（恢复为1级），实现全员一同降级；
    5. 父级统领清理：父目录标记为 2 或 3 级时，自动将下属所有已打标子项恢复为 1 级；
    6. 原子落盘：临时文件 + rename 替换，防止写入中断导致损坏。
    """

    LEVEL_DEFAULT = 1
    LEVEL_SENSITIVE = 2
    LEVEL_CRITICAL = 3

    _instances: Dict[str, "AssetSecurityManager"] = {}

    def __new__(cls, data_dir: str):
        abs_data_dir = os.path.normcase(os.path.realpath(os.path.abspath(data_dir)))
        if abs_data_dir not in cls._instances:
            instance = super().__new__(cls)
            cls._instances[abs_data_dir] = instance
        return cls._instances[abs_data_dir]

    def __init__(self, data_dir: str):
        if getattr(self, "_initialized", False):
            return
        self.data_dir = os.path.abspath(data_dir)
        os.makedirs(self.data_dir, exist_ok=True)
        self.backup_file = os.path.join(self.data_dir, "asset_security_levels.json")
        self._levels_cache: Dict[str, int] = {}
        self._last_mtime: float = 0.0
        # 磁盘一致性签名 (mtime, size, inode)，用于可靠判定"是否需要热重载"
        self._last_stat_sig: Optional[tuple] = None
        # 灾备文件是否**成功载入**：未成功时禁止用空缓存覆写它（见 load_backup/save_backup）
        self._levels_ready: bool = False
        self.load_backup()
        self._initialized = True

    @classmethod
    def get_instance(cls, data_dir: str) -> "AssetSecurityManager":
        return cls(data_dir)

    @staticmethod
    def normalize_rel_path(raw_path: str) -> str:
        """归一化相对路径，使用统一的 POSIX 正斜杠且去除首尾斜杠与空白"""
        if not raw_path:
            return ""
        norm = unicodedata.normalize('NFC', str(raw_path).strip().replace('\\', '/'))
        return norm.strip('/')

    def to_rel_path(self, abs_or_rel_path: str, target_root: str) -> str:
        """安全转换为相对于工作区根目录的标准相对路径（Windows大小写自适应）

        【P2-2 修复】跨盘符（或任何无法计算相对路径的情形）必须返回空字符串；
        旧实现会 fallthrough 到 `normalize_rel_path(入参)`，把 `E:/secret/x.txt` 当成本工作区的
        相对路径返回出去，直接调用方（如 set_asset_level）就可能写下非法灾备键。
        """
        if not abs_or_rel_path:
            return ""
        norm_root = os.path.normcase(os.path.realpath(os.path.abspath(target_root)))
        if os.path.isabs(abs_or_rel_path):
            norm_path = os.path.normcase(os.path.realpath(os.path.abspath(abs_or_rel_path)))
        else:
            norm_path = os.path.normcase(os.path.realpath(os.path.abspath(os.path.join(target_root, abs_or_rel_path))))

        # 跨盘符（Windows 下 os.path.relpath 会抛 ValueError）——显式判定为"不在工作区内"
        if os.path.splitdrive(norm_path)[0] != os.path.splitdrive(norm_root)[0]:
            return ""

        try:
            rel = os.path.relpath(norm_path, norm_root)
            if rel == "." or rel.startswith(".."):
                return ""
            return self.normalize_rel_path(rel)
        except Exception:
            return ""

    def _check_and_reload(self):
        """磁盘文件变动热感知：若磁盘状态与内存缓存不一致，自动热重载。

        【D6 修复】旧实现只判断 `mtime > self._last_mtime`，存在两个静默失效窗口：
        1. **灾备文件被删除后又被重建**（例如用一份较旧的备份覆盖、或清理脚本重建），
           新文件 mtime 可能**小于**内存里记录的旧 mtime。此时条件不成立，
           新写入的等级标记会被永久忽略，且 `_last_mtime` 再也不会更新
           （文件不存在时该函数直接 return，连基线都不刷新）。
        2. 同秒内快速改写（部分文件系统 mtime 精度为 1 秒）导致 mtime 相等。

        现改为用 (mtime, size, inode) 三元组做一致性比对：任一变化即重载；
        文件不存在时重置基线，使"删除再重建"能正确触发重载。
        """
        try:
            if not os.path.exists(self.backup_file):
                # 文件消失：重置基线并清空缓存，避免继续沿用已不存在的磁盘状态
                if self._last_mtime != 0.0 or self._levels_cache:
                    self._last_mtime = 0.0
                    self._last_stat_sig = None
                    self._levels_cache = {}
                return

            st = os.stat(self.backup_file)
            sig = (st.st_mtime, st.st_size, getattr(st, "st_ino", 0))
            if sig != getattr(self, "_last_stat_sig", None):
                self.load_backup()
        except Exception:
            pass

    def load_backup(self) -> Dict[str, int]:
        """从 data/asset_security_levels.json 加载非 1 级资产标记名单。

        【灾备防覆写】解析失败时**必须**把缓存与"已就绪"状态一起保持为
        "不可用"，否则下一次 save_backup 会用空缓存去原子覆写灾备文件，
        把全部 2/3 级标记永久抹掉（这份文件没有版本控制兜底，
        历史上已经真实丢过一次）。
        """
        was_ready = getattr(self, "_levels_ready", False)

        if os.path.exists(self.backup_file):
            try:
                with open(self.backup_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                raw_levels = data.get("levels", {})
                self._levels_cache = {
                    self.normalize_rel_path(k): int(v)
                    for k, v in raw_levels.items()
                    if int(v) in (self.LEVEL_SENSITIVE, self.LEVEL_CRITICAL) and self.normalize_rel_path(k)
                }
                # 【关键顺序】只有**解析成功**之后才登记"磁盘签名"，
                # 否则签名与磁盘一致会让热重载判定"无需重载"，坏文件被永久沿用。
                try:
                    st = os.stat(self.backup_file)
                    self._last_mtime = st.st_mtime
                    self._last_stat_sig = (st.st_mtime, st.st_size, getattr(st, "st_ino", 0))
                except OSError:
                    self._last_stat_sig = None
                self._levels_ready = True
                return self._levels_cache
            except Exception as e:
                print(f"[-] 读取资产安全等级备份失败: {e}；"
                      f"为避免覆盖现有等级，本次不载入空缓存（写入将被拒绝）", flush=True)
                # 解析失败：不写签名（以便磁盘文件被修好后能自动重载），
                # 并且**不把 _levels_ready 置真**，从而禁止用空缓存覆写文件。
                self._last_stat_sig = None
                self._levels_ready = False
                if not was_ready:
                    self._levels_cache = {}
                return self._levels_cache

        # 文件不存在：这是正常状态（尚无任何 2/3 级标记），允许写入
        self._levels_cache = {}
        self._last_stat_sig = None
        self._last_mtime = 0.0
        self._levels_ready = True
        return self._levels_cache

    def save_backup(self, allow_empty: bool = False) -> bool:
        """原子持久化非 1 级资产标记名单至 data/ 目录。

        【灾备防覆写】若灾备文件存在、但本次载入并未成功（解析失败），
        则**拒绝写入**——否则一次"用空缓存落盘"就会抹掉全部标记。
        清空整个清单必须是显式意图（调用方传 allow_empty=True）。
        """
        if (not allow_empty
                and not getattr(self, "_levels_ready", False)
                and os.path.exists(self.backup_file)):
            print("[-] 灾备清单未成功载入，已拒绝对其写入（避免抹掉现有安全等级）。"
                  "请修复 data/asset_security_levels.json 后重试。", flush=True)
            return False

        try:
            # 【轮转备份】每次落盘前留一份上一版，避免单点故障
            self._rotate_backup()
            payload = {
                "version": "1.0.0",
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "levels": self._levels_cache
            }
            temp_fd, temp_path = tempfile.mkstemp(dir=self.data_dir, prefix="sec_levels_", suffix=".tmp")
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            shutil.move(temp_path, self.backup_file)
            st = os.stat(self.backup_file)
            self._last_mtime = st.st_mtime
            self._last_stat_sig = (st.st_mtime, st.st_size, getattr(st, "st_ino", 0))
            self._levels_ready = True
            return True
        except Exception as e:
            print(f"[-] 原子持久化资产安全等级备份异常: {e}", flush=True)
            return False

    def _rotate_backup(self) -> None:
        """落盘前把当前文件留一份 .bak（保留最近一版），失败不影响主流程。"""
        try:
            if os.path.exists(self.backup_file):
                shutil.copy2(self.backup_file, self.backup_file + ".bak")
        except Exception as e:
            print(f"[-] 灾备清单轮转备份失败（不影响本次写入）: {e}", flush=True)

    def get_explicit_level(self, rel_path: str) -> int:
        """获取资产自身显式设定的安全等级（大小写不敏感匹配，未设则为 1 级）"""
        self._check_and_reload()
        clean_rel = self.normalize_rel_path(rel_path)
        if not clean_rel:
            return self.LEVEL_DEFAULT

        # 精确匹配
        if clean_rel in self._levels_cache:
            return self._levels_cache[clean_rel]

        # Windows 大小写容错匹配
        clean_rel_lower = clean_rel.lower()
        for k, v in self._levels_cache.items():
            if k.lower() == clean_rel_lower:
                return v
        return self.LEVEL_DEFAULT

    def restore_levels(self, levels: Dict[str, int]) -> bool:
        """把一批**显式等级标记**整体还原进缓存并原子落盘（供失败回滚使用）。

        【D4 补完】为什么不能用 `set_asset_level` 逐个还原：
        `set_asset_level(目录, 2/3, is_dir=True)` 按业务规则会**清掉该目录下所有子项的
        显式标记**（改由父目录继承）。而失败回滚要还原的恰恰是"被子项清理规则删掉的
        那些子项标记"，若逐个走 `set_asset_level`，还原父目录时会再清一遍子项，
        自相矛盾。

        本方法只做一件事：把给定的 相对路径→等级 合并进 `_levels_cache` 并落盘，
        不触发任何级联清理。调用方负责保证传入的是**该操作开始时完整快照**。

        :param levels: {相对路径: 2 或 3}，1 级/其它值会被忽略（与"标记"语义一致）
        :return: 落盘是否成功
        """
        restored = 0
        for rel, lvl in (levels or {}).items():
            try:
                level = int(lvl)
            except (TypeError, ValueError):
                continue
            if level not in (self.LEVEL_SENSITIVE, self.LEVEL_CRITICAL):
                continue
            clean = self.normalize_rel_path(str(rel))
            if not clean:
                continue
            self._levels_cache[clean] = level
            restored += 1
        if not restored:
            return True
        return self.save_backup()

    def get_effective_level(self, abs_or_rel_path: str, target_root: str) -> int:
        """
        动态计算资产的最终生效安全等级：
        生效等级 = Max(自身显式等级, 所有祖先父级目录显式等级)
        """
        self._check_and_reload()
        rel_path = self.to_rel_path(abs_or_rel_path, target_root)
        if not rel_path:
            return self.LEVEL_DEFAULT

        max_level = self.get_explicit_level(rel_path)
        parts = rel_path.split('/')

        # 逐级向上回溯检查所有祖先父目录
        for i in range(1, len(parts)):
            parent_rel = '/'.join(parts[:i])
            parent_level = self.get_explicit_level(parent_rel)
            if parent_level > max_level:
                max_level = parent_level
                if max_level == self.LEVEL_CRITICAL:
                    break

        return max_level

    def set_asset_level(self, abs_or_rel_path: str, level: int, target_root: str, is_dir: bool = False) -> Dict[
        str, Any]:
        """
        设置资产显式安全等级：
        - 若 level 为 1：从非 1 级名单中移除；
        - 若设置对象为文件夹且为 2 或 3 级：按业务规则，自动将属于其下属的所有已打标子项全部清理为 1 级（抹除独立标记）。
        """
        self._check_and_reload()
        rel_path = self.to_rel_path(abs_or_rel_path, target_root)
        if not rel_path:
            return {"success": False, "message": "无法计算资产的相对工作区路径", "cleaned_sub_items": []}

        target_level = int(level)
        cleaned_sub_items: List[str] = []

        # 清除大小写可能存在的旧 key
        clean_rel_lower = rel_path.lower()
        keys_to_remove = [k for k in self._levels_cache.keys() if k.lower() == clean_rel_lower]
        for k in keys_to_remove:
            del self._levels_cache[k]

        if target_level in (self.LEVEL_SENSITIVE, self.LEVEL_CRITICAL):
            self._levels_cache[rel_path] = target_level

            # 若为文件夹，自动清理所有已打标子项（恢复为 1 级显式状态）
            if is_dir:
                prefix = clean_rel_lower + "/"
                sub_keys_to_clean = [k for k in self._levels_cache.keys() if k.lower().startswith(prefix)]
                for k in sub_keys_to_clean:
                    del self._levels_cache[k]
                    cleaned_sub_items.append(k)

        self.save_backup()
        return {
            "success": True,
            "rel_path": rel_path,
            "level": target_level,
            "cleaned_sub_items": cleaned_sub_items
        }

    def detect_downgrade(self, src_path: str, dest_dir: str, target_root: str) -> Tuple[bool, int, int, str]:
        """
        跨目录移动降级风险预检：
        判断源资产移入目标目录后，是否因离开原高等级保护伞而发生安全降级。
        返回: (is_downgrade, src_effective_level, target_inherited_level, warning_message)
        """
        self._check_and_reload()
        src_level = self.get_effective_level(src_path, target_root)
        target_dir_level = self.get_effective_level(dest_dir, target_root)

        if src_level > target_dir_level:
            msg = (
                f"⚠️ 安全降级风险告警：当前资产生效等级为【{src_level}级】，"
                f"目标目录仅受【{target_dir_level}级】保护。"
                f"移出后该资产及内部所有文件都会降级为【{target_dir_level}级】！"
            )
            return True, src_level, target_dir_level, msg

        return False, src_level, target_dir_level, ""

    def handle_transfer_security_levels(self, old_src: str, new_dest: str, target_root: str,
                                        is_dir: bool = False, is_downgrade: bool = False) -> Dict[str, Any]:
        """
        【Bug 3 核心修复】物理移动完成后，处理安全等级灾备与继承：
        - 若发生降级移动：执行业务准则“全员一同降级”，彻底抹除旧路径及其子项的显式标记（降为1级）；
        - 若正常移动（同级或升级）：将旧路径重映射为新路径。
        """
        self._check_and_reload()
        old_rel = self.to_rel_path(old_src, target_root)
        new_rel = self.to_rel_path(new_dest, target_root)
        if not old_rel or not new_rel or old_rel == new_rel:
            return {"action": "none"}

        changed = False
        old_rel_lower = old_rel.lower()
        old_prefix = old_rel_lower + "/"
        new_prefix = new_rel + "/"

        if is_downgrade:
            # 彻底抹除显式高等级标记，让其自然继承目标目录的安全级别
            keys_to_clean = [k for k in list(self._levels_cache.keys())
                             if k.lower() == old_rel_lower or (is_dir and k.lower().startswith(old_prefix))]
            for k in keys_to_clean:
                del self._levels_cache[k]
                changed = True
            # 【D5 修复】回传落盘结果，调用方才能判断灾备是否真的写成功
            persisted = self.save_backup() if changed else True
            return {"action": "downgraded", "cleaned_keys": keys_to_clean, "persisted": persisted}
        else:
            # 正常迁移映射
            matched_key = None
            for k in list(self._levels_cache.keys()):
                if k.lower() == old_rel_lower:
                    matched_key = k
                    break

            if matched_key:
                val = self._levels_cache.pop(matched_key)
                self._levels_cache[new_rel] = val
                changed = True

            if is_dir:
                sub_matches = [k for k in list(self._levels_cache.keys()) if k.lower().startswith(old_prefix)]
                for sub_k in sub_matches:
                    tail = sub_k[len(old_prefix):]
                    updated_sub = new_prefix + tail
                    val = self._levels_cache.pop(sub_k)
                    self._levels_cache[updated_sub] = val
                    changed = True

            # 【D5 修复】同上：落盘失败必须让调用方可见
            persisted = self.save_backup() if changed else True
            return {"action": "remapped", "new_rel": new_rel, "persisted": persisted}

    def remap_paths_after_transfer(self, old_src: str, new_dest: str, target_root: str,
                                   is_dir: bool = False) -> Dict[str, Any]:
        """兼容旧接口的物理移动重命名转发。

        【D5 修复】原实现丢弃了 `handle_transfer_security_levels` 的返回值，
        调用方因此无法得知灾备落盘是否成功。内部的 `save_backup()` 在异常时
        只 print 并返回 False，属于"静默失败"：
        重命名后若 JSON 写失败，则旧路径仍保留标记、DB 已是新路径，
        下次冷启动重建派生等级时会把等级灌到一个**已不存在的路径**上，
        被重命名资产静默掉级。现原样回传结果供调用方判定与告警。
        """
        return self.handle_transfer_security_levels(
            old_src, new_dest, target_root, is_dir=is_dir, is_downgrade=False
        )

    def get_all_records(self) -> Dict[str, int]:
        """返回全部已标记的相对路径字典"""
        self._check_and_reload()
        return dict(self._levels_cache)


class SecurityManager:
    """
    安全管控中枢：
    1. 主管理密码 PBKDF2-HMAC-SHA256 加盐存储与鉴权
    2. API Key 对称混淆加密与本地安全落盘
    3. security_policy.json 策略解析与动作风险定级
    4. 5 维物理操作危险预检（磁盘空间、路径穿越、覆盖冲突、软链接、压缩炸弹）
    5. 引用全局唯一的 AssetSecurityManager 实例
    """

    LEVEL_SAFE = "SAFE"
    LEVEL_SENSITIVE = "SENSITIVE"
    LEVEL_DESTRUCTIVE = "DESTRUCTIVE"

    MAX_ZIP_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
    MAX_ZIP_EXPANSION_RATIO = 100.0
    MAX_ZIP_ENTRY_COUNT = 10000
    MIN_DISK_FREE_BYTES = 500 * 1024 * 1024

    def __init__(self, app_config_ref: dict, save_config_callback=None,
                 policy_path: Optional[str] = None, data_dir: Optional[str] = None):
        self.app_config = app_config_ref
        self.save_config_callback = save_config_callback

        if "security" not in self.app_config or not isinstance(self.app_config["security"], dict):
            self.app_config["security"] = {
                "master_password_hash": "",
                "master_password_salt": "",
                "permanent_skip_sensitive": False,
                "permanent_skip_destructive": False
            }

        self.session_skip_sensitive: bool = False
        self.session_skip_destructive: bool = False

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if not policy_path:
            self.policy_path = os.path.join(base_dir, "config", "security_policy.json")
        else:
            self.policy_path = policy_path

        # 【可注入性修复】data_dir 此前**写死**为 <项目根>/data。
        # 后果：隔离测试里夹具把安全等级标记写在**夹具工作区**，
        # 而这里构造出的 AssetSecurityManager 仍去读**项目本体**的
        # data/asset_security_levels.json —— 于是网关用真实工程状态做判定，
        # 夹具标记根本没生效（现象：items_meta 显示源资产 3 级，
        # 但 evaluate_action_with_assets 返回 max_asset_level=1）。
        # 生产调用不传该参数，行为与从前完全一致。
        if data_dir is None:
            data_dir = os.path.join(base_dir, "data")
        # 始终通过单例工厂获取全局共享的资产安全管理器
        self.asset_sec_mgr = AssetSecurityManager.get_instance(data_dir)
        self.security_policy: Dict[str, Any] = self._load_policy()

    def _load_policy(self) -> Dict[str, Any]:
        """动态加载安全策略 JSON，具备缺省自愈构建能力"""
        if os.path.exists(self.policy_path):
            try:
                with open(self.policy_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[-] 读取 security_policy.json 失败，将重构兜底: {e}", flush=True)

        default_policy = {
            "version": "1.2.0",
            "policies": {
                "delete_file": {"base_level": self.LEVEL_DESTRUCTIVE, "desc": "移入回收站（不可撤销，需手动拾回）",
                                "allow_skip": False},
                "move_file": {"base_level": self.LEVEL_SENSITIVE, "desc": "剪切移动资产", "allow_skip": True},
                "copy_file": {"base_level": self.LEVEL_SAFE, "desc": "复制文件副本", "allow_skip": True},
                "rename_file": {"base_level": self.LEVEL_SENSITIVE, "desc": "重命名资产", "allow_skip": True},
                "create_directory": {"base_level": self.LEVEL_SAFE, "desc": "新建目录", "allow_skip": True},
                "write_file": {"base_level": self.LEVEL_SENSITIVE, "desc": "新建或写入文本文件", "allow_skip": True},
                "compress_files": {"base_level": self.LEVEL_SAFE, "desc": "制作 ZIP 压缩包", "allow_skip": True},
                "extract_archive": {"base_level": self.LEVEL_SENSITIVE, "desc": "解压 ZIP 压缩包", "allow_skip": True},
                "read_file_content": {"base_level": self.LEVEL_SAFE, "desc": "读取文本文件或罗列目录",
                                      "allow_skip": True},
                "locate_or_open_file": {"base_level": self.LEVEL_SAFE, "desc": "定位或打开文件", "allow_skip": True}
            },
            "aliases": {
                "delete_files": "delete_file", "remove_file": "delete_file", "recycle_file": "delete_file",
                "move_files": "move_file", "cut_file": "move_file", "cut": "move_file",
                "copy_files": "copy_file", "copy": "copy_file", "rename": "rename_file",
                "mkdir": "create_directory", "create_folder": "create_directory",
                "write_file_content": "write_file", "create_file": "write_file",
                "zip": "compress_files", "unzip": "extract_archive"
            },
            "tool_exemptions": {
                "create_directory": True,
                "compress_files": True,
                "copy_file": True,
                "read_file_content": True,
                "locate_or_open_file": True
            }
        }

        try:
            os.makedirs(os.path.dirname(self.policy_path), exist_ok=True)
            with open(self.policy_path, "w", encoding="utf-8") as f:
                json.dump(default_policy, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        return default_policy

    def save_policy(self) -> bool:
        try:
            with open(self.policy_path, "w", encoding="utf-8") as f:
                json.dump(self.security_policy, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"[-] 保存 security_policy.json 失败: {e}", flush=True)
            return False

    def has_password_set(self) -> bool:
        sec = self.app_config.get("security", {})
        return bool(sec.get("master_password_hash") and sec.get("master_password_salt"))

    def set_master_password(self, plain_password: str) -> bool:
        if not plain_password:
            return False
        salt = secrets.token_hex(16)
        pwd_hash = self._hash_password(plain_password, salt)
        sec = self.app_config.setdefault("security", {})
        sec["master_password_salt"] = salt
        sec["master_password_hash"] = pwd_hash
        if self.save_config_callback:
            self.save_config_callback()
        return True

    def verify_password(self, plain_password: str) -> bool:
        if not self.has_password_set():
            return False
        sec = self.app_config.get("security", {})
        stored_salt = sec.get("master_password_salt", "")
        stored_hash = sec.get("master_password_hash", "")
        input_hash = self._hash_password(plain_password, stored_salt)
        return secrets.compare_digest(input_hash, stored_hash)

    @staticmethod
    def _hash_password(plain_password: str, salt: str) -> str:
        key = hashlib.pbkdf2_hmac(
            'sha256',
            plain_password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        )
        return key.hex()

    @staticmethod
    def _get_machine_seed() -> bytes:
        seed_str = f"{os.path.expanduser('~')}_{os.name}_{hashlib.md5(os.path.expanduser('~').encode()).hexdigest()}"
        return hashlib.sha256(seed_str.encode('utf-8')).digest()

    @classmethod
    def encrypt_api_key(cls, plain_key: str) -> str:
        if not plain_key:
            return ""
        if plain_key.startswith("enc::"):
            return plain_key
        seed = cls._get_machine_seed()
        data = plain_key.encode('utf-8')
        encrypted = bytes([b ^ seed[i % len(seed)] for i, b in enumerate(data)])
        return "enc::" + base64.b64encode(encrypted).decode('ascii')

    @classmethod
    def decrypt_api_key(cls, encrypted_key: str) -> str:
        if not encrypted_key:
            return ""
        if not encrypted_key.startswith("enc::"):
            return encrypted_key
        try:
            raw_b64 = encrypted_key[5:]
            encrypted = base64.b64decode(raw_b64.encode('ascii'))
            seed = cls._get_machine_seed()
            decrypted = bytes([b ^ seed[i % len(seed)] for i, b in enumerate(encrypted)])
            return decrypted.decode('utf-8', errors='ignore')
        except Exception:
            return ""

    def evaluate_action_with_assets(
            self,
            action_name: str,
            params: dict,
            target_root: str,
            involved_paths: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        深度评估动作风险级别：
        将基础动作策略与受控资产的生效等级 (1/2/3级) 深度融合：
        - 涉及 3 级机密资产：强制升级为 DESTRUCTIVE，强制要求密码，绝不免密；
        - 涉及 2 级敏感资产：强制升级为 SENSITIVE，强制弹窗，绝不跳过；
        - 仅 1 级普通资产：遵循 security_policy.json 基础规则与豁免。
        """
        raw_act = (action_name or "").strip().lower()
        aliases = self.security_policy.get("aliases", {})
        canonical_name = aliases.get(raw_act, raw_act)
        policies = self.security_policy.get("policies", {})
        rule = policies.get(canonical_name, {})

        base_level = rule.get("base_level", self.LEVEL_SAFE)
        base_desc = rule.get("desc", "常规资产操作")

        max_asset_level = AssetSecurityManager.LEVEL_DEFAULT
        paths_to_check = involved_paths or []
        for p in paths_to_check:
            if not p:
                continue
            eff = self.asset_sec_mgr.get_effective_level(str(p), target_root)
            if eff > max_asset_level:
                max_asset_level = eff

        final_level = base_level
        force_password = False
        is_asset_guarded = (max_asset_level > AssetSecurityManager.LEVEL_DEFAULT)

        if max_asset_level == AssetSecurityManager.LEVEL_CRITICAL:
            final_level = self.LEVEL_DESTRUCTIVE
            force_password = True
            reason = f"🔒【3 级机密资产保护】操作涉及 3 级高危机密资产，系统强制要求校验主管理密码！"
        elif max_asset_level == AssetSecurityManager.LEVEL_SENSITIVE:
            if final_level != self.LEVEL_DESTRUCTIVE:
                final_level = self.LEVEL_SENSITIVE
            reason = f"⚠️【2 级敏感资产操作】操作涉及 2 级敏感资产，系统强制要求人工核实确认！"
        else:
            reason = base_desc

        return {
            "canonical_action": canonical_name,
            "final_level": final_level,
            "max_asset_level": max_asset_level,
            "is_asset_guarded": is_asset_guarded,
            "force_password": force_password,
            "reason": reason
        }

    def classify_action(self, action_name: str, params: dict) -> Tuple[str, str]:
        raw_act = (action_name or "").strip().lower()
        aliases = self.security_policy.get("aliases", {})
        canonical_name = aliases.get(raw_act, raw_act)
        policies = self.security_policy.get("policies", {})
        rule = policies.get(canonical_name)

        if not rule:
            return self.LEVEL_SAFE, "只读或常规检索类操作"

        current_level = rule.get("base_level", self.LEVEL_SAFE)
        current_desc = rule.get("desc", "常规文件操作")
        return current_level, current_desc

    def is_action_exempt(self, level: str, action_name: Optional[str] = None, is_asset_guarded: bool = False) -> bool:
        """
        豁免判定：
        若命中 2 级或 3 级受控资产，硬性禁止任何免提醒/豁免，必须人工交互拦截！

        【安全修复】`is_asset_guarded` 此前只在**签名**里、函数体内从未真正使用，
        而调用方（网关）又恒定传 `is_asset_guarded=False` —— 于是这道防线形同虚设：
        策略文件里被标了"工具免检"的动作（如 `rename_file`），
        即便操作的是 **2 级/3 级受控资产**，也会被直接放行、不弹窗、不要密码。
        与用户口径（"涉及敏感动作或安全等级必须告警；2 级弹窗、3 级密码"）直接冲突。

        现改为：受控资产一律不免检 —— 先挡在 tool_exemptions / session_skip 之前。
        """
        if is_asset_guarded:
            return False

        sec = self.app_config.get("security", {})
        if level == self.LEVEL_DESTRUCTIVE:
            return self.session_skip_destructive or sec.get("permanent_skip_destructive", False)

        if action_name:
            raw_act = action_name.strip().lower()
            canonical_name = self.security_policy.get("aliases", {}).get(raw_act, raw_act)
            exemptions = self.security_policy.get("tool_exemptions", {})
            if exemptions.get(canonical_name) is True:
                return True

        if level == self.LEVEL_SENSITIVE:
            return self.session_skip_sensitive or sec.get("permanent_skip_sensitive", False)

        return True

    def set_tool_exemption(self, action_name: str, exempt: bool) -> bool:
        raw_act = action_name.strip().lower()
        canonical_name = self.security_policy.get("aliases", {}).get(raw_act, raw_act)
        self.security_policy.setdefault("tool_exemptions", {})[canonical_name] = bool(exempt)
        return self.save_policy()

    def set_session_skip(self, level: str, skip: bool):
        if level == self.LEVEL_SENSITIVE:
            self.session_skip_sensitive = skip
        elif level == self.LEVEL_DESTRUCTIVE:
            self.session_skip_destructive = skip

    @classmethod
    def precheck_disk_space(cls, target_dir: str, estimated_needed_bytes: int = 0) -> Tuple[bool, str]:
        try:
            check_path = target_dir if os.path.exists(target_dir) else os.path.dirname(os.path.abspath(target_dir))
            while not os.path.exists(check_path) and check_path and os.path.dirname(check_path) != check_path:
                check_path = os.path.dirname(check_path)

            usage = shutil.disk_usage(check_path)
            if usage.free < cls.MIN_DISK_FREE_BYTES:
                return False, f"磁盘安全预警：所在驱动器可用空间不足 ({usage.free // (1024 * 1024)}MB < 500MB)，已阻断写操作。"

            if estimated_needed_bytes > 0:
                safety_margin = int(estimated_needed_bytes * 1.15)
                if usage.free < safety_margin:
                    return False, (
                        f"磁盘空间不足预警：预计需要 {estimated_needed_bytes // (1024 * 1024)}MB，"
                        f"但当前可用空间仅剩 {usage.free // (1024 * 1024)}MB。"
                    )
            return True, ""
        except Exception as e:
            return False, f"磁盘剩余容量探测失败: {str(e)}"

    @classmethod
    def precheck_zip_bomb(cls, zip_path: str) -> Tuple[bool, str, int, int]:
        if not os.path.exists(zip_path):
            return False, "待解压的 ZIP 文件在磁盘上不存在", 0, 0

        try:
            zip_size = os.path.getsize(zip_path)
            total_uncompressed = 0
            entry_count = 0

            with zipfile.ZipFile(zip_path, 'r') as zf:
                infolist = zf.infolist()
                entry_count = len(infolist)

                if entry_count > cls.MAX_ZIP_ENTRY_COUNT:
                    return False, f"压缩炸弹告警：压缩包内文件数量达 {entry_count} 个，超出安全上限 ({cls.MAX_ZIP_ENTRY_COUNT})", 0, entry_count

                for info in infolist:
                    norm_entry = os.path.normpath(info.filename)
                    if norm_entry.startswith("..") or os.path.isabs(info.filename):
                        return False, f"Zip Slip 恶意路径穿越告警：条目 `{info.filename}` 尝试脱离解压根目录", 0, entry_count

                    if (info.external_attr >> 16) & 0o170000 == 0o120000:
                        return False, f"符号链接攻击拦截：条目 `{info.filename}` 属于符号链接，禁止解压", 0, entry_count

                    total_uncompressed += info.file_size
                    if total_uncompressed > cls.MAX_ZIP_UNCOMPRESSED_BYTES:
                        return False, f"压缩炸弹告警：解压后预计体积超过 {cls.MAX_ZIP_UNCOMPRESSED_BYTES // (1024 * 1024 * 1024)}GB 安全上限", total_uncompressed, entry_count

            ratio = (total_uncompressed / (zip_size + 1))
            if ratio > cls.MAX_ZIP_EXPANSION_RATIO and total_uncompressed > 50 * 1024 * 1024:
                return False, f"压缩炸弹告警：压缩包膨胀比率异常 ({ratio:.1f}:1 > {cls.MAX_ZIP_EXPANSION_RATIO}:1)", total_uncompressed, entry_count

            return True, "", total_uncompressed, entry_count
        except zipfile.BadZipFile:
            return False, "无效或损坏的 ZIP 压缩文件格式", 0, 0
        except Exception as e:
            return False, f"解析压缩包安全性失败: {str(e)}", 0, 0

    @classmethod
    def check_symlink_safety(cls, file_path: str) -> Tuple[bool, str]:
        try:
            if os.path.islink(file_path):
                real_dest = os.path.realpath(file_path)
                return False, f"软链接风险：`{file_path}` 是符号链接（指向 `{real_dest}`），系统拒绝直接对其物理操作"
            return True, ""
        except Exception as e:
            return False, f"检测符号链接失败: {str(e)}"