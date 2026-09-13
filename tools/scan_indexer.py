"""
Agent/tools/scan_indexer.py
通用文件树聚类压缩器与保真检索引擎
- 自动同步 UI 选中的 API 平台 (Gemini/DeepSeek 等)
- 当 Token 超出 config.json 阈值时自动触发二次深度压缩
- 零硬过滤：底层内存/检索索引 100% 完整保留，仅在 LLM 视图层实施动态模式熔断与兄弟目录聚合
"""

import json
import os
import re
import sys
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
from datetime import datetime

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))      # Agent/tools
AGENT_ROOT = os.path.dirname(TOOLS_DIR)                     # Agent
CORE_DIR = os.path.join(AGENT_ROOT, "core")                 # Agent/core
CONFIG_DIR = os.path.join(AGENT_ROOT, "config")             # Agent/config

API_CONFIG_FILE = os.path.join(CONFIG_DIR, "API_config.json")
APP_CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

if CORE_DIR not in sys.path:
    sys.path.insert(0, CORE_DIR)

try:
    from tokenizer import count_text_tokens, format_token_count
except ImportError:
    def count_text_tokens(text: Optional[str], platform: str = "DeepSeek") -> int:
        if not text:
            return 0
        return max(1, len(text) // 3)
    def format_token_count(count: int) -> str:
        return f"{count / 1000:.1f}k" if count >= 1000 else str(count)

DEFAULT_DATA_SCAN_DIR = os.path.join(AGENT_ROOT, "data", "scan")
DEFAULT_RAW_SCAN_FILE = os.path.join(DEFAULT_DATA_SCAN_DIR, "scan_result.json")
DEFAULT_COMPRESSED_FILE = os.path.join(DEFAULT_DATA_SCAN_DIR, "compressed_scan_result.md")
DEFAULT_TOKEN_THRESHOLD = 10000


def get_runtime_environment() -> Tuple[int, str]:
    """从系统中自动读取阈值以及 UI 当前激活的平台 (Gemini/DeepSeek)"""
    threshold = DEFAULT_TOKEN_THRESHOLD
    platform = "DeepSeek"

    # 1. 读取阈值
    if os.path.exists(APP_CONFIG_FILE):
        try:
            with open(APP_CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                threshold = int(cfg.get("tool_token_warning_threshold", DEFAULT_TOKEN_THRESHOLD))
        except Exception:
            pass

    # 2. 实时读取 UI 窗口当前激活的 API 平台
    if os.path.exists(API_CONFIG_FILE):
        try:
            with open(API_CONFIG_FILE, "r", encoding="utf-8") as f:
                api_data = json.load(f)
                curr_profile = api_data.get("current_profile", "")
                profiles = api_data.get("profiles", {})
                if curr_profile in profiles:
                    platform = profiles[curr_profile].get("platform", "DeepSeek")
        except Exception:
            pass

    return threshold, platform


class ScanIndexer:
    def __init__(self, raw_scan_json: Dict[str, Any], min_cluster_threshold: int = 3, max_distinct_limit: int = 10):
        self.raw_data = raw_scan_json
        self.min_cluster_threshold = min_cluster_threshold
        self.max_distinct_limit = max_distinct_limit

        self.root_path = self.raw_data.get("scan_meta", {}).get("root_path", "")
        self.system_now = datetime.now()

        # 底层全量索引：保证零丢失
        self.file_registry: List[Dict[str, Any]] = []
        self.dir_registry: List[Dict[str, Any]] = []

        self._build_registry(self.raw_data.get("structure", {}))

    def _build_registry(self, node: Dict[str, Any]):
        if not node:
            return

        self.dir_registry.append({
            "name": node.get("name"),
            "path": node.get("path"),
            "mtime": node.get("mtime"),
            "status": node.get("status"),
            "file_count": node.get("file_stats", {}).get("total", 0),
            "dir_count": node.get("dir_stats", {}).get("total", 0),
            "truncated": node.get("file_stats", {}).get("truncated", False)
        })

        dir_path = node.get("path", "")
        for f in node.get("files", []):
            full_path = os.path.join(dir_path, f.get("name", ""))
            self.file_registry.append({
                "name": f.get("name"),
                "path": full_path,
                "dir_path": dir_path,
                "size_bytes": f.get("size_bytes", 0),
                "mtime": f.get("mtime"),
                "status": f.get("status")
            })

        for sub in node.get("subdirectories", []):
            self._build_registry(sub)

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f}{unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f}TB"

    def _format_mtime(self, mtime_str: str) -> str:
        if not mtime_str:
            return ""
        try:
            target_dt = datetime.strptime(mtime_str, "%Y-%m-%d %H:%M:%S")
            if target_dt.date() == self.system_now.date():
                return target_dt.strftime("%H:%M")
            elif target_dt.year == self.system_now.year:
                return target_dt.strftime("%m-%d")
            else:
                return target_dt.strftime("%Y-%m-%d")
        except ValueError:
            return mtime_str[:16]

    def _get_relative_path(self, absolute_path: str) -> str:
        if not absolute_path or not self.root_path:
            return absolute_path
        try:
            rel = os.path.relpath(absolute_path, self.root_path)
            return "." if rel == "." else f"./{rel.replace(os.sep, '/')}"
        except ValueError:
            return absolute_path

    @staticmethod
    def _induce_pattern(filename: str) -> Tuple[str, str]:
        name_without_ext, ext = os.path.splitext(filename)
        ext = ext.lower()
        pattern_base = re.sub(r'\d+', '{N}', name_without_ext)
        pattern_base = re.sub(r'(\{N\}[_\-\s.]*)+', '{N}_', pattern_base).rstrip('_')
        return f"{pattern_base}{ext}", ext

    def _cluster_file_list(self, files: List[Dict[str, Any]], deep_mode: bool = False) -> Dict[str, Any]:
        """文件级聚类：包含 deep_mode 下的模式上限熔断与防膨胀机制"""
        if not files:
            return {"clustered_patterns": [], "distinct_files": [], "fallback_summaries": []}

        pattern_groups = defaultdict(list)
        for f in files:
            pattern, ext = self._induce_pattern(f["name"])
            pattern_groups[(pattern, ext)].append(f)

        clustered_results = []
        isolated_files = []

        # 核心优化 1：深度模式提高聚类门槛（至少 5 个相同模式才提取，避免碎规则刷屏）
        threshold = 5 if deep_mode else self.min_cluster_threshold

        for (pattern, ext), group_files in pattern_groups.items():
            count = len(group_files)
            if count >= threshold:
                total_size = sum(x.get("size_bytes", 0) for x in group_files)
                times = sorted([f.get("mtime", "") for f in group_files if f.get("mtime")])
                mtime_range = [self._format_mtime(times[0]), self._format_mtime(times[-1])] if times else []
                if mtime_range and mtime_range[0] == mtime_range[-1]:
                    mtime_range = [mtime_range[0]]

                clustered_results.append({
                    "pattern": pattern,
                    "count": count,
                    "total_size": self._format_size(total_size),
                    "mtime_range": mtime_range,
                    "sample_files": [group_files[0]["name"]] if deep_mode else (
                        [group_files[0]["name"], group_files[-1]["name"]] if count > 1 else [group_files[0]["name"]]
                    )
                })
            else:
                isolated_files.extend(group_files)

        # 核心优化 2：模式熔断机制（Entropy Capping）
        # 深度模式下单目录提取的正则 pattern 超过 3 个，视为高熵碎文件，丢弃细分模式直接按后缀汇总
        if deep_mode and len(clustered_results) > 3:
            for p in clustered_results:
                for f in files:
                    if self._induce_pattern(f["name"])[0] == p["pattern"]:
                        isolated_files.append(f)
            clustered_results = []

        distinct_files = []
        fallback_summaries = []
        distinct_limit = 0 if deep_mode else self.max_distinct_limit

        if len(isolated_files) > distinct_limit:
            ext_groups = defaultdict(list)
            for f in isolated_files:
                _, ext = os.path.splitext(f["name"])
                ext_groups[ext.lower()].append(f)

            for ext, e_files in ext_groups.items():
                if len(e_files) <= 1 and not deep_mode:
                    distinct_files.extend(e_files)
                else:
                    total_size = sum(x.get("size_bytes", 0) for x in e_files)
                    times = sorted([f.get("mtime", "") for f in e_files if f.get("mtime")])
                    fallback_summaries.append({
                        "extension_group": ext if ext else "other",
                        "count": len(e_files),
                        "total_size": self._format_size(total_size),
                        "mtime_range": [self._format_mtime(times[0]), self._format_mtime(times[-1])] if times else [],
                        "sample": e_files[0]["name"]
                    })
        else:
            distinct_files = isolated_files

        formatted_distinct = []
        for f in distinct_files:
            formatted_distinct.append({
                "name": f["name"],
                "size": self._format_size(f.get("size_bytes", 0)),
                "mtime": self._format_mtime(f.get("mtime", ""))
            })

        return {
            "clustered_patterns": clustered_results,
            "distinct_files": formatted_distinct,
            "fallback_summaries": fallback_summaries
        }

    def _count_node_totals(self, node: Dict[str, Any]) -> Tuple[int, int]:
        """递归统计一个目录树节点的总文件数与总字节大小"""
        files = node.get("files", [])
        total_files = len(files)
        total_bytes = sum(f.get("size_bytes", 0) for f in files)
        for sub in node.get("subdirectories", []):
            sub_files, sub_bytes = self._count_node_totals(sub)
            total_files += sub_files
            total_bytes += sub_bytes
        return total_files, total_bytes

    def _cluster_subdirectories(self, subdirs: List[Dict[str, Any]], deep_mode: bool = False) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        核心优化 3：兄弟子目录聚合
        将结构雷同/命名相似的实验版本目录折叠为 1 行（如 data_standardized_big_1, data_standardized_big_2）
        """
        if not deep_mode or len(subdirs) <= 3:
            return subdirs, []

        groups = defaultdict(list)
        for s in subdirs:
            name = s.get("name", "")
            # 模式诱导：提取数字通配骨架
            base_pattern = re.sub(r'\d+', '{N}', name)
            base_pattern = re.sub(r'(\{N\}[_\-\s.]*)+', '{N}_', base_pattern).rstrip('_')
            groups[base_pattern].append(s)

        preserved_subdirs = []
        collapsed_summaries = []

        for pattern, dir_list in groups.items():
            # 当同类型变体文件夹超过等于 3 个时触发折叠
            if len(dir_list) >= 3:
                agg_files = 0
                agg_bytes = 0
                for d in dir_list:
                    f_cnt, b_cnt = self._count_node_totals(d)
                    agg_files += f_cnt
                    agg_bytes += b_cnt

                collapsed_summaries.append(
                    f"📁 [{len(dir_list)} sibling dirs: {pattern}] (~{agg_files} files, {self._format_size(agg_bytes)}, Collapsed)"
                )
            else:
                preserved_subdirs.extend(dir_list)

        return preserved_subdirs, collapsed_summaries

    # ==================== 1. 标准模式 (保真展示，富文本渲染) ====================
    def generate_compressed_markdown(self) -> str:
        scan_time = self.raw_data.get("scan_meta", {}).get("scan_time", "N/A")
        lines = [
            f"# Scan Tree: `{self.root_path}` (Scanned: {scan_time})",
            "> Time rule: Today=HH:MM, Current Year=MM-DD, Older=YYYY-MM-DD\n"
        ]

        def _render_node(node: Dict[str, Any], depth: int = 0):
            indent = "  " * depth
            rel_path = self._get_relative_path(node.get("path", ""))

            tags = []
            if node.get("status") and node.get("status") != "normal":
                tags.append(f"status:{node['status']}")
            if node.get("file_stats", {}).get("truncated", False):
                tags.append("TRUNCATED")
            tag_str = f" `[{', '.join(tags)}]`" if tags else ""

            lines.append(f"{indent}- 📁 **{rel_path}/**{tag_str}")

            clustering = self._cluster_file_list(node.get("files", []), deep_mode=False)
            item_indent = "  " * (depth + 1)

            for p in clustering["clustered_patterns"]:
                trange = "..".join(p["mtime_range"])
                samples = "..".join(p["sample_files"])
                lines.append(
                    f"{item_indent}- 🧩 `{p['pattern']}` (×{p['count']}, {p['total_size']}, {trange}) e.g. `{samples}`"
                )

            for fb in clustering["fallback_summaries"]:
                trange = "..".join(fb["mtime_range"])
                lines.append(
                    f"{item_indent}- 📦 `*{fb['extension_group']}` (×{fb['count']}, {fb['total_size']}, {trange}) e.g. `{fb['sample']}`"
                )

            for d in clustering["distinct_files"]:
                lines.append(
                    f"{item_indent}- 📄 `{d['name']}` ({d['size']}, {d['mtime']})"
                )

            for sub in node.get("subdirectories", []):
                _render_node(sub, depth + 1)

        _render_node(self.raw_data.get("structure", {}))
        return "\n".join(lines)

    # ==================== 2. 二次深度压缩 (专为控制 Token 设计) ====================
    def _squash_node(self, node: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """单链无文件子目录合并 (如 tools/.idea/inspectionProfiles)"""
        curr_name = node.get("name") or ""
        curr_node = node
        accumulated_path = [curr_name]

        while (len(curr_node.get("files", [])) == 0 and
               len(curr_node.get("subdirectories", [])) == 1 and
               curr_node.get("status") == "normal"):
            curr_node = curr_node["subdirectories"][0]
            accumulated_path.append(curr_node.get("name", ""))

        return "/".join(accumulated_path).strip("/"), curr_node

    def generate_deep_compressed_markdown(self) -> str:
        lines = [
            f"# Scan Tree (Deep Compressed): {self.root_path}\n"
        ]

        def _render_deep(node: Dict[str, Any], depth: int = 0):
            indent = "  " * depth
            display_path, target_node = self._squash_node(node)
            if depth == 0:
                display_path = "./"

            tags = []
            if target_node.get("file_stats", {}).get("truncated", False):
                tags.append("TRUNC")
            if target_node.get("status") and target_node.get("status") != "normal":
                tags.append(target_node['status'].replace("depth_limit_reached", "MAX_DEPTH"))
            tag_str = f" [{','.join(tags)}]" if tags else ""

            # 无 Emoji 高紧凑输出
            lines.append(f"{indent}/ {display_path}/{tag_str}")

            clustering = self._cluster_file_list(target_node.get("files", []), deep_mode=True)
            item_indent = "  " * (depth + 1)

            # 核心优化 4：去除了毫无语义价值的长样本抽样 [sample]，大幅降低 Token
            for p in clustering["clustered_patterns"]:
                lines.append(f"{item_indent}+ {p['pattern']} (x{p['count']},{p['total_size']})")

            for fb in clustering["fallback_summaries"]:
                lines.append(f"{item_indent}* *{fb['extension_group']} (x{fb['count']},{fb['total_size']})")

            for d in clustering["distinct_files"]:
                lines.append(f"{item_indent}- {d['name']} ({d['size']})")

            # 目录级兄弟聚合处理
            subdirs = target_node.get("subdirectories", [])
            preserved_subs, collapsed_summaries = self._cluster_subdirectories(subdirs, deep_mode=True)

            for c_summary in collapsed_summaries:
                lines.append(f"{item_indent}* {c_summary}")

            for sub in preserved_subs:
                _render_deep(sub, depth + 1)

        _render_deep(self.raw_data.get("structure", {}))
        return "\n".join(lines)

    # ==================== 3. 动态判定与检索引擎入口 ====================
    def generate_compressed_context(self) -> Tuple[str, bool, int, str, int]:
        threshold, platform = get_runtime_environment()

        # 测算标准模式
        primary_md = self.generate_compressed_markdown()
        token_count = count_text_tokens(primary_md, platform=platform)

        if token_count <= threshold:
            return primary_md, False, token_count, platform, threshold

        # 超阈值自动平滑降维为深度压缩
        deep_md = self.generate_deep_compressed_markdown()
        deep_tokens = count_text_tokens(deep_md, platform=platform)
        return deep_md, True, deep_tokens, platform, threshold

    def search_files(self, keyword: Optional[str] = None, ext: Optional[str] = None, dir_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """供 Agent 调用的高保真全文检索引擎"""
        results = []
        for file_info in self.file_registry:
            if ext and not file_info["name"].lower().endswith(ext.lower()):
                continue
            if dir_path and not file_info["dir_path"].startswith(dir_path):
                continue
            if keyword and keyword.lower() not in file_info["name"].lower():
                continue
            results.append(file_info)
        return results

    def resolve_pattern_files(self, dir_path: str, pattern: str) -> List[str]:
        """将压缩地图中的正则模式实时反解回真实磁盘文件列表"""
        matched = []
        for file_info in self.file_registry:
            if file_info["dir_path"] == dir_path:
                inferred_pat, _ = self._induce_pattern(file_info["name"])
                if inferred_pat == pattern:
                    matched.append(file_info["path"])
        return matched


def compress_scan_file(input_file: Optional[str] = None, output_file: Optional[str] = None) -> Optional[str]:
    target_in = input_file or DEFAULT_RAW_SCAN_FILE
    target_out = output_file or DEFAULT_COMPRESSED_FILE

    if not os.path.exists(target_in):
        print(f"[-] 找不到输入文件: {os.path.abspath(target_in)}")
        return None

    os.makedirs(os.path.dirname(os.path.abspath(target_out)), exist_ok=True)

    with open(target_in, "r", encoding="utf-8") as f:
        raw_json = json.load(f)

    indexer = ScanIndexer(raw_json)
    markdown_content, is_deep, final_tokens, platform, threshold = indexer.generate_compressed_context()

    with open(target_out, "w", encoding="utf-8") as f:
        f.write(markdown_content)

    raw_size = os.path.getsize(target_in)
    comp_size = os.path.getsize(target_out)
    ratio = (1 - (comp_size / raw_size)) * 100 if raw_size > 0 else 0

    mode_tag = "⚡ [二次深度压缩模式]" if is_deep else "📄 [标准压缩模式]"
    print(f"[+] {mode_tag} 地图已生成 -> {os.path.abspath(target_out)}")
    print(f"[*] 分词平台: {platform} | 真实 Token: {format_token_count(final_tokens)} / 阈值: {format_token_count(threshold)}")
    print(f"[*] 原始 JSON: {raw_size / 1024:.1f} KB | 输出文件: {comp_size / 1024:.1f} KB (体积减重 {ratio:.1f}%)")

    return target_out