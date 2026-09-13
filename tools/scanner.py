# Agent/tools/scanner.py

import os
import sys
import json
import threading
from datetime import datetime
from typing import Set, Optional, Dict, Any, List, Tuple
from collections import defaultdict

DEFAULT_MAX_SAMPLE_COUNT = 100
MAX_DIRECTORY_ENTRIES_BUDGET = 3000
WIN_LONG_PATH_PREFIX = "\\\\?\\"

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_ROOT = os.path.dirname(TOOLS_DIR)
DEFAULT_DATA_SCAN_DIR = os.path.join(AGENT_ROOT, "data", "scan")
DEFAULT_SCAN_OUTPUT_FILE = os.path.join(DEFAULT_DATA_SCAN_DIR, "scan_result.json")
CONFIG_FILE = os.path.join(AGENT_ROOT, "config", "config.json")

DEFAULT_SYSTEM_IGNORED = {
    "node_modules", ".git", ".svn", ".hg", "__pycache__", ".idea", ".vscode",
    "$RECYCLE.BIN", "System Volume Information"
}


def load_full_config() -> Dict[str, Any]:
    """完整读取整个 config.json"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[-] 读取 config.json 失败: {e}")
    return {}


def extract_scanner_options(cfg: Dict[str, Any]) -> Dict[str, Any]:
    scan_scope = {}
    if isinstance(cfg.get("scanner"), dict):
        scan_scope.update(cfg["scanner"])
    elif isinstance(cfg.get("scan_config"), dict):
        scan_scope.update(cfg["scan_config"])

    merged = {**cfg, **scan_scope}

    target_path = merged.get("target_path", os.path.expanduser("~"))
    try:
        max_depth = int(merged.get("max_depth", 3))
    except (ValueError, TypeError):
        max_depth = 3

    max_samples = int(merged.get("max_sample_count", DEFAULT_MAX_SAMPLE_COUNT))

    bl_paths = merged.get("blacklist_paths", [])
    bl_names = merged.get("blacklist_names", [])
    bl_exts = merged.get("blacklist_extensions", [])

    if isinstance(merged.get("blacklist"), dict):
        bl_paths = list(set(bl_paths + merged["blacklist"].get("paths", [])))
        bl_names = list(set(bl_names + merged["blacklist"].get("names", [])))
        bl_exts = list(set(bl_exts + merged["blacklist"].get("extensions", [])))

    bl_names = list(set(bl_names).union(DEFAULT_SYSTEM_IGNORED))

    return {
        "target_path": target_path,
        "max_depth": max_depth,
        "max_samples": max_samples,
        "blacklist": {
            "paths": bl_paths,
            "names": bl_names,
            "extensions": bl_exts
        }
    }


def clean_path(path_str: str) -> str:
    if not path_str:
        return ""
    p = str(path_str)
    if p.startswith(WIN_LONG_PATH_PREFIX):
        p = p[len(WIN_LONG_PATH_PREFIX):]
    return os.path.normpath(p)


def normalize_path(path_str: str) -> str:
    raw_clean = clean_path(path_str)
    real_p = os.path.realpath(raw_clean)
    norm_p = os.path.normcase(real_p)
    return norm_p.rstrip(os.sep).rstrip('/')


def fix_path_for_windows(path_str: str) -> str:
    abs_path = os.path.abspath(clean_path(path_str))
    if sys.platform.startswith('win') and not abs_path.startswith(WIN_LONG_PATH_PREFIX):
        return f"{WIN_LONG_PATH_PREFIX}{abs_path}"
    return abs_path


def format_mtime(timestamp: float) -> str:
    try:
        if timestamp <= 0:
            return "Unknown"
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "Unknown"


def format_size(size_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f}TB"


class ScannerFilter:
    def __init__(self, caller_script: Optional[str] = None, output_file: Optional[str] = None,
                 blacklist: Optional[dict] = None):
        self.exact_paths: Set[str] = set()
        self.ignored_names: Set[str] = {"__pycache__"}
        self.ignored_exts: Set[str] = {".pyc", ".pyo"}

        tool_script = normalize_path(__file__)
        self.exact_paths.add(tool_script)

        if caller_script:
            self.exact_paths.add(normalize_path(caller_script))

        if output_file:
            self.exact_paths.add(normalize_path(output_file))

        if blacklist:
            for name in blacklist.get("names", []):
                if name:
                    self.ignored_names.add(name.lower() if sys.platform.startswith('win') else name)

            for ext in blacklist.get("extensions", []):
                if ext:
                    clean_ext = ext if ext.startswith('.') else f".{ext}"
                    self.ignored_exts.add(clean_ext.lower())

            for path_item in blacklist.get("paths", []):
                if path_item:
                    self.exact_paths.add(normalize_path(path_item))

    def should_ignore_name(self, name: str) -> bool:
        name_for_check = name.lower() if sys.platform.startswith('win') else name
        return name_for_check in self.ignored_names

    def should_ignore(self, entry: os.DirEntry) -> bool:
        if self.should_ignore_name(entry.name):
            return True

        try:
            if entry.is_file(follow_symlinks=False):
                _, ext = os.path.splitext(entry.name)
                if ext.lower() in self.ignored_exts:
                    return True
        except (PermissionError, OSError):
            pass

        try:
            real_entry_path = normalize_path(entry.path)
            if real_entry_path in self.exact_paths:
                return True
        except Exception:
            pass

        return False


def stratified_time_slice(items: List[Dict[str, Any]], item_type: str = "文件") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    total = len(items)
    if total <= 100:
        return items, []

    sorted_items = sorted(items, key=lambda x: x.get("_raw_mtime", 0.0), reverse=True)
    head_80 = sorted_items[:80]
    tail_10 = sorted_items[-10:]
    middle_pool = sorted_items[80:-10]
    total_middle_pool = len(middle_pool)

    mid_start_offset = (total_middle_pool - 10) // 2
    mid_end_offset = mid_start_offset + 10

    first_omitted = middle_pool[:mid_start_offset]
    mid_10 = middle_pool[mid_start_offset:mid_end_offset]
    second_omitted = middle_pool[mid_end_offset:]

    def _create_omission_node(omitted_slice: List[Dict[str, Any]], label: str) -> Dict[str, Any]:
        count = len(omitted_slice)
        total_size = sum(x.get("size_bytes", 0) for x in omitted_slice)
        start_time = omitted_slice[0].get("mtime", "Unknown") if omitted_slice else "Unknown"
        end_time = omitted_slice[-1].get("mtime", "Unknown") if omitted_slice else "Unknown"
        desc = f"[{label}: 已省略 {count} 个{item_type} | 时间范围: {end_time} 至 {start_time} | 体积: {format_size(total_size)}]"
        return {
            "name": desc,
            "size_bytes": total_size,
            "mtime": f"{end_time} ~ {start_time}",
            "status": "omitted_interval",
            "is_omission_marker": True,
            "omitted_count": count
        }

    assembled_items: List[Dict[str, Any]] = []
    assembled_items.extend(head_80)
    omissions_meta = []

    if first_omitted:
        marker1 = _create_omission_node(first_omitted, "区间省略 1")
        assembled_items.append(marker1)
        omissions_meta.append(marker1)

    assembled_items.extend(mid_10)

    if second_omitted:
        marker2 = _create_omission_node(second_omitted, "区间省略 2")
        assembled_items.append(marker2)
        omissions_meta.append(marker2)

    assembled_items.extend(tail_10)

    return assembled_items, omissions_meta


def filter_categories_if_needed(file_records: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    category_map = defaultdict(list)
    for f in file_records:
        _, ext = os.path.splitext(f["name"])
        ext_clean = ext.lower() if ext else "[无后缀]"
        category_map[ext_clean].append(f)

    total_categories = len(category_map)
    category_meta = {
        "total_categories": total_categories,
        "truncated": False,
        "omitted_categories_count": 0,
        "omitted_category_names": []
    }

    if total_categories <= 100:
        return file_records, category_meta

    category_summary = []
    for ext, files in category_map.items():
        newest_mtime = max(x.get("_raw_mtime", 0.0) for x in files)
        category_summary.append({
            "ext": ext,
            "_raw_mtime": newest_mtime,
            "files": files
        })

    sorted_cats = sorted(category_summary, key=lambda x: x["_raw_mtime"], reverse=True)
    head_cats = sorted_cats[:80]
    tail_cats = sorted_cats[-10:]
    mid_pool = sorted_cats[80:-10]

    mid_start = (len(mid_pool) - 10) // 2
    mid_cats = mid_pool[mid_start:mid_start + 10]
    omitted_cats = mid_pool[:mid_start] + mid_pool[mid_start + 10:]

    category_meta["truncated"] = True
    category_meta["omitted_categories_count"] = len(omitted_cats)
    category_meta["omitted_category_names"] = [c["ext"] for c in omitted_cats[:20]]

    retained_files = []
    for c in (head_cats + mid_cats + tail_cats):
        retained_files.extend(c["files"])

    return retained_files, category_meta


def scan_directory(current_path: str, current_depth: int, max_depth: int, filter_engine: ScannerFilter,
                   max_sample_count: int = DEFAULT_MAX_SAMPLE_COUNT,
                   visited_paths: Optional[Set[str]] = None,
                   abort_event: Optional[threading.Event] = None) -> dict:
    if visited_paths is None:
        visited_paths = set()

    safe_path = fix_path_for_windows(current_path)
    clean_display_path = clean_path(os.path.abspath(current_path))
    dir_name = os.path.basename(clean_display_path) or clean_display_path

    node = {
        "name": dir_name,
        "path": clean_display_path,
        "type": "directory",
        "status": "normal",
        "mtime": "Unknown",
        "file_stats": {
            "total": 0,
            "truncated": False,
            "sampled": 0,
            "omitted_intervals": []
        },
        "category_stats": {
            "total_categories": 0,
            "truncated": False,
            "omitted_categories_count": 0
        },
        "dir_stats": {"total": 0, "truncated": False, "sampled": 0},
        "files": [],
        "subdirectories": []
    }

    if abort_event and abort_event.is_set():
        node["status"] = "aborted_by_user"
        return node

    try:
        real_current_path = normalize_path(safe_path)
        if real_current_path in visited_paths:
            node["status"] = "symlink_loop_detected"
            return node
        visited_paths.add(real_current_path)
    except Exception:
        pass

    try:
        stat_info = os.stat(safe_path)
        node["mtime"] = format_mtime(stat_info.st_mtime)
    except PermissionError:
        node["status"] = "access_denied"
        return node
    except FileNotFoundError:
        node["status"] = "deleted_mid_scan"
        return node
    except OSError as e:
        node["status"] = f"error_os_{e.errno}"
        return node

    raw_file_records = []
    raw_dir_entries = []
    entries_scanned = 0

    try:
        with os.scandir(safe_path) as it:
            for entry in it:
                if abort_event and abort_event.is_set():
                    node["status"] = "aborted_by_user"
                    return node

                entries_scanned += 1
                if entries_scanned > MAX_DIRECTORY_ENTRIES_BUDGET:
                    node["file_stats"]["truncated"] = True
                    node["status"] = "directory_budget_exceeded"
                    break

                try:
                    if filter_engine.should_ignore_name(entry.name):
                        continue

                    is_dir = entry.is_dir(follow_symlinks=False)
                    is_file = entry.is_file(follow_symlinks=False)

                    if is_file:
                        if filter_engine.should_ignore(entry):
                            continue

                        status = "normal"
                        try:
                            f_stat = entry.stat(follow_symlinks=False)
                            size = f_stat.st_size
                            mtime_raw = f_stat.st_mtime
                            mtime_str = format_mtime(mtime_raw)
                        except PermissionError:
                            status = "access_denied"
                            size, mtime_raw, mtime_str = 0, 0.0, "Unknown"
                        except FileNotFoundError:
                            status = "deleted_mid_scan"
                            size, mtime_raw, mtime_str = 0, 0.0, "Unknown"
                        except OSError:
                            status = "locked_or_busy"
                            size, mtime_raw, mtime_str = 0, 0.0, "Unknown"

                        raw_file_records.append({
                            "name": entry.name,
                            "size_bytes": size,
                            "mtime": mtime_str,
                            "status": status,
                            "_raw_mtime": mtime_raw
                        })

                    elif is_dir:
                        if filter_engine.should_ignore(entry):
                            continue

                        d_mtime_raw = 0.0
                        try:
                            d_stat = entry.stat(follow_symlinks=False)
                            d_mtime_raw = d_stat.st_mtime
                        except Exception:
                            pass
                        raw_dir_entries.append((entry, d_mtime_raw))

                except (PermissionError, OSError):
                    continue
    except PermissionError:
        node["status"] = "access_denied"
        return node
    except FileNotFoundError:
        node["status"] = "deleted_mid_scan"
        return node

    total_files = len(raw_file_records)
    node["file_stats"]["total"] = total_files

    files_after_cat, cat_meta = filter_categories_if_needed(raw_file_records)
    node["category_stats"].update(cat_meta)

    if len(files_after_cat) > max_sample_count:
        node["file_stats"]["truncated"] = True
        sampled_files, omissions = stratified_time_slice(files_after_cat, item_type="文件")
        node["file_stats"]["omitted_intervals"] = omissions
    else:
        sampled_files = sorted(files_after_cat, key=lambda x: x.get("_raw_mtime", 0.0), reverse=True)

    cleaned_file_list = []
    for f in sampled_files:
        f.pop("_raw_mtime", None)
        cleaned_file_list.append(f)

    node["files"] = cleaned_file_list
    node["file_stats"]["sampled"] = len(cleaned_file_list)

    total_dirs = len(raw_dir_entries)
    node["dir_stats"]["total"] = total_dirs
    raw_dir_entries.sort(key=lambda x: x[1], reverse=True)

    if total_dirs > max_sample_count:
        node["dir_stats"]["truncated"] = True
        sampled_dirs = [x[0] for x in raw_dir_entries[:max_sample_count]]
    else:
        sampled_dirs = [x[0] for x in raw_dir_entries]

    node["dir_stats"]["sampled"] = len(sampled_dirs)

    for d_entry in sampled_dirs:
        if abort_event and abort_event.is_set():
            break

        dir_full_path = os.path.join(clean_display_path, d_entry.name)
        if current_depth < max_depth:
            sub_node = scan_directory(
                dir_full_path,
                current_depth=current_depth + 1,
                max_depth=max_depth,
                filter_engine=filter_engine,
                max_sample_count=max_sample_count,
                visited_paths=visited_paths,
                abort_event=abort_event
            )
            node["subdirectories"].append(sub_node)
        else:
            sub_node_shallow = {
                "name": d_entry.name,
                "path": clean_path(os.path.abspath(dir_full_path)),
                "type": "directory",
                "status": "depth_limit_reached",
                "mtime": "Unknown",
                "files": [],
                "subdirectories": []
            }
            try:
                d_stat = d_entry.stat(follow_symlinks=False)
                sub_node_shallow["mtime"] = format_mtime(d_stat.st_mtime)
            except Exception:
                pass
            node["subdirectories"].append(sub_node_shallow)

    return node


def execute_scan(abort_event: Optional[threading.Event] = None) -> Optional[str]:
    """无参执行扫描：严格读取 config.json 中的 target_path 与 max_depth"""
    full_cfg = load_full_config()
    opts = extract_scanner_options(full_cfg)

    target_dir = clean_path(opts["target_path"])
    effective_max_depth = opts["max_depth"]
    max_samples = opts["max_samples"]
    blacklist = opts["blacklist"]

    if not os.path.exists(target_dir):
        print(f"[-] 错误：目标目录不存在 -> {target_dir}", flush=True)
        return None

    print(f"[*] [按配置物理扫描] 目标: {os.path.abspath(target_dir)} | 深度: {effective_max_depth}", flush=True)

    target_output = DEFAULT_SCAN_OUTPUT_FILE
    filter_engine = ScannerFilter(
        caller_script=None,
        output_file=target_output,
        blacklist=blacklist
    )

    start_time = datetime.now()
    visited_records: Set[str] = set()

    tree_data = scan_directory(
        target_dir,
        current_depth=1,
        max_depth=effective_max_depth,
        filter_engine=filter_engine,
        max_sample_count=max_samples,
        visited_paths=visited_records,
        abort_event=abort_event
    )

    result = {
        "scan_meta": {
            "root_path": os.path.abspath(target_dir),
            "max_depth": effective_max_depth,
            "scan_time": start_time.strftime('%Y-%m-%d %H:%M:%S'),
            "duration_seconds": round((datetime.now() - start_time).total_seconds(), 2),
            "strategy": "stratified_80_10_10_safe_circuit",
            "blacklist_config": blacklist
        },
        "structure": tree_data
    }

    output_dir = os.path.dirname(os.path.abspath(target_output))
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    with open(target_output, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"[+] 扫描成功完成，结果写入 -> {os.path.abspath(target_output)}", flush=True)
    return target_output