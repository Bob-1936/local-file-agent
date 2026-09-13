# core/indexer_engine.py
# -*- coding: utf-8 -*-

import os
import sys
import json
import sqlite3
import hashlib
import time
import re
import ast
import queue
import logging
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor

import lancedb
import pyarrow as pa
from fastembed import TextEmbedding

logger = logging.getLogger("IndexerEngine")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

HAS_DOCX = False
try:
    import docx
    HAS_DOCX = True
except ImportError:
    pass

HAS_PYPDF = False
try:
    import pypdf
    HAS_PYPDF = True
except ImportError:
    pass

HAS_PIL = False
try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    HAS_PIL = True
except ImportError:
    pass

HAS_JIEBA = False
try:
    import jieba
    jieba.setLogLevel(logging.ERROR)
    HAS_JIEBA = True
except ImportError:
    pass

os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"

_MODEL_INIT_LOCK = threading.Lock()
_EMBED_INFERENCE_LOCK = threading.Lock()
_LOCAL_TEXT_MODEL: Optional[TextEmbedding] = None
_MODEL_DIMENSION: Optional[int] = None

TEXT_EXTENSIONS = {
    '.py', '.md', '.txt', '.json', '.yaml', '.yml',
    '.ini', '.csv', '.sql', '.html', '.log', '.docx', '.pdf'
}
IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.webp', '.bmp'}


def get_local_text_model() -> TextEmbedding:
    global _LOCAL_TEXT_MODEL
    if _LOCAL_TEXT_MODEL is None:
        with _MODEL_INIT_LOCK:
            if _LOCAL_TEXT_MODEL is None:
                logger.info("加载文本向量模型 BAAI/bge-small-zh-v1.5...")
                _LOCAL_TEXT_MODEL = TextEmbedding(model_name="BAAI/bge-small-zh-v1.5")
    return _LOCAL_TEXT_MODEL


def get_model_dimension() -> int:
    global _MODEL_DIMENSION
    if _MODEL_DIMENSION is None:
        model = get_local_text_model()
        with _EMBED_INFERENCE_LOCK:
            probe_vec = list(model.embed(["probe"]))[0]
            _MODEL_DIMENSION = len(probe_vec)
    return _MODEL_DIMENSION


def tokenize_text(text: str) -> str:
    if not text:
        return ""
    clean_text = re.sub(r'[\r\n\t]', ' ', text)
    if HAS_JIEBA:
        tokens = jieba.cut_for_search(clean_text)
        return " ".join([t.strip() for t in tokens if t.strip()])
    return " ".join(list(clean_text))


def extract_content_snippet(file_path: str, ext: str, is_dir: bool = False, max_chars: int = 1500) -> str:
    if not os.path.exists(file_path):
        return ""

    if is_dir or os.path.isdir(file_path):
        parent_dirs = os.path.normpath(file_path).split(os.sep)
        context_path = " / ".join(parent_dirs[-4:])
        return f"文件夹目录拓扑: {context_path}"

    if ext in IMAGE_EXTENSIONS:
        if not HAS_PIL:
            parent_dirs = os.path.normpath(file_path).split(os.sep)
            return f"图片路径上下文: {' / '.join(parent_dirs[-4:-1])}"
        try:
            parent_dirs = os.path.normpath(file_path).split(os.sep)
            context_path = " / ".join(parent_dirs[-4:-1])
            exif_desc = []
            with Image.open(file_path) as img:
                w, h = img.size
                exif_desc.append(f"分辨率: {w}x{h}")
                exif_data = img._getexif()
                if exif_data:
                    for tag_id, val in exif_data.items():
                        tag = TAGS.get(tag_id, tag_id)
                        if tag in ['ImageDescription', 'XPTitle', 'XPKeywords', 'UserComment', 'Software', 'Model']:
                            clean_val = str(val).strip().replace('\x00', '')
                            if clean_val:
                                exif_desc.append(f"{tag}: {clean_val[:80]}")
            exif_info_str = "，".join(exif_desc)
            return f"图片主题路径: {context_path}。元数据参数: {exif_info_str}"
        except Exception as e:
            logger.debug(f"提取图片元数据异常 [{file_path}]: {e}")
            return ""

    if ext == ".py":
        try:
            max_ast_bytes = 1024 * 1024
            file_size = os.path.getsize(file_path)
            classes, functions, imports = [], [], []
            code_text = ""

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                if file_size <= max_ast_bytes:
                    code_text = f.read()
                else:
                    chunk = f.read(65536)
                    last_newline = chunk.rfind('\n')
                    code_text = chunk[:last_newline] if last_newline > 0 else chunk

            parsed_by_ast = False
            try:
                tree = ast.parse(code_text)
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        classes.append(node.name)
                    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        functions.append(node.name)
                    elif isinstance(node, ast.Import):
                        for n in node.names:
                            imports.append(n.name)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            imports.append(node.module)
                parsed_by_ast = True
            except (SyntaxError, ValueError):
                pass

            if not parsed_by_ast:
                classes = re.findall(r"^\s*class\s+([A-Za-z0-9_]+)", code_text, flags=re.MULTILINE)
                functions = re.findall(r"^\s*(?:async\s+)?def\s+([A-Za-z0-9_]+)", code_text, flags=re.MULTILINE)
                import_matches = re.findall(r"^\s*(?:from\s+([A-Za-z0-9_\.]+)\s+import|import\s+([A-Za-z0-9_,\s]+))",
                                            code_text, flags=re.MULTILINE)
                for mod, raw_imp in import_matches:
                    if mod:
                        imports.append(mod.split('.')[0])
                    elif raw_imp:
                        for imp_item in raw_imp.split(','):
                            clean_item = imp_item.strip().split()[0] if imp_item.strip() else ""
                            if clean_item:
                                imports.append(clean_item)

            class_summary = "定义类: " + ", ".join(classes[:25]) if classes else ""
            func_summary = "定义函数: " + ", ".join(functions[:30]) if functions else ""
            unique_imports = list(dict.fromkeys(imports))
            import_summary = "导入模块: " + ", ".join(unique_imports[:20]) if unique_imports else ""
            body_preview = code_text[:500].replace("\n", " ").strip()

            snippet = f"{class_summary}。{func_summary}。{import_summary}。关键代码: {body_preview}"
            return snippet[:max_chars].strip("。 ")
        except Exception as e:
            logger.debug(f"提取 Python 特征异常 [{file_path}]: {e}")
            return ""

    if ext == ".docx":
        if not HAS_DOCX:
            return ""
        try:
            doc = docx.Document(file_path)
            valid_paras = [p.text.strip() for p in doc.paragraphs if p.text.strip()]
            total_p = len(valid_paras)
            if total_p == 0:
                return ""
            if total_p <= 10:
                sampled = valid_paras
            else:
                mid_idx = total_p // 2
                sampled = valid_paras[:3] + valid_paras[mid_idx - 3: mid_idx + 3] + valid_paras[-2:]
            return " ".join(sampled)[:max_chars].strip()
        except Exception as e:
            logger.debug(f"提取 Word 特征异常 [{file_path}]: {e}")
            return ""

    if ext == ".pdf":
        if not HAS_PYPDF:
            return ""
        try:
            reader = pypdf.PdfReader(file_path)
            num_pages = len(reader.pages)
            extracted = []
            pages_to_read = [0]
            if num_pages > 2:
                pages_to_read.append(1)
            if num_pages > 5:
                pages_to_read.append(num_pages // 2)

            for p_no in pages_to_read:
                if p_no < num_pages:
                    txt = reader.pages[p_no].extract_text()
                    if txt:
                        extracted.append(txt.replace("\n", " ").strip())
            return " ".join(extracted)[:max_chars].strip()
        except Exception as e:
            logger.debug(f"提取 PDF 特征异常 [{file_path}]: {e}")
            return ""

    if ext == ".csv":
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [f.readline().strip() for _ in range(4)]
                valid_lines = [l for l in lines if l]
                return "表格前置数据: " + " | ".join(valid_lines)[:max_chars]
        except Exception as e:
            logger.debug(f"提取 CSV 特征异常 [{file_path}]: {e}")
            return ""

    plain_text_exts = {'.md', '.txt', '.json', '.yaml', '.yml', '.ini', '.sql', '.html', '.log'}
    if ext in plain_text_exts:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(max_chars).replace("\n", " ").strip()
        except Exception as e:
            logger.debug(f"提取文本特征异常 [{file_path}]: {e}")
            return ""

    return ""


class CoreConfig:
    def __init__(self, config_path: str = None):
        base_dir = Path(__file__).resolve().parent.parent
        self.config_file = Path(config_path) if config_path else base_dir / "config" / "config.json"
        self.base_dir = self.config_file.parent.parent
        self.target_path: str = ""
        self.blacklist_paths: List[str] = []
        self.db_path: str = str(self.base_dir / "data" / "database" / "file_indexer.db")
        self.lancedb_dir: str = str(self.base_dir / "data" / "lancedb")
        self.load_config()

    def load_config(self):
        if not self.config_file.exists():
            os.makedirs(self.config_file.parent, exist_ok=True)
            default_data = {
                "target_path": str(self.base_dir),
                "blacklist_paths": [str(self.base_dir / ".git"), str(self.base_dir / "data")]
            }
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(default_data, f, indent=4, ensure_ascii=False)

        with open(self.config_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.target_path = os.path.normpath(os.path.abspath(data.get("target_path", "")))
        self.blacklist_paths = [
            os.path.normpath(os.path.abspath(p))
            for p in data.get("blacklist_paths", [])
        ]
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        os.makedirs(self.lancedb_dir, exist_ok=True)


class DatabaseEngine:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def session(self):
        conn = sqlite3.connect(self.db_path, timeout=60.0)
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 60000;")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self.session() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    file_name TEXT NOT NULL,
                    file_extension TEXT,
                    file_size INTEGER NOT NULL,
                    created_time REAL,
                    modified_time REAL,
                    last_accessed_time REAL,
                    file_hash TEXT DEFAULT NULL,
                    tags TEXT DEFAULT '[]',
                    category TEXT DEFAULT '未分类',
                    description TEXT DEFAULT '',
                    is_favorite BOOLEAN DEFAULT 0,
                    rating INTEGER DEFAULT 0,
                    is_dir BOOLEAN DEFAULT 0,
                    status TEXT DEFAULT 'active',
                    is_deleted BOOLEAN DEFAULT 0,
                    vector_indexed BOOLEAN DEFAULT 0,
                    security_level INTEGER DEFAULT 1,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            ''')

            cursor.execute("PRAGMA table_info(files);")
            cols = [col[1] for col in cursor.fetchall()]
            if "is_dir" not in cols:
                cursor.execute("ALTER TABLE files ADD COLUMN is_dir BOOLEAN DEFAULT 0;")
            if "security_level" not in cols:
                cursor.execute("ALTER TABLE files ADD COLUMN security_level INTEGER DEFAULT 1;")

            cursor.execute('''
                CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5(
                    file_id UNINDEXED,
                    file_name_tokens,
                    description_tokens,
                    tokenize='unicode61'
                );
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_tags (
                    file_id INTEGER NOT NULL,
                    tag_name TEXT NOT NULL,
                    PRIMARY KEY (file_id, tag_name),
                    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
                );
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS operation_journal (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    operator TEXT DEFAULT 'agent',
                    src_path TEXT,
                    dest_path TEXT,
                    extra_meta TEXT DEFAULT '{}',
                    can_undo INTEGER DEFAULT 1,
                    is_undone INTEGER DEFAULT 0,
                    created_at REAL,
                    formatted_time TEXT
                );
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    formatted_time TEXT,
                    operator TEXT,
                    action_name TEXT,
                    level TEXT,
                    target_paths TEXT,
                    status TEXT,
                    details TEXT
                );
            ''')

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_path ON files(file_path COLLATE NOCASE);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_name ON files(file_name);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ext ON files(file_extension);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_is_dir ON files(is_dir);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_level ON files(security_level);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON files(status, is_deleted);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vec_indexed ON files(vector_indexed, is_deleted);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_op_journal_undone ON operation_journal(is_undone, can_undo);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp);")
            conn.commit()


class LanceDBEngine:
    def __init__(self, db_dir: str):
        self.db = lancedb.connect(db_dir)
        self.table_name = "file_embeddings"
        self._table_lock = threading.Lock()
        self._init_tables()

    def _init_tables(self):
        dim = get_model_dimension()
        schema = pa.schema([
            pa.field("file_id", pa.int64()),
            pa.field("vector", pa.list_(pa.float32(), dim))
        ])
        with self._table_lock:
            if self.table_name not in self.db.table_names():
                self.table = self.db.create_table(self.table_name, schema=schema)
            else:
                self.table = self.db.open_table(self.table_name)

    def _delete_by_file_ids_locked(self, clean_ids: List[int]):
        batch_size = 300
        for i in range(0, len(clean_ids), batch_size):
            chunk = clean_ids[i:i + batch_size]
            id_filter = ", ".join(map(str, chunk))
            try:
                self.table.delete(f"file_id IN ({id_filter})")
            except Exception as e:
                logger.error(f"LanceDB 向量清理异常: {e}")

    def delete_by_file_ids(self, file_ids: List[int]):
        if not file_ids:
            return
        clean_ids = []
        for fid in file_ids:
            try:
                clean_ids.append(int(fid))
            except (ValueError, TypeError):
                continue
        if not clean_ids:
            return
        with self._table_lock:
            self._delete_by_file_ids_locked(clean_ids)

    def upsert_vectors(self, records: List[Dict[str, Any]]):
        if not records:
            return
        clean_ids = []
        for r in records:
            try:
                clean_ids.append(int(r["file_id"]))
            except (ValueError, TypeError):
                continue

        with self._table_lock:
            if clean_ids:
                self._delete_by_file_ids_locked(clean_ids)
            self.table.add(records)

    def search_similar_file_ids(self, query_vector: List[float], top_k: int = 200) -> List[Tuple[int, float]]:
        try:
            with self._table_lock:
                results = self.table.search(query_vector).metric("cosine").limit(top_k).to_list()
            return [(int(r["file_id"]), float(r["_distance"])) for r in results]
        except Exception as e:
            logger.error(f"LanceDB 相似度检索异常: {e}")
            return []


class IndexerCore:
    def __init__(self, config_path: str = None):
        self.config = CoreConfig(config_path)
        self.db = DatabaseEngine(self.config.db_path)
        self.vdb = LanceDBEngine(self.config.lancedb_dir)
        self._vector_build_lock = threading.Lock()
        self.reseed_security_levels()

    def is_blacklisted(self, current_path: str) -> bool:
        norm_path = os.path.normcase(os.path.normpath(os.path.abspath(current_path)))
        for bp in self.config.blacklist_paths:
            norm_bp = os.path.normcase(os.path.normpath(os.path.abspath(bp)))
            if norm_path == norm_bp or norm_path.startswith(norm_bp + os.sep):
                return True
        return False

    # ==================== 安全等级灾备自愈与数据库同步 ====================

    def reseed_security_levels(self):
        """
        根据 data/asset_security_levels.json 备份文件，对数据库重新标注 2/3 级安全等级：
        - 保证在冷启动或清库重建后，安全等级标记绝对不会遗失；
        - 按规范将相对路径映射回当前真实沙箱绝对路径并批量对齐。
        """
        backup_file = os.path.join(self.config.base_dir, "data", "asset_security_levels.json")
        if not os.path.exists(backup_file):
            return

        try:
            with open(backup_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            levels_map = data.get("levels", {})
            if not levels_map:
                return

            target_root = self.config.target_path
            with self.db.session() as conn:
                with conn:
                    # 先将所有标记重设为 1，随后根据灾备精准重灌
                    conn.execute("UPDATE files SET security_level = 1 WHERE security_level != 1;")

                    for rel_p, lvl in levels_map.items():
                        clean_rel = rel_p.replace('/', os.sep)
                        full_abs = os.path.normpath(os.path.join(target_root, clean_rel))
                        conn.execute(
                            "UPDATE files SET security_level = ? WHERE file_path = ? COLLATE NOCASE",
                            (int(lvl), full_abs)
                        )
            logger.info(f"[安全自愈] 已依据 data/ 灾备清单完成 {len(levels_map)} 项资产的安全等级重新校准。")
        except Exception as e:
            logger.error(f"安全等级灾备重放异常: {e}")

    def update_asset_security_level(self, abs_path: str, level: int, is_dir: bool = False) -> Dict[str, Any]:
        """更新单个资产的显式安全等级。若为目录打标，自动清理所有下属子文件的显式标记（恢复为1）"""
        clean_path = os.path.normpath(abs_path)
        target_lvl = int(level)
        cleaned_count = 0

        with self.db.session() as conn:
            with conn:
                conn.execute(
                    "UPDATE files SET security_level = ? WHERE file_path = ? COLLATE NOCASE",
                    (target_lvl, clean_path)
                )

                if is_dir and target_lvl in (2, 3):
                    # 规则要求：父目录设置2/3级后，下属已打标子文件全部恢复为1级（统一由父目录动态继承）
                    win_prefix = clean_path + "\\"
                    posix_prefix = clean_path + "/"
                    cursor = conn.cursor()
                    cursor.execute(
                        "UPDATE files SET security_level = 1 WHERE (file_path LIKE ? OR file_path LIKE ?) AND security_level != 1",
                        (win_prefix + "%", posix_prefix + "%")
                    )
                    cleaned_count = cursor.rowcount

        return {"success": True, "cleaned_count": cleaned_count}

    def batch_update_security_levels(self, path_level_pairs: List[Tuple[str, int, bool]]) -> Dict[str, Any]:
        """批量更新资产安全等级并执行子项清理"""
        total_cleaned = 0
        with self.db.session() as conn:
            with conn:
                for p, lvl, is_d in path_level_pairs:
                    norm_p = os.path.normpath(p)
                    conn.execute(
                        "UPDATE files SET security_level = ? WHERE file_path = ? COLLATE NOCASE",
                        (int(lvl), norm_p)
                    )
                    if is_d and int(lvl) in (2, 3):
                        win_prefix = norm_p + "\\"
                        posix_prefix = norm_p + "/"
                        cursor = conn.cursor()
                        cursor.execute(
                            "UPDATE files SET security_level = 1 WHERE (file_path LIKE ? OR file_path LIKE ?) AND security_level != 1",
                            (win_prefix + "%", posix_prefix + "%")
                        )
                        total_cleaned += cursor.rowcount

        return {"success": True, "updated_count": len(path_level_pairs), "cleaned_sub_count": total_cleaned}

    # ==================== 会话隔离与操作流水日志 ====================

    def clear_operation_journal(self):
        try:
            with self.db.session() as conn:
                with conn:
                    conn.execute("DELETE FROM operation_journal;")
            logger.info("[会话初始化] 已重置当次运行的操作撤回流水栈。")
        except Exception as e:
            logger.error(f"重置操作流水栈异常: {e}")

    def has_undoable_operations(self) -> bool:
        try:
            with self.db.session() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM operation_journal WHERE can_undo = 1 AND is_undone = 0 LIMIT 1;")
                return cursor.fetchone() is not None
        except Exception:
            return False

    def record_operation_journal(
            self,
            operation_id: str,
            action_type: str,
            operator: str = "agent",
            src_path: str = "",
            dest_path: str = "",
            extra_meta: Optional[Dict[str, Any]] = None,
            can_undo: bool = True
    ):
        now = time.time()
        fmt_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        meta_json = json.dumps(extra_meta or {}, ensure_ascii=False)
        try:
            with self.db.session() as conn:
                with conn:
                    conn.execute('''
                        INSERT INTO operation_journal 
                        (operation_id, action_type, operator, src_path, dest_path, extra_meta, can_undo, is_undone, created_at, formatted_time)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                    ''', (operation_id, action_type, operator, src_path, dest_path, meta_json, 1 if can_undo else 0, now, fmt_time))
        except Exception as e:
            logger.error(f"记录操作流水日志异常: {e}")

    def get_last_undoable_operation(self) -> Optional[Dict[str, Any]]:
        try:
            with self.db.session() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM operation_journal 
                    WHERE can_undo = 1 AND is_undone = 0 
                    ORDER BY id DESC LIMIT 1
                ''')
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"获取可撤回流水异常: {e}")
            return None

    def mark_operation_undone(self, record_id: int):
        try:
            with self.db.session() as conn:
                with conn:
                    conn.execute("UPDATE operation_journal SET is_undone = 1 WHERE id = ?", (record_id,))
        except Exception as e:
            logger.error(f"更新操作流水撤回状态异常: {e}")

    # ==================== 全生命周期操作审计日志 ====================

    def log_audit_event(
            self,
            action_name: str,
            operator: str = "agent",
            level: str = "SAFE",
            target_paths: Optional[List[str]] = None,
            status: str = "SUCCESS",
            details: str = ""
    ):
        now = time.time()
        fmt_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        targets_json = json.dumps(target_paths or [], ensure_ascii=False)
        try:
            with self.db.session() as conn:
                with conn:
                    conn.execute('''
                        INSERT INTO audit_logs 
                        (timestamp, formatted_time, operator, action_name, level, target_paths, status, details)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (now, fmt_time, operator, action_name, level, targets_json, status, details))
        except Exception as e:
            logger.error(f"写入审计日志异常: {e}")

    def query_audit_logs(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        try:
            with self.db.session() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM audit_logs 
                    ORDER BY id DESC LIMIT ? OFFSET ?
                ''', (limit, offset))
                return [dict(r) for r in cursor.fetchall()]
        except Exception as e:
            logger.error(f"查询审计日志异常: {e}")
            return []

    # ==================== 磁盘扫描与向量检索流 ====================

    def sync(self, abort_event: Optional[threading.Event] = None) -> Dict[str, int]:
        target = self.config.target_path
        if not os.path.exists(target):
            raise FileNotFoundError(f"目标扫描路径不存在: {target}")

        with self.db.session() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TEMP TABLE temp_scanned (
                    file_path TEXT PRIMARY KEY COLLATE NOCASE,
                    file_name TEXT,
                    file_extension TEXT,
                    file_size INTEGER,
                    created_time REAL,
                    modified_time REAL,
                    last_accessed_time REAL,
                    is_dir BOOLEAN DEFAULT 0
                ) WITHOUT ROWID;
            ''')

            batch = []
            total_scanned = 0
            for root, dirs, files in os.walk(target, topdown=True):
                if abort_event and abort_event.is_set():
                    return {"total_scanned": total_scanned, "added": 0, "updated": 0, "soft_deleted": 0, "aborted": 1}

                dirs[:] = [d for d in dirs if not self.is_blacklisted(os.path.join(root, d))]
                if self.is_blacklisted(root):
                    continue

                for d in dirs:
                    dir_path = os.path.normpath(os.path.join(root, d))
                    try:
                        stat = os.stat(dir_path)
                        batch.append((dir_path, d, "", 0, stat.st_ctime, stat.st_mtime, stat.st_atime, 1))
                        total_scanned += 1
                    except (PermissionError, FileNotFoundError, OSError):
                        continue

                    if len(batch) >= 2000:
                        cursor.executemany('INSERT INTO temp_scanned VALUES (?, ?, ?, ?, ?, ?, ?, ?)', batch)
                        batch.clear()

                for file_name in files:
                    if abort_event and abort_event.is_set():
                        break

                    full_path = os.path.normpath(os.path.join(root, file_name))
                    if self.is_blacklisted(full_path):
                        continue

                    try:
                        stat = os.stat(full_path)
                    except (PermissionError, FileNotFoundError, OSError):
                        continue

                    ext = os.path.splitext(file_name)[1].lower()
                    batch.append((full_path, file_name, ext, stat.st_size, stat.st_ctime, stat.st_mtime, stat.st_atime, 0))
                    total_scanned += 1

                    if len(batch) >= 2000:
                        cursor.executemany('INSERT INTO temp_scanned VALUES (?, ?, ?, ?, ?, ?, ?, ?)', batch)
                        batch.clear()

            if batch:
                cursor.executemany('INSERT INTO temp_scanned VALUES (?, ?, ?, ?, ?, ?, ?, ?)', batch)
                batch.clear()

            with conn:
                cursor.execute('''
                    INSERT INTO files (file_path, file_name, file_extension, file_size, created_time, modified_time, last_accessed_time, is_dir, status, is_deleted, vector_indexed, security_level)
                    SELECT t.file_path, t.file_name, t.file_extension, t.file_size, t.created_time, t.modified_time, t.last_accessed_time, t.is_dir, 'active', 0, 0, 1
                    FROM temp_scanned t LEFT JOIN files f ON t.file_path = f.file_path WHERE f.id IS NULL;
                ''')
                added = cursor.rowcount

                cursor.execute('''
                    UPDATE files
                    SET 
                        file_path = (SELECT t.file_path FROM temp_scanned t WHERE t.file_path = files.file_path),
                        file_name = (SELECT t.file_name FROM temp_scanned t WHERE t.file_path = files.file_path),
                        file_extension = (SELECT t.file_extension FROM temp_scanned t WHERE t.file_path = files.file_path),
                        file_size = (SELECT t.file_size FROM temp_scanned t WHERE t.file_path = files.file_path),
                        is_dir = (SELECT t.is_dir FROM temp_scanned t WHERE t.file_path = files.file_path),
                        modified_time = (SELECT t.modified_time FROM temp_scanned t WHERE t.file_path = files.file_path),
                        status = 'active',
                        is_deleted = 0,
                        vector_indexed = CASE 
                            WHEN files.modified_time != (SELECT t.modified_time FROM temp_scanned t WHERE t.file_path = files.file_path) THEN 0 
                            ELSE files.vector_indexed 
                        END,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE EXISTS (
                        SELECT 1 FROM temp_scanned t 
                        WHERE t.file_path = files.file_path 
                          AND (files.modified_time != t.modified_time OR files.file_size != t.file_size OR files.is_deleted = 1)
                    );
                ''')
                updated = cursor.rowcount

                cursor.execute('''
                    UPDATE files SET is_deleted = 1, status = 'missing', updated_at = CURRENT_TIMESTAMP
                    WHERE is_deleted = 0 AND file_path NOT IN (SELECT file_path FROM temp_scanned);
                ''')
                deleted = cursor.rowcount

                cursor.execute("SELECT id FROM files WHERE is_deleted = 1 AND vector_indexed = 1")
                deleted_ids = [row[0] for row in cursor.fetchall()]

            if deleted_ids:
                self.vdb.delete_by_file_ids(deleted_ids)
                with conn:
                    q_marks = ','.join(['?'] * len(deleted_ids))
                    cursor.execute(f"UPDATE files SET vector_indexed = 0 WHERE id IN ({q_marks})", deleted_ids)
                    cursor.execute(f"DELETE FROM files_fts WHERE file_id IN ({q_marks})", deleted_ids)

        # 扫描同步后，依据外部持久化清单自动二次校验补齐
        self.reseed_security_levels()
        return {"total_scanned": total_scanned, "added": added, "updated": updated, "soft_deleted": deleted}

    def build_vector_index(self, batch_size: int = 64, abort_event: Optional[threading.Event] = None) -> Tuple[bool, str]:
        if not self._vector_build_lock.acquire(blocking=False):
            return True, "已有向量构建任务在执行，跳过本次。"
        try:
            all_supported = tuple(TEXT_EXTENSIONS.union(IMAGE_EXTENSIONS))
            placeholders = ','.join(['?'] * len(all_supported))

            with self.db.session() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(f'''
                    SELECT id, file_path, file_name, file_extension, is_dir 
                    FROM files 
                    WHERE is_deleted = 0 
                      AND vector_indexed = 0 
                      AND (file_extension IN ({placeholders}) OR is_dir = 1)
                ''', all_supported)
                rows = [dict(r) for r in cursor.fetchall()]

            total = len(rows)
            if total == 0:
                return True, "没有需要构建向量的资产（均已同步）。"

            text_model = get_local_text_model()
            data_queue = queue.Queue(maxsize=batch_size * 4)
            stop_sentinel = object()

            def _producer():
                def _extract_task(item):
                    if abort_event and abort_event.is_set():
                        return None
                    try:
                        fid = item["id"]
                        fpath = item["file_path"]
                        fname = item["file_name"]
                        ext = item["file_extension"] or ""
                        is_dir = bool(item.get("is_dir", 0))

                        snippet = extract_content_snippet(fpath, ext, is_dir=is_dir)
                        type_prefix = "文件夹" if is_dir else "文件"
                        corpus = f"{type_prefix}: {fname}。特征与路径: {snippet}"
                        fname_tokens = tokenize_text(fname)
                        snippet_tokens = tokenize_text(snippet)
                        return {
                            "fid": fid,
                            "corpus": corpus,
                            "snippet": snippet,
                            "fname_tokens": fname_tokens,
                            "snippet_tokens": snippet_tokens
                        }
                    except Exception as e:
                        logger.error(f"特征提取异常 file_id={item.get('id')}: {e}")
                        return None

                try:
                    with ThreadPoolExecutor(max_workers=8) as executor:
                        for res in executor.map(_extract_task, rows):
                            if abort_event and abort_event.is_set():
                                break
                            if res is not None:
                                while not (abort_event and abort_event.is_set()):
                                    try:
                                        data_queue.put(res, timeout=0.5)
                                        break
                                    except queue.Full:
                                        continue
                except Exception as e:
                    logger.error(f"向量生产线程异常: {e}")
                finally:
                    try:
                        data_queue.put(stop_sentinel, timeout=5.0)
                    except queue.Full:
                        pass

            prod_thread = threading.Thread(target=_producer, daemon=True)
            prod_thread.start()

            success_count = 0
            batch_items = []
            empty_count = 0
            max_empty = 300

            while True:
                if abort_event and abort_event.is_set():
                    break

                try:
                    item = data_queue.get(timeout=1.0)
                    empty_count = 0
                except queue.Empty:
                    empty_count += 1
                    if not prod_thread.is_alive() and empty_count > 5:
                        break
                    if empty_count > max_empty:
                        break
                    continue

                if item is stop_sentinel:
                    if batch_items:
                        success_count += self._flush_pipeline_batch(batch_items, text_model)
                        batch_items.clear()
                    break

                batch_items.append(item)
                if len(batch_items) >= batch_size:
                    success_count += self._flush_pipeline_batch(batch_items, text_model)
                    batch_items.clear()

            prod_thread.join(timeout=3.0)
            return True, f"成功为 {success_count}/{total} 个资产完成特征构建。"
        finally:
            self._vector_build_lock.release()

    def _flush_pipeline_batch(self, batch_items: List[Dict[str, Any]], model: TextEmbedding) -> int:
        if not batch_items:
            return 0
        fids = [x["fid"] for x in batch_items]
        texts = [x["corpus"] for x in batch_items]

        try:
            with _EMBED_INFERENCE_LOCK:
                embeddings = list(model.embed(texts, batch_size=len(texts)))
            records = [{"file_id": int(fid), "vector": vec.tolist()} for fid, vec in zip(fids, embeddings)]
        except Exception as e:
            logger.error(f"批次向量推理异常: {e}")
            return 0

        try:
            with self.db.session() as conn:
                with conn:
                    update_params = [(x["snippet"], x["fid"]) for x in batch_items]
                    conn.executemany("UPDATE files SET description = ? WHERE id = ?", update_params)

                    q_marks = ','.join(['?'] * len(fids))
                    conn.execute(f"UPDATE files SET vector_indexed = 1 WHERE id IN ({q_marks})", fids)

                    conn.execute(f"DELETE FROM files_fts WHERE file_id IN ({q_marks})", fids)
                    fts_params = [(str(x["fid"]), x["fname_tokens"], x["snippet_tokens"]) for x in batch_items]
                    conn.executemany("INSERT INTO files_fts(file_id, file_name_tokens, description_tokens) VALUES (?, ?, ?)", fts_params)
        except Exception as e:
            logger.error(f"批次数据库写入异常: {e}")
            return 0

        try:
            self.vdb.upsert_vectors(records)
        except Exception as e:
            logger.error(f"批次向量写入异常: {e}")
            try:
                with self.db.session() as conn:
                    with conn:
                        q_marks = ','.join(['?'] * len(fids))
                        conn.execute(f"UPDATE files SET vector_indexed = 0 WHERE id IN ({q_marks})", fids)
            except Exception:
                pass
            return 0

        return len(records)

    def index_single_asset_or_tree(self, root_asset_path: str):
        if not os.path.exists(root_asset_path):
            return

        norm_root = os.path.normpath(os.path.abspath(root_asset_path))
        if self.is_blacklisted(norm_root):
            return

        items_to_sync: List[Tuple[str, str, str, int, float, float, float, int]] = []

        if os.path.isdir(norm_root):
            try:
                st = os.stat(norm_root)
                items_to_sync.append((norm_root, os.path.basename(norm_root), "", 0, st.st_ctime, st.st_mtime, st.st_atime, 1))
            except Exception:
                pass

            for r, dirs, files in os.walk(norm_root, topdown=True):
                dirs[:] = [d for d in dirs if not self.is_blacklisted(os.path.join(r, d))]
                for d in dirs:
                    sub_d_path = os.path.normpath(os.path.join(r, d))
                    try:
                        st = os.stat(sub_d_path)
                        items_to_sync.append((sub_d_path, d, "", 0, st.st_ctime, st.st_mtime, st.st_atime, 1))
                    except Exception:
                        continue
                for f in files:
                    sub_f_path = os.path.normpath(os.path.join(r, f))
                    if self.is_blacklisted(sub_f_path):
                        continue
                    try:
                        st = os.stat(sub_f_path)
                        ext = os.path.splitext(f)[1].lower()
                        items_to_sync.append((sub_f_path, f, ext, st.st_size, st.st_ctime, st.st_mtime, st.st_atime, 0))
                    except Exception:
                        continue
        else:
            try:
                st = os.stat(norm_root)
                fname = os.path.basename(norm_root)
                ext = os.path.splitext(fname)[1].lower()
                items_to_sync.append((norm_root, fname, ext, st.st_size, st.st_ctime, st.st_mtime, st.st_atime, 0))
            except Exception:
                pass

        if not items_to_sync:
            return

        with self.db.session() as conn:
            with conn:
                for path_val, name_val, ext_val, size_val, ctime_val, mtime_val, atime_val, is_d_val in items_to_sync:
                    conn.execute('''
                        INSERT INTO files (file_path, file_name, file_extension, file_size, created_time, modified_time, last_accessed_time, is_dir, status, is_deleted, vector_indexed, security_level)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 0, 0, 1)
                        ON CONFLICT(file_path) DO UPDATE SET
                            file_name = excluded.file_name,
                            file_extension = excluded.file_extension,
                            file_size = excluded.file_size,
                            modified_time = excluded.modified_time,
                            is_dir = excluded.is_dir,
                            status = 'active',
                            is_deleted = 0,
                            vector_indexed = 0,
                            updated_at = CURRENT_TIMESTAMP;
                    ''', (path_val, name_val, ext_val, size_val, ctime_val, mtime_val, atime_val, is_d_val))

        try:
            threading.Thread(target=self.build_vector_index, kwargs={"batch_size": 32}, daemon=True).start()
        except Exception:
            pass

    def rename_file(self, file_id: int, new_name: str) -> Tuple[bool, str]:
        clean_new_name = os.path.basename(new_name.strip())
        if not clean_new_name or clean_new_name != new_name.strip() or any(c in clean_new_name for c in ['/', '\\', ':', '*', '?', '"', '<', '>', '|']):
            return False, "非法名称: 禁止包含路径分隔符或保留字符。"

        with self.db.session() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT file_path, file_name, is_dir FROM files WHERE id = ? AND is_deleted = 0", (file_id,))
            row = cursor.fetchone()
            if not row:
                return False, "未找到目标或已被删除。"

            old_path, old_name, is_dir = os.path.normpath(row[0]), row[1], bool(row[2])
            if clean_new_name == old_name:
                return True, old_path

            dir_name = os.path.dirname(old_path)
            new_path = os.path.normpath(os.path.join(dir_name, clean_new_name))
            new_ext = "" if is_dir else os.path.splitext(clean_new_name)[1].lower()

            is_case_only_change = (os.path.normcase(old_path) == os.path.normcase(new_path))
            if not is_case_only_change and os.path.lexists(new_path):
                return False, f"目标路径在磁盘上已存在同名资产: {new_path}"

            try:
                os.rename(old_path, new_path)
            except Exception as e:
                return False, f"磁盘物理重命名拒绝: {str(e)}"

            try:
                with conn:
                    cursor.execute(
                        "UPDATE files SET file_path = ?, file_name = ?, file_extension = ?, vector_indexed = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (new_path, clean_new_name, new_ext, file_id)
                    )
                    cursor.execute("DELETE FROM files_fts WHERE file_id = ?", (str(file_id),))

                    affected_sub_ids = []
                    if is_dir:
                        search_prefix_win = old_path + "\\"
                        search_prefix_posix = old_path + "/"
                        cursor.execute(
                            "SELECT id, file_path FROM files WHERE (file_path LIKE ? OR file_path LIKE ?) AND is_deleted = 0",
                            (search_prefix_win + "%", search_prefix_posix + "%")
                        )
                        sub_records = cursor.fetchall()
                        old_len = len(old_path)
                        for sub_id, sub_p in sub_records:
                            sub_new_p = os.path.normpath(new_path + sub_p[old_len:])
                            cursor.execute(
                                "UPDATE files SET file_path = ?, vector_indexed = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                                (sub_new_p, sub_id)
                            )
                            affected_sub_ids.append(sub_id)

                        if affected_sub_ids:
                            q_marks = ','.join(['?'] * len(affected_sub_ids))
                            cursor.execute(f"DELETE FROM files_fts WHERE file_id IN ({q_marks})", [str(x) for x in affected_sub_ids])

                all_dirty_ids = [file_id] + affected_sub_ids
                self.vdb.delete_by_file_ids(all_dirty_ids)
                threading.Thread(target=self.build_vector_index, kwargs={"batch_size": 32}, daemon=True).start()
                return True, new_path
            except Exception as db_err:
                try:
                    os.rename(new_path, old_path)
                    return False, f"数据库同步失败，已回滚物理重命名: {db_err}"
                except Exception as rollback_err:
                    return False, f"重命名异常且回滚失败: db={db_err}, rollback={rollback_err}"

    def find_duplicates(self) -> Dict[str, List[Dict[str, Any]]]:
        candidates = []
        with self.db.session() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, file_path, file_size, file_hash 
                FROM files 
                WHERE is_deleted = 0 AND is_dir = 0 AND file_size IN (
                    SELECT file_size FROM files 
                    WHERE is_deleted = 0 AND is_dir = 0 AND file_size > 0 
                    GROUP BY file_size HAVING count(*) > 1
                );
            ''')
            candidates = [dict(r) for r in cursor.fetchall()]

        hash_updates = []
        hash_groups: Dict[str, List[Dict[str, Any]]] = {}

        for row in candidates:
            fid, fpath, fhash = row["id"], row["file_path"], row["file_hash"]
            if not fhash and os.path.exists(fpath):
                try:
                    hasher = hashlib.sha256()
                    with open(fpath, 'rb') as f:
                        while chunk := f.read(65536):
                            hasher.update(chunk)
                    fhash = hasher.hexdigest()
                    hash_updates.append((fhash, fid))
                    row["file_hash"] = fhash
                except (PermissionError, OSError):
                    continue

            if fhash:
                hash_groups.setdefault(fhash, []).append(row)

        if hash_updates:
            with self.db.session() as conn:
                with conn:
                    conn.executemany("UPDATE files SET file_hash = ? WHERE id = ?", hash_updates)

        return {h: files for h, files in hash_groups.items() if len(files) > 1}

    def clear_database(self) -> Tuple[bool, str]:
        """全量重置数据库后，自动依据 data/asset_security_levels.json 自愈重灌安全等级"""
        try:
            with self.db.session() as conn:
                with conn:
                    conn.execute("DROP TABLE IF EXISTS files_fts;")
                    conn.execute("DROP TABLE IF EXISTS file_tags;")
                    conn.execute("DROP TABLE IF EXISTS files;")
                    conn.execute("DROP TABLE IF EXISTS operation_journal;")
                    conn.execute("DROP TABLE IF EXISTS audit_logs;")

            self.db._init_db()
            try:
                if self.vdb.table_name in self.vdb.db.table_names():
                    self.vdb.db.drop_table(self.vdb.table_name)
                self.vdb._init_tables()
            except Exception as e:
                logger.warning(f"清空 LanceDB 表告警: {e}")

            # 核心自愈重灌：从 data/ 备份文件对安全等级自动恢复标注
            self.reseed_security_levels()
            return True, "数据库、倒排表、向量库及操作流水已全量重置，并已成功依据灾备清单自愈恢复安全等级。"
        except Exception as e:
            return False, f"重置失败: {str(e)}"

    def get_storage_insights(self) -> Dict[str, Any]:
        with self.db.session() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_extension, COUNT(*) as count, SUM(file_size) as total_size 
                FROM files WHERE is_deleted = 0 AND is_dir = 0
                GROUP BY file_extension 
                ORDER BY total_size DESC LIMIT 10
            ''')
            ext_stats = [dict(row) for row in cursor.fetchall()]

            cursor.execute('''
                SELECT id, file_name, file_path, file_size 
                FROM files WHERE is_deleted = 0 AND is_dir = 0
                ORDER BY file_size DESC LIMIT 10
            ''')
            large_files = [dict(row) for row in cursor.fetchall()]

        return {"extension_stats": ext_stats, "largest_files": large_files}