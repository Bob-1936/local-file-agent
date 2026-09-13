# Local File Agent (本地文件智能管理助手 - 2026 Web)

`Local File Agent (Web Edition)` 是一套基于 **LangGraph 异步图状态机** 与现代化轻量响应式 Web 技术栈构建的工业级本地资产智能体系统。系统深度集成本地关系型数据库（**SQLite3 WAL + FTS5 倒排索引**）、嵌入式向量检索引擎（**LanceDB + Arrow**）以及全生态大语言模型（**DeepSeek / OpenAI / Claude / Gemini / Ollama / 本地兼容端点**）。

系统采用“**宏观全景树状模式聚类压缩**”与“**微观多路混合检索 (RRF)**”双轨架构，支持 **15 大全功能本地资产工具套件**。本次重大工业级重构彻底解决并落地了 **AI 自主安全等级调整与升降级密码防护**、**AI 文件与文件夹路径自愈重命名**、**三级资产安全等级单例防护与热重载**、**跨目录移动全员真降级与数据库联动**、**原地操作自愈反馈**、**全工具覆盖冲突免密换名 vs 高危密码覆盖**、**脱离 Agent 的原生原子撤销 (Undo Stack)**、**5 维物理安全预检** 以及 **Web 控制面板防折行样式加固**，确保达到生产级的稳定鲁棒性与绝对的物理数据安全。

---

## 目录
- [架构演进与核心特性](#架构演进与核心特性)
- [完整项目目录图谱](#完整项目目录图谱)
- [文件职责与功能矩阵](#文件职责与功能矩阵)
- [关键技术机制深度剖析](#关键技术机制深度剖析)
  - [1. 三级资产安全防护与 AI 自主设级 (Security Levels)](#1-三级资产安全防护与-ai-自主设级-security-levels)
  - [2. AI 智能自愈重命名机制 (文件/目录双轨适配)](#2-ai-智能自愈重命名机制-文件目录双轨适配)
  - [3. 跨目录移动“全员降级”真实生效机制](#3-跨目录移动全员降级真实生效机制)
  - [4. 原地移动自愈反馈 (根治模型试错重试)](#4-原地移动自愈反馈-根治模型试错重试)
  - [5. 5 维危险操作物理预检引擎 (Pre-check Engine)](#5-5-维危险操作物理预检引擎-pre-check-engine)
  - [6. 覆盖与命名冲突严格阻断：免密更名 vs 高危密码覆盖](#6-覆盖与命名冲突严格阻断免密更名-vs-高危密码覆盖)
  - [7. 脱离 Agent 的原生原子撤销与生命周期隔离 (Undo Stack)](#7-脱离-agent-的原生原子撤销与生命周期隔离-undo-stack)
  - [8. 全生命周期操作审计日志 (Operation Audit Logs)](#8-全生命周期操作审计日志-operation-audit-logs)
- [15 大强类型工具契约矩阵](#15-大强类型工具契约矩阵)
- [快速启动与部署说明](#快速启动与部署说明)
- [技术栈与环境依赖](#技术栈与环境依赖)

---

## 架构演进与核心特性

对比传统的脚本式 Agent 与桌面管理工具，本系统实现了十一项工业级技术演进：

1. **AI 自主资产安全等级调整（`set_security_level`）与升降级严谨拦截**：
   赋予大模型直接调整特定文件或文件夹安全级别（1普通/2敏感/3机密）的能力。
   * **升级防护**：调整至 3 级（机密）时，切面网关强制定级为破坏性高危动作，**强制验证主管理密码**；
   * **降级警报**：当试图将 2/3 级资产降低安全等级时，系统主动挂起并弹出“全员安全降级警报”，原 3 级降级必须输入主密码确认；
   * **继承清理**：文件夹设为 2/3 级后，底层自动将下属所有已显式打标的子项重置为 1 级（统一由父级动态继承）；
   * **可撤销自愈**：操作自动写入流水，支持原生点击“↩ 撤销”恢复到修改前的安全等级。
2. **AI 文件与文件夹路径自愈重命名（`rename_file`）彻底解脱 ID 束缚**：
   彻底重构了传统工具必须传入整型 `file_id` 的痛点。大模型可直接传相对路径、绝对路径或名称（`file_path`）。若目标文件或文件夹尚未被数据库索引，系统执行**未入库自动即时建索**自愈补齐 ID，无缝支持物理重命名、同名冲突前置挂起、撤销逆向回转以及灾备映射自动重绑定。
3. **三级资产安全等级全局单例与热感知（彻底根除实例孤岛）**：
   在 `core/security.py` 中将 `AssetSecurityManager` 构建为进程级单例（`AssetSecurityManager.get_instance`），搭载基于文件修改时间（`mtime`）的热重载引擎。无论前端在 Web 面板上批量打标、AI 在后台调工具，还是安全网关切面校验，始终读取同一份绝对同步的内存缓存。
4. **跨目录移动“全员降级”真抹标与数据库同步**：
   严格落实业务规范——“**资产移入低安全级别目录后，所有文件一同降级**”。当用户在弹窗中批准降级并输入密码后，底层从灾备清单中彻底抹除原有高等级显式标记，并级联更新 SQLite 数据库中的 `files.security_level`。
5. **原地移动自愈反馈（根除模型反复试错）**：
   当 Agent 发起原地移动（`src_path == dest_path`）时，底层不再静默 `continue` 返回空结果，而是主动向 Agent 明确返回“资产已在目标目录下，无需移动（原地保持成功）”，模型立刻获知状态并自然收敛。
6. **前端资产管理面板防折行样式加固**：
   全面修复 CSS 自适应排版缺陷。关键列（标记来源、安全等级 Badge、操作按钮）增加 `whitespace-nowrap`、`min-w` 以及徽章的 `inline-flex shrink-0` 保护，文字与彩色徽章绝不折行成垂直竖排。
7. **Windows 全平台路径大小写自适应归一化**：
   针对 Windows 环境下的盘符大小写（`C:\` vs `c:\`）和斜杠混用隐患，底层采用跨平台 `os.path.normcase` 规范化，灾备字典采用不区分大小写的键值容错查找。
8. **5 维危险操作物理预检引擎 (Pre-check Engine)**：
   在任何涉及磁盘变动的操作触碰物理介质前，自动执行 5 维预检：**磁盘空间余量探测（低阈值熔断）**、**Zip Slip 恶意路径穿越拦截**、**压缩炸弹防御（膨胀比/文件数/释放体积三重硬顶）**、**符号链接逃逸拦截** 以及 **目标覆盖冲突探测**。
9. **凡覆盖皆危险：免密换名 vs 高危密码覆盖**：
   * **更换名称**：常规安全操作，弹窗提供新文件名输入框，**免密放行继续执行**；
   * **覆盖替换**：凡导致已有文件被抹除覆盖的操作，**统一定级为破坏性高危动作，强制验证主管理密码**；
   * **前置挂起拦截**：覆盖 `move_file`、`copy_file`、`write_file`、`extract_archive` 与 `rename_file`，在触碰磁盘前强行挂起呼出 Web 模态框。
10. **脱离 Agent 的原生原子撤销（Undo Stack，带互斥锁与生命周期隔离）**：
    用户点击顶栏“↩ 撤销上一步”时，**完全不经过大模型与 LangGraph 图调度，直接由后端读取本地物理流水执行原子反转**。
    * **覆盖备份自愈**：覆盖发生前在 `.local_agent_undo_backups` 产生快照，撤销时原样无损还原；
    * **逆向级联恢复**：支持移动还原、重命名改回原名、解压清理、打包删除以及安全等级回滚；
    * **生命周期隔离**：服务重启时自动清空操作流水栈，绝不跨会话误撤回历史文件。
11. **全生命周期合规操作审计日志 (`audit_logs`)**：
    SQLite 独立持久化存储 `audit_logs` 表，全屏看板实时查阅，记录操作人、时间、动作、等级、涉及资产与明细。

---

## 完整项目目录图谱

```text
Agent/
│
├── config/                          # [配置持久层] 运行时配置、独立安全策略与凭证
│   ├── API_config.json              # 大模型多 Profile 配置（设备指纹混淆密文存储）
│   ├── config.json                  # 主程序运行配置（工作区根目录、深度、黑名单、Token阈值、密码哈希）
│   ├── fast_chat.json               # 快捷指令预设定义
│   └── security_policy.json         # 【核心解耦】15 大工具声明式安全策略、动态规则、别名与细粒度豁免表
│
├── core/                            # [核心系统层] 图内核编排、存储中枢与安全机制
│   ├── agent_graph_web.py           # Web 异步 LangGraph 图状态机、批处理短路节点、思考流解析
│   ├── indexer_engine.py            # SQLite3 WAL + FTS5 与 LanceDB 双库引擎；流水表、审计表与重命名核心
│   ├── model_factory.py             # 统一模型工厂：OpenAI/DeepSeek/Claude/Gemini 原生参数清洗与代理端点处理
│   ├── security.py                  # 【单例重构】安全管控中枢、AssetSecurityManager 全局单例、mtime热感知、全员降级抹标、5 维危险预检
│   └── tokenizer.py                 # 本地离线多平台 Token 计数器（适配 OpenAI 与 Gemini 拟合算法）
│
├── data/                            # [数据持久层] 索引库、向量表、宏观扫描快照与常驻资料
│   ├── asset_security_levels.json   # 【核心灾备】非 1 级资产显式等级独立清单 (相对路径持久化，冷启动自愈)
│   ├── database/                    # SQLite 关系型数据库目录 (file_indexer.db)
│   ├── lancedb/                     # LanceDB 本地向量表目录
│   └── scan/                        # 磁盘物理扫描原始 JSON 快照与聚类压缩 Markdown 地图
│
├── tools/                           # [业务工具层] 强类型契约工具与提示词装配
│   ├── agent_tools_web.py           # Web 强契约工具工厂：全量 15 大工具统一切面拦截、Pydantic Schema 约束
│   ├── file_manager_tool.py         # 【核心自愈】AI重命名路径自愈、AI调整安全等级、原地移动反馈、降级抹标、原子撤销
│   ├── prompt_manager.py            # 提示词上下文与会话事务管理器（深拷贝快照回滚、工作区物理锚定、边界截断）
│   ├── scan_indexer.py              # 地图聚类压缩引擎：数字模式诱导、两阶段深度压缩、兄弟目录聚合
│   └── scanner.py                   # 磁盘物理扫描器：分层时间切片（80/10/10 策略）、目录预算熔断与死循环检测
│
├── web/                             # [界面表现层] 现代响应式前端（免构建、零依赖）
│   ├── vendor/                      # 本地离线第三方静态库 (Tailwind, Vue, Lucide, Highlight, Markdown-it)
│   ├── app.js                       # Vue 3 核心驱动：SSE 流式拼装、撤销状态探针置灰、互斥锁定、HITL 冲突与密码核验
│   └── index.html                   # 【排版加固】资产管理面板防折行修复、深浅色自适应、审计日志看板、HITL 冲突与鉴权模态框
│
├── run_web.py                       # 【程序总启动入口】可用端口自增探测、浏览器延迟拉起与 Uvicorn 引导
└── server.py                        # 【API 与服务总调度】FastAPI 后端、单例注入、升降级与重命名切面拦截、HITL 鉴权
```

---

## 文件职责与功能矩阵

### 1. 服务调度与启动入口

| 文件名 | 模块归属 | 核心职责说明 |
| :--- | :---: | :--- |
| **`run_web.py`** | 启动入口 | 自动在 `[9000, 9050)` 区间探测未占用端口；服务就绪后后台子线程延迟 1.2 秒自动拉起系统默认浏览器；引导运行 `uvicorn.run("server:app")`。 |
| **`server.py`** | 服务核心 | FastAPI 后端调度；全局单例绑定；**接入 `set_security_level` 升降级切面拦截与主密码核验**；**重构 `rename_file` 路径冲突前置挂起**；提供原生撤销端点 (`POST /api/fs/undo`) 与状态探针；审计日志查询。 |

---

### 2. `core/` 核心图引擎、持久化与安全中枢

| 文件名 | 模块归属 | 核心职责说明 |
| :--- | :---: | :--- |
| **`security.py`** | 安全中枢 | **`AssetSecurityManager` 进程级全局单例**，搭载 `_check_and_reload` 磁盘变动热重载；**跨目录降级全员抹标机制 (`handle_transfer_security_levels`)**；全平台 Windows 路径大小写归一化；PBKDF2 加盐散列；**5 维危险预检引擎**。 |
| **`indexer_engine.py`** | 数据引擎 | 管理 SQLite3 WAL 模式与 LanceDB 向量表；维护 **`operation_journal`（流水表）** 与 **`audit_logs`（审计表）**；启动清库后依据 `data/asset_security_levels.json` 自动灾备重灌安全等级；**底层物理重命名与子目录级联同步**。 |
| **`agent_graph_web.py`** | 图状态机 | 编译强类型 `WebAgentState` 图；实现 `SafeAsyncToolBatchNode`（前序被拒后续秒级短路阻断）；内置 `WebThinkingStreamParser`（提取 `<think>` 流）与正文 Markdown JSON 容错反解。 |
| **`model_factory.py`** | 模型适配 | 统一构建 OpenAI、DeepSeek、Claude、Gemini 标准实例；自动清洗反向代理与端点协议。 |
| **`tokenizer.py`** | 分词估算 | 本地离线多平台 Token 计数器；适配 OpenAI/DeepSeek (cl100k) 与 Gemini 专用拟合规则。 |

---

### 3. `tools/` 提示词装配与专业工具套件

| 文件名 | 模块归属 | 核心职责说明 |
| :--- | :---: | :--- |
| **`agent_tools_web.py`** | 工具契约 | 采用 Pydantic 严格约束输入 Schema；**扩展至 15 大工具**；**重构 `rename_file` 契约支持路径与 ID**；**新增 `set_security_level` 契约**；全量工具统一切面拦截（`_check_security`）。 |
| **`file_manager_tool.py`** | 资产管理 | **新增 `set_security_level`（物理/数据库/灾备/撤销流水四重联动）**；**重写 `rename_file` 智能自愈解析（支持未入库自愈建索）**；原地移动自愈反馈；移动降级真实抹标；原生原子撤销引擎 (`undo_last_operation`)。 |
| **`prompt_manager.py`** | 提示词与事务 | 动态组装工作区沙箱物理基准；**注入 15 大工具清单、AI 设级原则与重命名规范**；换名免密 vs 覆盖密码原则；会话事务管理（`begin` / `rollback` / `commit`）。 |
| **`scan_indexer.py`** | 聚类压缩 | 分析文件名数字模式诱导归纳正则模板；提供标准与二次深度压缩双模式；相似兄弟目录聚合折叠。 |
| **`scanner.py`** | 物理扫描 | 单目录 3000 项遍历预算熔断与软链接死循环防御；分层时间切片算法极速构建全景文件树。 |

---

### 4. `config/` 策略配置与 `web/` 交互界面

| 文件名 | 模块归属 | 核心职责说明 |
| :--- | :---: | :--- |
| **`security_policy.json`** | 策略配置 | 外部解耦安全规则表。定义 15 大动作的基础风险等级（`base_level`）、操作说明、多语言别名映射（`aliases`）与单工具免确认清单（`tool_exemptions`）。 |
| **`index.html`** | 页面骨架 | 资产安全管理面板排版加固（`whitespace-nowrap`、列宽锁死、杜绝汉字垂直竖排）；顶栏集成【↩ 撤销上一步】与【📋 审计日志】；HITL 模态框清晰分离【更名免密】与【覆盖密码】。 |
| **`app.js`** | 交互驱动 | Vue 3 构建；SSE 流式增量拼装；撤销状态探针与按钮置灰控制；资产管理面板浏览、单选、多选、全选、反选与批量设级。 |

---

## 关键技术机制深度剖析

### 1. 三级资产安全防护与 AI 自主设级 (Security Levels)
系统严格按照三级保护准则运行：
* **1 级（普通，默认）**：常规资产，遵循基础策略；
* **2 级（敏感）**：涉及此类资产的操作强制弹出人机协同窗口进行确认；
* **3 级（机密高危）**：涉及此类资产的操作（查看 `read_file_content`、移动、复制、重命名等）**强制验证主管理密码**；
* **动态继承**：文件夹标记为 2 或 3 级后，其下所有子文件和子目录动态继承该最高等级；
* **AI 自主设级（`set_security_level`）**：
  * **升为 3 级**：必须输入主密码；
  * **降级操作**：弹出全员降级严重警报，原为 3 级降级必须输入主密码；
  * **目录降级子项重置**：目录设级后自动重置子项独立标记；
  * **撤销保护**：设级操作记录入流水，点击顶栏撤销即可无损还原原等级。

```text
[AI / 用户发起 set_security_level] ──► _async_security_intercept
                                              │
                   ┌──────────────────────────┴──────────────────────────┐
                   ▼                                                     ▼
           [目标为 3 级 或 发生降级]                                [设置为 2 级]
                   │                                                     │
                   ▼                                                     ▼
        强制验证主管理密码 / 降级警报                                  弹出确认窗口
                   │                                                     │
                   └──────────────────────────┬──────────────────────────┘
                                              ▼
                             AssetSecurityManager (原子写灾备 JSON)
                                              ▼
                             SQLite files.security_level 级联同步
                                              ▼
                             写入 operation_journal (支持原子撤回)
```

### 2. AI 智能自愈重命名机制 (文件/目录双轨适配)
重写后的 `rename_file` 彻底解决了模型因为没有 `file_id` 导致的执行瘫痪：
1. **参数自适应解析**：参数支持 `file_path` 与 `file_id` 双轨输入。AI 直接传路径即可；
2. **未索引资产即时建索自愈**：若物理存在但库中暂无主键，自动先执行 `index_single_asset_or_tree` 登记入库生成 ID；
3. **同名冲突前置拦截**：在物理变动前预检同名冲突，主动挂起弹出更名窗口，杜绝物理覆盖；
4. **全套索引级联刷新**：物理重命名后，自动级联更新 SQLite 数据库、FTS5 倒排索引、LanceDB 向量库以及安全等级灾备映射。

### 3. 跨目录移动“全员降级”真实生效机制
* **降级探测**：源资产的生效级别高于目标目录的继承级别时触发；
* **弹窗警报**：严重警告“移出后该资产及内部所有文件都会降级”，原为 3 级需验证主密码；
* **物理抹标与数据库同步**：底层执行 `handle_transfer_security_levels(..., is_downgrade=True)`，彻底从灾备清单清除显式标记，并同步更新 SQLite 数据库；
* **撤销自愈**：撤销移动时，逆向移回源路径的同时自动将被抹除的原高级别显式恢复。

### 4. 原地移动自愈反馈 (根治模型试错重试)
当 Agent 发起原地移动（`src_path == dest_path`）时，底层不再静默 `continue` 返回空结果，而是主动向 Agent 返回：
```python
"资产已在目标目录下（路径未改变），无需物理剪切（原地保持成功）"
```
模型接收到确切解答后自然收敛，彻底根除死循环重试。

### 5. 5 维危险操作物理预检引擎 (Pre-check Engine)
在物理资产执行任何变更动作前强制执行：
1. **磁盘空间预检 (`precheck_disk_space`)**：剩余空间 < 500MB 或 预计写入体积 > 可用容量 90% 时直接熔断；
2. **Zip Slip 路径穿越检查**：解压条目规范路径脱离目标沙箱根目录时抛出致命异常阻断；
3. **压缩炸弹检查 (`precheck_zip_bomb`)**：解压体积 > 2GB、膨胀比 > 100:1 或文件数 > 10,000 时直接拒绝解压；
4. **符号链接攻击检查 (`check_symlink_safety`)**：拒绝直接对符号链接进行物理操作；
5. **覆盖冲突检测 (`detect_transfer_conflicts`)**：目标路径已存在同名资产时触发前置挂起拦截。

### 6. 覆盖与命名冲突严格阻断：免密更名 vs 高危密码覆盖
系统将“同名冲突”处理彻底前置到安全拦截层：
1. **全工具前置冲突扫描**：移动、复制、写文件、解压与重命名在触碰磁盘前，若目标路径已存在同名资产，底层直接挂起并推送 `hitl_suspend`（携带 `is_conflict: true`）；
2. **免密更换名称（安全操作）**：用户输入新名称，点击【更名并继续】，系统直接免密放行；
3. **确认覆盖原有文件（高危操作）**：用户执意覆盖，系统判定为破坏性操作（`DESTRUCTIVE`），**强制要求输入主管理密码**；覆盖前在 `.local_agent_undo_backups` 产生安全快照。

### 7. 脱离 Agent 的原生原子撤销与生命周期隔离 (Undo Stack)
用户点击顶栏“↩ 撤销上一步”时，执行纯本地事务回退：
* **无模型介入**：不经过 LLM 与 LangGraph，直接读取 `operation_journal` 流水；
* **覆盖备份自愈**：将被覆盖的原文件从备份目录原样无损还原；
* **多操作反转支持**：剪切移回、复制清理、重命名改回原名、解压删除、打包移除、安全等级回退；
* **生命周期隔离**：服务启动自动清理旧流水栈，避免跨会话误撤回；
* **按钮动态置灰**：通过 `canUndo` 探针实时反馈状态，无记录时禁用按钮；撤回期间全局互斥锁锁定界面。

### 8. 全生命周期操作审计日志 (Operation Audit Logs)
* **独立合规表**：在 SQLite 中独立开辟 `audit_logs` 表长期留存；
* **全要素审计**：字段涵盖 `id`、`timestamp`、`formatted_time`、`operator`、`action_name`、`level`、`target_paths`、`status`、`details`；
* **查看看板**：用户点击顶栏【📋 审计日志】即可呼出全屏表格面板实时查阅。

---

## 15 大强类型工具契约矩阵

全量 15 个工具均接入 Pydantic Schema 约束与 `_check_security` 统一切面，由 `security_policy.json` 统一管控：

| 工具标识 (`name`) | 参数模式 (`args_schema`) | 默认等级 | 动态冲突策略与核心安全机制 |
| :--- | :--- | :---: | :--- |
| **`scan_directory`** | `EmptyInput` | 🟢 `SAFE` | 物理遍历磁盘目录并构建压缩树。旁路挂载至侧边栏临时资料库，增量同步数据库与向量。 |
| **`search_files`** | `SearchFilesInput`<br>• `query`: Optional[str]<br>• `ext`: Optional[str]<br>• `parent_path`: Optional[str]<br>• `min_size_mb`: Optional[float]<br>• `max_size_mb`: Optional[float]<br>• `limit`: Optional[int] | 🟢 `SAFE` | RRF 融合算法（向量语义 + FTS5 全文倒排 + 文件名精确匹配）。支持空 query 属性过滤。 |
| **`read_file_content`** | `ReadFileContentInput`<br>• `file_path`: Optional[str]<br>• `file_id`: Optional[int]<br>• `section`: Optional[str] | 🟢 `SAFE` | 30KB/500 行硬预算保护，支持分段采样。**受资产安全保护：读 2 级弹窗确认，读 3 级机密强制验密码**。 |
| **`delete_file`** | `DeleteFileInput`<br>• `files`: List[str] | 🔴 `DESTRUCTIVE` | **破坏性操作**：强制主密码鉴权；移入系统回收站；**明确提示无法自动撤回，需去系统回收站手动拾回**。 |
| **`move_file`** | `MoveFileInput`<br>• `files`: List[str]<br>• `target_dir`: str<br>• `rename_to`: Optional[str]<br>• `overwrite`: Optional[bool] | 🟡 `SENSITIVE` | 批量剪切；**原地移动自愈反馈**；**跨目录降级全员抹标与数据库同步**；**同名冲突免密换名 vs 密码覆盖**。 |
| **`copy_file`** | `CopyFileInput`<br>• `files`: List[str]<br>• `target_dir`: str<br>• `rename_to`: Optional[str]<br>• `overwrite`: Optional[bool] | 🟢 `SAFE` | 批量复制副本；**受资产安全保护：复制 2/3 级资产弹窗拦截**；**同名冲突免密换名 vs 密码覆盖**。 |
| **`create_directory`** | `CreateDirectoryInput`<br>• `dir_path`: str | 🟢 `SAFE` | 在沙箱内新建目录文件夹；**已存在同名目录时拦截报错**；记录可撤销流水（空目录可撤回删除）。 |
| **`write_file`** | `WriteFileInput`<br>• `file_path`: str<br>• `content`: Optional[str]<br>• `overwrite_name`: Optional[str] | 🟡 `SENSITIVE` | 新建或写入文本文件；**单次 5MB 文本限额保护**；**同名冲突免密换名 vs 密码覆盖**。 |
| **`compress_files`** | `CompressFilesInput`<br>• `files`: List[str]<br>• `output_zip`: str<br>• `rename_to`: Optional[str] | 🟢 `SAFE` | 制作 ZIP 压缩包；磁盘空间预检；**目标 ZIP 存在时拦截换名**；支持撤销删除压缩包。 |
| **`extract_archive`** | `ExtractArchiveInput`<br>• `zip_path`: str<br>• `target_dir`: Optional[str]<br>• `overwrite`: Optional[bool] | 🟡 `SENSITIVE` | 安全解压 ZIP 包；**强制 Zip Slip 防御、压缩炸弹预检与冲突拦截：换名免密，覆盖需主密码**。 |
| **`find_duplicate_files`**| `EmptyInput` | 🟢 `SAFE` | 基于 SHA-256 哈希排查当前工作区已被索引的重复内容文件。 |
| **`get_storage_insights`** | `EmptyInput` | 🟢 `SAFE` | 生成存储空间透视体检报告，输出后缀占用分布与 Top10 巨石文件。 |
| **`rename_file`** | `RenameFileInput`<br>• `new_name`: str<br>• `file_path`: Optional[str]<br>• `file_id`: Optional[Union[int, str]] | 🟡 `SENSITIVE` | **AI 重命名文件/文件夹（支持路径与 ID 智能自愈解析、未入库即时入库）**；**同名冲突前置弹窗拦截换名**；支持撤销还原原名。 |
| **`set_security_level`** | `SetSecurityLevelInput`<br>• `target_level`: int (1/2/3)<br>• `file_path`: Optional[str]<br>• `file_id`: Optional[Union[int, str]] | 🟡 `SENSITIVE` | **AI 调整资产安全等级**；**升至 3 级强验主密码；降级操作触发降级警报且原为 3 级强验主密码**；目录设级自动清理子项；支持撤销回滚。 |
| **`locate_or_open_file`**| `LocateOrOpenFileInput`<br>• `file_id`: Optional[int]<br>• `file_path`: Optional[str]<br>• `action`: str ('locate'/'open') | 🟢 `SAFE` | 在系统资源管理器中高亮定位选中文件，或直接调用系统关联程序打开文件。 |

---

## 快速启动与部署说明

### 1. 环境准备
确保已安装 Python 3.9 或更高版本。安装核心依赖库：
```bash
pip install fastapi uvicorn pydantic \
    langgraph langchain-core langchain-openai langchain-anthropic langchain-google-genai \
    lancedb pyarrow fastembed jieba tiktoken send2trash requests
```
*(可选增强：安装 `python-docx`、`pypdf`、`pillow` 可自动激活 Word 正文、PDF 文档与图片 EXIF 元数据的深度解析)*

### 2. 配置文件说明
项目首次运行若检测到配置文件缺失，系统将自动自愈创建标准模板：
* `config/security_policy.json`：配置各工具风险基线、别名映射与单工具豁免清单；
* `config/config.json`：配置授权工作区物理根路径（`target_path`）、扫描深度、黑名单与管理密码哈希；
* `data/asset_security_levels.json`：非 1 级资产标记清单（系统自动维护与灾备自愈）。

### 3. 一键启动
执行总启动入口脚本：
```bash
python run_web.py
```
* 系统自动探测未占用端口（默认 `9000` 起），引导启动 Uvicorn ASGI 服务；
* 后端启动时自动执行**清空操作流水栈（隔离旧会话）**以及 SQLite / LanceDB 冷启动增量自愈对齐；
* 服务就绪后后台子线程延迟 1.2 秒**自动拉起系统默认浏览器**打开交互控制台。

---

## 技术栈与环境依赖

- **后端运行时**: Python 3.9+
- **服务网关与通信**: **FastAPI**, **Uvicorn**, **Server-Sent Events (SSE)**
- **并发控制与安全锁**: `asyncio.Lock()` (全局撤销互斥), `threading.Event`, `asyncio.Event`
- **Agent 编排框架**: **LangGraph (>= 0.2.0)**, **LangChain Core (>= 0.3.0)**
- **模型生态适配**: `langchain-openai`, `langchain-anthropic`, `langchain-google-genai`
- **数据契约校验**: **Pydantic v2**
- **关系与倒排数据库**: **SQLite3** (开启 WAL 模式 + FTS5 全文倒排索引扩展)
- **嵌入式向量数据库**: **LanceDB (Apache Arrow 数据底座)**
- **向量推理引擎**: **FastEmbed** (`BAAI/bge-small-zh-v1.5`, 纯 CPU 轻量嵌入)
- **物理磁盘操作与预检**: Python `zipfile`, `shutil`, `send2trash`, `unicodedata`
- **分词与 Token 计算**: `tiktoken` (cl100k_base), `jieba` (中文分词), Gemini 拟合算法
- **安全加固与加密**: `hashlib` (PBKDF2-HMAC-SHA256), `secrets`, 机器设备指纹对称混淆
- **安全等级管理**: **AssetSecurityManager (Singleton & Hot-Reload)**
- **安全策略分发**: **Declarative JSON Policy Engine** (`security_policy.json`)
- **前端表现层**: 原生 HTML5, **Vue 3 (Composition API)**, **TailwindCSS**, Lucide Icons, Markdown-it, Highlight.js (**完全无需 Node.js 或 npm 打包构建**)