// web/app.js
// -*- coding: utf-8 -*-

const { createApp, ref, reactive, computed, onMounted, nextTick } = Vue;

createApp({
  setup() {
    const mdParser = window.markdownit({
      html: false,
      linkify: true,
      typographer: true,
      highlight: function (str, lang) {
        if (lang && hljs.getLanguage(lang)) {
          try {
            return hljs.highlight(str, { language: lang }).value;
          } catch (__) {}
        }
        return '';
      }
    });

    const isDarkMode = ref(true);
    const platformPresets = ref({});

    const state = reactive({
      app_config: {},
      theme: 'dark',
      api_profiles: {},
      current_api_profile: '',
      current_model_tag: '',
      fast_chats: [],
      has_password: false,
      system_prompt: '',
      system_tokens: 0,
      history_count: 0,
      history_tokens: 0,
      total_tokens: 0,
      persistent_prompts: [],
      temp_prompts: []
    });

    // 空对话时的开场白。
    // 【为什么要在前端兜底】它并不是聊天记录的一部分（后端不知道它），
    // 而每次启动都会开一份新对话，窗口为空 → 界面若只按后端重建就会一片空白，
    // Agent 的自我介绍就没了。
    const WELCOME_MESSAGE = {
      role: 'assistant',
      content: '你好！我是基于 **LangGraph 工业级图状态机** 驱动的本地资产智能管理 Agent。\n系统已搭载 **三级资产安全防护引擎**，支持文件夹动态等级继承、操作提醒、主密码高危防护与降级预警。',
      thought: '',
      thinkExpanded: false,
      tool_calls: []
    };

    const messages = ref([{ ...WELCOME_MESSAGE }]);

    const inputMessage = ref('');
    const attachedFile = ref(null);
    const isStreaming = ref(false);
    // 【收尾中】点了中止之后、服务端确认"上一回合收尾完成"之前：
    // 按钮显示为加载图标且点不动，输入框可以打字但**发不出去**。
    const isFinalizing = ref(false);
    // 对话记录的窗口状态：更早还有多少条没有载入内存（滚动到顶时提示）
    const historyWindow = reactive({ dropped: 0, total_messages: 0, in_window: 0, size_bytes: 0, window_rounds: 0 });
    const isUndoing = ref(false);
    const canUndo = ref(false);
    const isSyncingDb = ref(false);
    const isEstimating = ref(false);
    const isFetchingModels = ref(false);
    const isBrowsingDir = ref(false);
    const isRescanningPersistent = ref(false);
    const isPasswordGuideMode = ref(false);
    const estimateResult = ref(null);
    const availableModels = ref([]);
    const auditLogs = ref([]);
    const chatContainer = ref(null);
    const messageInputRef = ref(null);
    let currentAbortController = null;

    // ==================== 资产安全等级管理器状态 ====================
    const securityAssetsList = ref([]);
    const selectedAssetPaths = ref(new Set());
    const currentBrowseDir = ref('');
    const isLoadingAssets = ref(false);
    const isUpdatingSecurityLevels = ref(false);

    const modals = reactive({
      api: false,
      scan_config: false,
      fast_chat: false,
      edit_sys_prompt: false,
      add_temp_prompt: false,
      edit_temp_prompt: false,
      password: false,
      audit_log: false,
      security_levels: false
    });

    // 批量/单项设级的密码凭证（涉及 3 级机密时后端强制校验，前端不缓存、不落 localStorage）
    const securityPassword = ref('');
    const securityPending = reactive({ need: false, target_level: 1 });

    const permSkipWarning = reactive({
      visible: false,
      targetKey: '',
      level_name: ''
    });

    const formApi = reactive({
      name: '',
      platform: 'DeepSeek',
      url: '',
      key: '',
      selected_model: '',
      cached_models: []
    });

    const formScan = reactive({
      target_path: '',
      max_depth: 3,
      blacklist_str: '',
      tool_token_warning_threshold: 10000,
      permanent_skip_sensitive: false,
      permanent_skip_destructive: false,
      // 对话记录：内存窗口轮数、记录体积告警阈值（MB）
      chat_history_window_rounds: 50,
      chat_log_size_warn_mb: 100
    });

    // 对话记录管理（审计面板）
    const chatLogs = ref([]);
    const chatLogDir = ref('');
    const isLoadingChatLogs = ref(false);

    const formPassword = reactive({ old_password: '', new_password: '', confirm_password: '' });
    const formFastChats = ref([]);
    const tempSysPrompt = ref('');
    const formTempPrompt = reactive({ title: '', content: '' });
    const formEditTempPrompt = reactive({ prompt_id: '', title: '', content: '' });

    const hitlModal = reactive({
      visible: false,
      session_id: 'default',
      action_name: '',
      reason: '',
      level: 'SENSITIVE',
      params: {},
      items_meta: [],
      password: '',
      skipThisSession: false,
      is_conflict: false,
      is_downgrade: false,
      max_asset_level: 1,
      new_name: ''
    });

    const hitlAssetAnalysis = computed(() => {
      const p = hitlModal.params || {};
      const meta = hitlModal.items_meta || [];
      let itemsList = [];

      if (meta && meta.length > 0) {
        itemsList = meta.map(m => ({
          path: String(m.path).replace(/\\/g, '/'),
          is_dir: !!m.is_dir,
          security_level: m.security_level || 1
        }));
      } else {
        const raw = p.files || p.file_path || p.output_zip || p.dir_path || [];
        const files = Array.isArray(raw) ? raw.map(String) : [String(raw)].filter(Boolean);
        itemsList = files.map(f => ({
          path: f.replace(/\\/g, '/'),
          is_dir: f.endsWith('/'),
          security_level: 1
        }));
      }

      return {
        items: itemsList.map(item => ({
          name: item.path.split('/').pop() || item.path,
          is_dir: item.is_dir,
          security_level: item.security_level
        }))
      };
    });

    const isAllCurrentSelected = computed(() => {
      if (securityAssetsList.value.length === 0) return false;
      return securityAssetsList.value.every(item => selectedAssetPaths.value.has(item.rel_path));
    });

    const scrollToBottom = async () => {
      await nextTick();
      if (chatContainer.value) {
        chatContainer.value.scrollTop = chatContainer.value.scrollHeight;
      }
      lucide.createIcons();
    };

    const renderMarkdown = (text) => {
      if (!text) return '';
      return mdParser.render(text);
    };

    const formatTokens = (tokens) => {
      if (!tokens) return '0';
      return Number(tokens).toLocaleString();
    };

    // ==================== 主题与防闪烁联动 ====================
    const applyTheme = (themeName) => {
      isDarkMode.value = (themeName === 'dark');
      if (isDarkMode.value) {
        document.documentElement.classList.add('dark');
      } else {
        document.documentElement.classList.remove('dark');
      }
      try {
        localStorage.setItem('app_theme', themeName);
      } catch (e) {}
    };

    const toggleTheme = async () => {
      const newTheme = isDarkMode.value ? 'light' : 'dark';
      applyTheme(newTheme);
      state.theme = newTheme;
      try {
        await fetch('/api/config/theme', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ theme: newTheme })
        });
      } catch (e) {
        console.error('保存主题失败:', e);
      }
    };

    const loadPresets = async () => {
      try {
        const res = await fetch('/api/config/api/presets');
        const data = await res.json();
        if (data.success) {
          platformPresets.value = data.presets || {};
        }
      } catch (e) {
        console.error('获取厂商预设失败:', e);
      }
    };

    const checkUndoStatus = async () => {
      try {
        const res = await fetch('/api/fs/undo_status?session_id=default');
        const data = await res.json();
        if (data.success) {
          canUndo.value = !!data.can_undo;
        }
      } catch (e) {
        canUndo.value = false;
      }
    };

    const refreshConfigs = async () => {
      try {
        const res = await fetch('/api/config/init?session_id=default');
        const data = await res.json();
        state.app_config = data.app_config || {};
        state.theme = data.theme || 'dark';
        applyTheme(state.theme);

        state.api_profiles = data.api_profiles || {};
        state.current_api_profile = data.current_api_profile || '';
        state.fast_chats = data.fast_chats || [];
        state.has_password = data.has_password || false;
        canUndo.value = !!data.can_undo;
        state.system_prompt = data.system_prompt || '';
        state.system_tokens = data.system_tokens || 0;
        state.history_count = data.history_count || 0;
        state.history_tokens = data.history_tokens || 0;
        state.total_tokens = data.total_tokens || 0;
        state.persistent_prompts = data.persistent_prompts || [];
        state.temp_prompts = data.temp_prompts || [];

        if (state.current_api_profile && state.api_profiles[state.current_api_profile]) {
          const prof = state.api_profiles[state.current_api_profile];
          state.current_model_tag = `${prof.platform} (${prof.selected_model})`;
        } else {
          state.current_model_tag = '未指定模型';
        }
        await nextTick();
        lucide.createIcons();
      } catch (e) {
        console.error('初始化配置失败:', e);
      }
    };

    const switchProfile = async () => {
      if (!state.current_api_profile) return;
      await fetch(`/api/config/api/switch?profile_name=${encodeURIComponent(state.current_api_profile)}`, { method: 'POST' });
      await refreshConfigs();
    };

    const onPlatformChange = () => {
      const p = formApi.platform;
      const preset = platformPresets.value[p];
      if (preset && p !== '自定义端点 (高级)') {
        formApi.url = preset.url || '';
      }
      if (!formApi.name.trim() || formApi.name.startsWith('我的_')) {
        formApi.name = `我的_${p}`;
      }
      availableModels.value = [];
    };

    const fetchOnlineModels = async () => {
      if (!formApi.key.trim() && !formApi.name) {
        alert('请先填入 API Key！');
        return;
      }
      isFetchingModels.value = true;
      try {
        const res = await fetch('/api/models/fetch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            platform: formApi.platform,
            url: formApi.url.trim(),
            key: formApi.key.trim(),
            profile_name: formApi.name.trim()
          })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          availableModels.value = data.models || [];
          if (availableModels.value.length > 0 && !formApi.selected_model) {
            formApi.selected_model = availableModels.value[0];
          }
          alert(`成功拉取到 ${availableModels.value.length} 个可用模型！`);
        } else {
          alert(data.detail || '拉取模型失败，请检查端点与 Key');
        }
      } catch (e) {
        alert('拉取模型异常: ' + e.message);
      } finally {
        isFetchingModels.value = false;
        await nextTick();
        lucide.createIcons();
      }
    };

    const browseDirectory = async () => {
      isBrowsingDir.value = true;
      try {
        const res = await fetch('/api/utils/browse_dir', { method: 'POST' });
        const data = await res.json();
        if (data.success && data.path) {
          formScan.target_path = data.path;
        }
      } catch (e) {
        alert('呼出本地目录选择器失败: ' + e.message);
      } finally {
        isBrowsingDir.value = false;
      }
    };

    // ==================== API Profile 切换与安全删除 ====================
    const selectProfileToEdit = (profileName) => {
      if (!profileName) {
        formApi.name = `我的_${formApi.platform}`;
        formApi.key = '';
        formApi.selected_model = '';
        availableModels.value = [];
        return;
      }
      const target = state.api_profiles[profileName];
      if (target) {
        formApi.name = profileName;
        formApi.platform = target.platform || 'DeepSeek';
        formApi.url = target.url || '';
        formApi.key = '';
        formApi.selected_model = target.selected_model || '';
        formApi.cached_models = target.cached_models || [];
        availableModels.value = formApi.cached_models.length > 0 ? formApi.cached_models : [];
      }
    };

    const deleteApiProfile = async (profileName) => {
      const targetName = profileName || formApi.name;
      if (!targetName) return;

      if (!confirm(`确定要彻底删除 API 配置【${targetName}】吗？此操作无法撤销。`)) {
        return;
      }

      try {
        const res = await fetch(`/api/config/api/${encodeURIComponent(targetName)}`, {
          method: 'DELETE'
        });
        const data = await res.json();
        if (res.ok && data.success) {
          await refreshConfigs();
          const remaining = Object.keys(state.api_profiles);
          if (remaining.length > 0) {
            selectProfileToEdit(remaining[0]);
          } else {
            selectProfileToEdit('');
          }
          alert(data.message || '配置已成功删除');
        } else {
          alert(data.detail || '删除配置失败');
        }
      } catch (e) {
        alert('删除配置发生网络异常: ' + e.message);
      }
    };

    const openModal = async (name) => {
      if (name === 'api') {
        const curr = state.api_profiles[state.current_api_profile] || {};
        formApi.name = state.current_api_profile || '';
        formApi.platform = curr.platform || 'DeepSeek';
        formApi.url = curr.url || '';
        formApi.key = '';
        formApi.selected_model = curr.selected_model || '';
        formApi.cached_models = curr.cached_models || [];
        availableModels.value = formApi.cached_models.length > 0 ? formApi.cached_models : [];
      } else if (name === 'scan_config') {
        formScan.target_path = state.app_config.target_path || '';
        formScan.max_depth = state.app_config.max_depth || 3;
        formScan.tool_token_warning_threshold = state.app_config.tool_token_warning_threshold || 10000;
        formScan.blacklist_str = (state.app_config.blacklist_paths || []).join('\n');
        formScan.chat_history_window_rounds = state.app_config.chat_history_window_rounds || 50;
        formScan.chat_log_size_warn_mb = state.app_config.chat_log_size_warn_mb || 100;
        const sec = state.app_config.security || {};
        formScan.permanent_skip_sensitive = !!sec.permanent_skip_sensitive;
        formScan.permanent_skip_destructive = !!sec.permanent_skip_destructive;
        estimateResult.value = null;
      } else if (name === 'fast_chat') {
        formFastChats.value = JSON.parse(JSON.stringify(state.fast_chats));
      } else if (name === 'edit_sys_prompt') {
        tempSysPrompt.value = state.system_prompt;
      } else if (name === 'add_temp_prompt') {
        formTempPrompt.title = `临时规则_${state.temp_prompts.length + 1}`;
        formTempPrompt.content = '';
      } else if (name === 'audit_log') {
        await fetchAuditLogs();
        await fetchChatLogs();
      }
      modals[name] = true;
      nextTick(() => lucide.createIcons());
    };

    const closeModal = (name) => {
      modals[name] = false;
      if (name === 'password') {
        isPasswordGuideMode.value = false;
      }
    };

    // 【BUG-F4 修复】统一的保存类请求包装：绝不忽略 HTTP 失败。
    // 过去这些函数不检查 res.ok，用户改错路径/清空深度后弹窗照常关闭、配置实际未生效。
    const saveRequest = async (url, options, label) => {
      try {
        const res = await fetch(url, options);
        let data = null;
        try { data = await res.json(); } catch (e) { data = null; }
        if (!res.ok || (data && data.success === false)) {
          const detail = (data && (data.detail || data.message)) || `HTTP ${res.status}`;
          alert(`❌ ${label}失败：${detail}`);
          return false;
        }
        return true;
      } catch (e) {
        alert(`❌ ${label}异常：${e.message}`);
        return false;
      }
    };

    // ==================== 资产安全等级管理逻辑 ====================
    const openSecurityLevelsModal = async () => {
      selectedAssetPaths.value = new Set();
      selectedAssetItems.clear();
      securityPassword.value = '';
      securityPending.need = false;
      currentBrowseDir.value = '';
      modals.security_levels = true;
      await loadAssetBrowseDir('');
    };

    const loadAssetBrowseDir = async (relDir = '') => {
      isLoadingAssets.value = true;
      try {
        const url = `/api/fs/browse_assets?session_id=default&rel_dir=${encodeURIComponent(relDir)}`;
        const res = await fetch(url);
        const data = await res.json();
        if (data.success) {
          currentBrowseDir.value = data.current_rel_dir || '';
          securityAssetsList.value = data.entries || [];
        } else {
          alert(data.detail || '读取工作区资产失败');
        }
      } catch (e) {
        alert('读取资产异常: ' + e.message);
      } finally {
        isLoadingAssets.value = false;
        await nextTick();
        lucide.createIcons();
      }
    };

    const navigateParentAssetDir = async () => {
      if (!currentBrowseDir.value) return;
      const parts = currentBrowseDir.value.split('/');
      parts.pop();
      const parentRel = parts.join('/');
      await loadAssetBrowseDir(parentRel);
    };

    // 选择集同时缓存"资产对象"：这样跨目录勾选后依然拿得到真实的 abs_path（BUG-F2 修复所需）
    const selectedAssetItems = new Map();

    const toggleAssetSelection = (item) => {
      const p = item.rel_path;
      if (selectedAssetPaths.value.has(p)) {
        selectedAssetPaths.value.delete(p);
        selectedAssetItems.delete(p);
      } else {
        selectedAssetPaths.value.add(p);
        selectedAssetItems.set(p, item);
      }
    };

    const selectAllAssets = () => {
      securityAssetsList.value.forEach(item => {
        selectedAssetPaths.value.add(item.rel_path);
        selectedAssetItems.set(item.rel_path, item);
      });
    };

    const invertSelectAssets = () => {
      securityAssetsList.value.forEach(item => {
        if (selectedAssetPaths.value.has(item.rel_path)) {
          selectedAssetPaths.value.delete(item.rel_path);
          selectedAssetItems.delete(item.rel_path);
        } else {
          selectedAssetPaths.value.add(item.rel_path);
          selectedAssetItems.set(item.rel_path, item);
        }
      });
    };

    const clearAssetSelection = () => {
      selectedAssetPaths.value.clear();
      selectedAssetItems.clear();
    };

    const toggleSelectAllCurrent = () => {
      if (isAllCurrentSelected.value) {
        securityAssetsList.value.forEach(item => {
          selectedAssetPaths.value.delete(item.rel_path);
          selectedAssetItems.delete(item.rel_path);
        });
      } else {
        securityAssetsList.value.forEach(item => {
          selectedAssetPaths.value.add(item.rel_path);
          selectedAssetItems.set(item.rel_path, item);
        });
      }
    };

    // 统一提交入口：把"跨目录选择集"与"机密密码"一次性处理干净
    const submitSecurityLevels = async (itemsPayload, targetLevel, onSuccess) => {
      try {
        const res = await fetch('/api/security/levels/update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            session_id: 'default',
            items: itemsPayload,
            target_level: targetLevel,
            password: securityPassword.value
          })
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok && data.success) {
          securityPassword.value = '';
          securityPending.need = false;
          if (onSuccess) await onSuccess(data);
        } else if (res.status === 428) {
          alert(data.detail || '请先设置主管理密码');
          openPasswordModal(true);
        } else if (res.status === 403) {
          alert(data.detail || '主管理密码验证失败');
          securityPending.need = true;
        } else {
          alert(data.detail || '更新失败');
        }
      } catch (e) {
        alert('调用批量更新等级异常: ' + e.message);
      }
    };

    const applyBatchSecurityLevel = async (targetLevel) => {
      if (selectedAssetPaths.value.size === 0) return alert('请先勾选需要设置安全等级的资产！');

      if (targetLevel === 3 && !state.has_password) {
        alert('将资产设为 3 级（机密）前，系统强制要求先设置主管理密码！');
        openPasswordModal(true);
        return;
      }

      // 【BUG-F2 修复】载荷必须基于"全局选择集"，而不是只从当前目录列表里筛：
      // 之前跨目录勾选后提交 items=[]，后端"成功更新 0 项"，用户却以为设置成功了。
      const itemsPayload = [];
      for (const relPath of selectedAssetPaths.value) {
        const hit = securityAssetsList.value.find(it => it.rel_path === relPath) || selectedAssetItems.get(relPath);
        if (hit && hit.abs_path) {
          itemsPayload.push({ path: hit.abs_path, is_dir: !!hit.is_dir });
        }
      }

      if (itemsPayload.length === 0) {
        return alert('当前选择集中没有可提交的资产，请重新勾选。');
      }
      if (itemsPayload.length < selectedAssetPaths.value.size) {
        alert(`提示：已勾选 ${selectedAssetPaths.value.size} 项，其中 ${itemsPayload.length} 项可提交（其余缺少绝对路径，请重新勾选）。`);
      }

      const hasCritical = securityAssetsList.value.some(
        it => selectedAssetPaths.value.has(it.rel_path) && it.effective_level === 3);
      securityPending.target_level = targetLevel;
      if ((targetLevel === 3 || hasCritical) && !securityPassword.value.trim()) {
        securityPending.need = true;
        return alert('本次操作涉及 3 级（机密）资产：请输入主管理密码后再次点击确认。');
      }

      isUpdatingSecurityLevels.value = true;
      try {
        await submitSecurityLevels(itemsPayload, targetLevel, async (data) => {
          alert(data.message || '安全等级更新完成');
          selectedAssetPaths.value.clear();
          selectedAssetItems.clear();
          securityPending.need = false;
          await loadAssetBrowseDir(currentBrowseDir.value);
        });
      } finally {
        isUpdatingSecurityLevels.value = false;
      }
    };

    const onSingleAssetLevelChange = async (item, event) => {
      const newLvl = parseInt(event.target.value, 10);
      if (newLvl === 3 && !state.has_password) {
        event.target.value = item.explicit_level;
        alert('将资产设为 3 级（机密）前，系统强制要求先设置主管理密码！');
        openPasswordModal(true);
        return;
      }

      // 涉及 3 级（升为 3 级 / 从 3 级降级）时必须先拿到主密码
      const touchesCritical = (newLvl === 3 || item.effective_level === 3);
      if (touchesCritical && !securityPassword.value.trim()) {
        event.target.value = item.explicit_level;
        securityPending.need = true;
        securityPending.target_level = newLvl;
        return alert('该资产涉及 3 级（机密）保护：请先在下方输入主管理密码，再重新选择等级。');
      }

      const itemsPayload = [{ path: item.abs_path, is_dir: item.is_dir }];
      let ok = false;
      await submitSecurityLevels(itemsPayload, newLvl, async () => {
        ok = true;
        await loadAssetBrowseDir(currentBrowseDir.value);
      });
      if (!ok) event.target.value = item.explicit_level;
    };

    // ==================== 原生原子撤销操作 ====================
    const triggerUndo = async () => {
      if (!canUndo.value || isUndoing.value || isStreaming.value) return;
      isUndoing.value = true;
      try {
        const res = await fetch('/api/fs/undo?session_id=default', { method: 'POST' });
        const data = await res.json();
        if (res.ok && data.success) {
          canUndo.value = !!data.can_undo;

          let detailsLines = [];
          if (data.affected_items && data.affected_items.length > 0) {
            detailsLines = data.affected_items.map(it => `- \`${it}\``);
          }

          const statusHint = data.can_undo
            ? '（💡 流水栈中仍有更早的历史操作，可继续点击撤销）'
            : '（🏁 已全部回退至本会话初始状态）';

          const cardContent = [
            `### ↩ 物理操作撤回已成功完成`,
            `**撤销摘要**: ${data.summary || '物理变更已还原'}`,
            `**资产变动明细**:`,
            detailsLines.length > 0 ? detailsLines.join('\n') : '- 数据库、安全等级与特征索引已恢复原状',
            ``,
            `*${statusHint}*`
          ].join('\n');

          messages.value.push({
            role: 'assistant',
            content: cardContent,
            thought: '',
            thinkExpanded: false,
            tool_calls: []
          });

          await refreshConfigs();
          await scrollToBottom();
        } else {
          alert(data.detail || data.message || '当前没有可撤回的操作记录');
          canUndo.value = false;
        }
      } catch (e) {
        alert('撤销调用异常: ' + e.message);
      } finally {
        isUndoing.value = false;
        await nextTick();
        lucide.createIcons();
      }
    };

    const fetchAuditLogs = async () => {
      try {
        const res = await fetch('/api/audit/logs?session_id=default&limit=50');
        const data = await res.json();
        if (data.success) {
          auditLogs.value = data.logs || [];
        }
      } catch (e) {
        console.error('拉取审计日志失败:', e);
      }
    };

    // ==================== 对话记录管理（审计面板内） ====================
    const fetchChatLogs = async () => {
      isLoadingChatLogs.value = true;
      try {
        const res = await fetch('/api/chat/logs?session_id=default');
        const data = await res.json();
        if (data.success) {
          chatLogs.value = data.logs || [];
          chatLogDir.value = data.log_dir || '';
        }
      } catch (e) {
        console.error('拉取对话记录列表失败:', e);
      } finally {
        isLoadingChatLogs.value = false;
      }
    };

    const switchChatLog = async (log) => {
      if (!window.confirm(`接续对话记录 ${log.name}？\n\n当前对话会先确认收尾完成，然后切换到这份记录。`)) return;
      try {
        const res = await fetch('/api/chat/logs/switch?session_id=default', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: log.name })
        });
        const data = await res.json();
        if (!res.ok) { alert(data.detail || '切换失败'); return; }
        // 界面上的消息列表来自后端窗口，切换后需要重新拉取才能显示对应内容
        await fetchChatLogs();
        await refreshConfigs();
        await loadChatHistoryToUI();
        alert(data.message || '已切换');
      } catch (e) {
        alert('切换失败: ' + e.message);
      }
    };

    const deleteChatLog = async (log) => {
      if (!window.confirm(`确定删除对话记录 ${log.name}？\n\n这是不可恢复的操作。`)) return;
      try {
        const res = await fetch('/api/chat/logs/delete?session_id=default', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: log.name })
        });
        const data = await res.json();
        if (!res.ok) { alert(data.detail || '删除失败'); return; }
        await fetchChatLogs();
        await refreshHistoryWindow();
      } catch (e) {
        alert('删除失败: ' + e.message);
      }
    };

    const openChatLogDirHint = () => {
      if (chatLogDir.value) alert('对话记录文件所在目录：\n' + chatLogDir.value);
    };


    const openPasswordModal = (fromGuide = false) => {
      isPasswordGuideMode.value = !!fromGuide;
      formPassword.old_password = '';
      formPassword.new_password = '';
      formPassword.confirm_password = '';
      modals.password = true;
      nextTick(() => lucide.createIcons());
    };

    const submitPasswordChange = async () => {
      if (!formPassword.new_password.trim()) return alert('新密码不能为空！');
      if (formPassword.new_password !== formPassword.confirm_password) return alert('两次输入的新密码不一致！');

      try {
        const res = await fetch('/api/security/password/update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            old_password: isPasswordGuideMode.value ? null : formPassword.old_password,
            new_password: formPassword.new_password
          })
        });
        const data = await res.json();
        if (!res.ok) {
          alert(data.detail || '更新密码失败');
          return;
        }
        alert(data.message || '管理密码已设置生效');
        closeModal('password');
        await refreshConfigs();
      } catch (e) {
        alert('更新失败: ' + e.message);
      }
    };

    const runTokenEstimation = async () => {
      if (!formScan.target_path.trim()) return alert('请先输入有效的扫描根目录');
      isEstimating.value = true;
      try {
        const url = `/api/scan/estimate_tokens?target_path=${encodeURIComponent(formScan.target_path.trim())}&max_depth=${formScan.max_depth}`;
        const res = await fetch(url, { method: 'POST' });
        const data = await res.json();
        if (data.success) {
          estimateResult.value = data.data;
        } else {
          alert(data.detail || '测算失败');
        }
      } catch (e) {
        alert('测算失败: ' + e.message);
      } finally {
        isEstimating.value = false;
      }
    };

    const handleTogglePermSensitive = () => {
      if (!formScan.permanent_skip_sensitive) {
        permSkipWarning.targetKey = 'permanent_skip_sensitive';
        permSkipWarning.level_name = '普通敏感操作 (剪切/重命名)';
        permSkipWarning.visible = true;
      } else {
        formScan.permanent_skip_sensitive = false;
      }
    };

    const handleTogglePermDestructive = () => {
      if (!formScan.permanent_skip_destructive) {
        if (!state.has_password) {
          alert('请先设置主管理密码，才能开启普通破坏性操作免密！');
          return;
        }
        permSkipWarning.targetKey = 'permanent_skip_destructive';
        permSkipWarning.level_name = '破坏性高危操作 (覆盖/删除入回收站)';
        permSkipWarning.visible = true;
      } else {
        formScan.permanent_skip_destructive = false;
      }
    };

    const confirmPermSkip = (confirmed) => {
      if (confirmed && permSkipWarning.targetKey) {
        formScan[permSkipWarning.targetKey] = true;
      } else if (permSkipWarning.targetKey) {
        formScan[permSkipWarning.targetKey] = false;
      }
      permSkipWarning.visible = false;
    };

    const resetSystemPromptDefault = async () => {
      try {
        const res = await fetch('/api/prompt/system/default');
        const data = await res.json();
        if (data.success && data.prompt) {
          tempSysPrompt.value = data.prompt;
        }
      } catch (e) {
        alert('拉取默认系统提示词失败: ' + e.message);
      }
    };

    const saveSystemPrompt = async () => {
      const ok = await saveRequest('/api/prompt/system', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: 'default', prompt: tempSysPrompt.value })
      }, '保存系统提示词');
      if (!ok) return;
      closeModal('edit_sys_prompt');
      await refreshConfigs();
    };

    const openEditTempPrompt = (item) => {
      formEditTempPrompt.prompt_id = item.id;
      formEditTempPrompt.title = item.title;
      formEditTempPrompt.content = item.content;
      modals.edit_temp_prompt = true;
      nextTick(() => lucide.createIcons());
    };

    const saveEditTempPrompt = async () => {
      if (!formEditTempPrompt.title.trim()) return alert('标题不能为空');
      if (!formEditTempPrompt.content.trim()) return alert('正文不能为空');
      const ok = await saveRequest('/api/prompt/temp/update', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: 'default',
          prompt_id: formEditTempPrompt.prompt_id,
          title: formEditTempPrompt.title,
          content: formEditTempPrompt.content
        })
      }, '更新临时提示词');
      if (!ok) return;
      closeModal('edit_temp_prompt');
      await refreshConfigs();
    };

    const moveTempPrompt = async (srcIdx, direction) => {
      const destIdx = srcIdx + direction;
      if (destIdx < 0 || destIdx >= state.temp_prompts.length) return;
      const ok = await saveRequest('/api/prompt/temp/reorder', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: 'default', src_idx: srcIdx, dest_idx: destIdx })
      }, '调整临时提示词顺序');
      if (!ok) return;
      await refreshConfigs();
    };

    const saveTempPrompt = async () => {
      if (!formTempPrompt.title.trim()) return alert('标题不能为空');
      const ok = await saveRequest('/api/prompt/temp/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: 'default', title: formTempPrompt.title, content: formTempPrompt.content })
      }, '新增临时提示词');
      if (!ok) return;
      closeModal('add_temp_prompt');
      await refreshConfigs();
    };

    const deleteTempPrompt = async (id) => {
      const ok = await saveRequest(`/api/prompt/temp/${id}?session_id=default`, { method: 'DELETE' }, '删除临时提示词');
      if (!ok) return;
      await refreshConfigs();
    };

    const togglePersistent = async (id, enabled) => {
      const ok = await saveRequest('/api/prompt/persistent/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: 'default', prompt_id: id, enabled: enabled })
      }, '切换常驻资料开关');
      if (!ok) return;
      await refreshConfigs();
    };

    const rescanPersistentPrompts = async () => {
      isRescanningPersistent.value = true;
      try {
        const res = await fetch('/api/prompt/persistent/rescan?session_id=default', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
          await refreshConfigs();
        }
      } catch (e) {
        alert('重新扫描常驻资料异常: ' + e.message);
      } finally {
        isRescanningPersistent.value = false;
      }
    };

    const saveApiProfile = async () => {
      if (!formApi.name.trim()) return alert('配置名称不能为空');
      const modelsToSave = availableModels.value.length > 0 ? availableModels.value : formApi.cached_models;
      const ok = await saveRequest('/api/config/api/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formApi.name.trim(),
          data: {
            platform: formApi.platform,
            url: formApi.url.trim(),
            key: formApi.key.trim(),
            selected_model: formApi.selected_model.trim(),
            cached_models: modelsToSave
          }
        })
      }, '保存 API 配置');
      if (!ok) return;
      closeModal('api');
      await refreshConfigs();
    };

    const saveScanConfig = async () => {
      const bl = formScan.blacklist_str.split('\n').map(s => s.trim()).filter(Boolean);
      if (!formScan.target_path || !String(formScan.target_path).trim()) {
        return alert('目标扫描路径不能为空！');
      }
      const depth = parseInt(formScan.max_depth, 10);
      if (!Number.isFinite(depth) || depth < 1) {
        return alert('扫描深度必须是大于等于 1 的整数！');
      }
      const windowRounds = parseInt(formScan.chat_history_window_rounds, 10);
      if (!Number.isFinite(windowRounds) || windowRounds < 1) {
        return alert('对话上下文窗口必须是大于等于 1 的整数（轮）！');
      }
      const warnMb = parseFloat(formScan.chat_log_size_warn_mb);
      if (!Number.isFinite(warnMb) || warnMb < 1) {
        return alert('对话记录告警阈值必须是大于等于 1 的数字（MB）！');
      }
      const ok = await saveRequest('/api/config/scan/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_path: formScan.target_path.trim(),
          max_depth: depth,
          blacklist_paths: bl,
          tool_token_warning_threshold: formScan.tool_token_warning_threshold,
          // 本接口不再接受"重置主密码"：改密必须走 /api/security/password/update（校验旧密码）
          new_password: null,
          permanent_skip_sensitive: formScan.permanent_skip_sensitive,
          permanent_skip_destructive: formScan.permanent_skip_destructive,
          chat_history_window_rounds: windowRounds,
          chat_log_size_warn_mb: warnMb
        })
      }, '保存扫描工作区配置');
      if (!ok) return;
      closeModal('scan_config');
      await refreshConfigs();
      await refreshHistoryWindow();
      // 窗口轮数可能刚被改小：立刻按新窗口重建界面，否则旧消息会一直显示到下一轮
      await loadChatHistoryToUI();
    };

    const saveFastChats = async () => {
      const ok = await saveRequest('/api/config/fast_chats/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fast_chats: formFastChats.value })
      }, '保存快捷指令');
      if (!ok) return;
      closeModal('fast_chat');
      await refreshConfigs();
    };

    const handleFileUpload = async (event) => {
      const file = event.target.files[0];
      if (!file) return;

      const formData = new FormData();
      formData.append("file", file);
      formData.append("session_id", "default");

      try {
        const res = await fetch("/api/upload/file", { method: "POST", body: formData });
        const data = await res.json();
        if (res.ok && data.success) {
          attachedFile.value = data;
        } else {
          alert(data.detail || '上传文件失败');
        }
      } catch (e) {
        alert("上传附件异常: " + e.message);
      } finally {
        event.target.value = "";
      }
    };

    const triggerFastChat = (chip) => {
      const text = (typeof chip === 'string') ? chip : (chip.content || '');
      inputMessage.value = text;
      if (messageInputRef.value) {
        messageInputRef.value.focus();
      }
    };

    // ==================== 智能体流式通信 ====================
    const sendMessage = async () => {
      const text = inputMessage.value.trim();
      const currentAttach = attachedFile.value;
      if ((!text && !currentAttach) || isStreaming.value || isUndoing.value) return;
      // 【收尾中】上一回合还没确认收尾完成 —— 这时候发不出去。
      // 服务端也有一道同样的保证；这里只是把状态如实反映到界面上。
      if (isFinalizing.value) return;

      let displayText = text;
      if (currentAttach && !currentAttach.is_image) {
        displayText += `\n\n[附加文本内容: ${currentAttach.filename}]\n\`\`\`\n${currentAttach.text_content.slice(0, 5000)}\n\`\`\``;
      }

      messages.value.push({
        role: 'user',
        content: displayText,
        image: (currentAttach && currentAttach.is_image) ? `data:image/${currentAttach.mime};base64,${currentAttach.base64}` : null
      });

      inputMessage.value = '';
      attachedFile.value = null;

      const currentAssistantMsg = reactive({
        role: 'assistant',
        content: '',
        thought: '',
        thinkExpanded: true,
        tool_calls: []
      });
      messages.value.push(currentAssistantMsg);
      isStreaming.value = true;
      await scrollToBottom();

      currentAbortController = new AbortController();

      const payload = {
        session_id: 'default',
        message: displayText,
        image_base64: (currentAttach && currentAttach.is_image) ? currentAttach.base64 : null,
        image_mime: (currentAttach && currentAttach.is_image) ? currentAttach.mime : 'jpeg'
      };

      try {
        const response = await fetch('/api/chat/stream', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          signal: currentAbortController.signal
        });

        const reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8');
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          buffer = buffer.replace(/\r\n/g, '\n');

          let eventEndIndex;
          while ((eventEndIndex = buffer.indexOf('\n\n')) !== -1) {
            const block = buffer.slice(0, eventEndIndex);
            buffer = buffer.slice(eventEndIndex + 2);

            if (!block.trim()) continue;

            let event = 'message';
            let dataLines = [];

            for (const line of block.split('\n')) {
              if (line.startsWith('event: ')) {
                event = line.substring(7).trim();
              } else if (line.startsWith('data: ')) {
                dataLines.push(line.substring(6));
              }
            }

            const rawData = dataLines.join('\n');
            let parsedPayload = rawData;
            try {
              parsedPayload = JSON.parse(rawData);
            } catch (_) {}

            if (event === 'thought') {
              currentAssistantMsg.thought += parsedPayload;
              await scrollToBottom();
            } else if (event === 'text_delta') {
              let textChunk = '';
              if (typeof parsedPayload === 'string') {
                textChunk = parsedPayload;
              } else if (Array.isArray(parsedPayload)) {
                textChunk = parsedPayload.map(b => (b && typeof b === 'object' && b.text) ? b.text : String(b)).join('');
              } else if (parsedPayload && typeof parsedPayload === 'object' && parsedPayload.text) {
                textChunk = parsedPayload.text;
              } else {
                textChunk = String(parsedPayload);
              }
              currentAssistantMsg.content += textChunk;
              await scrollToBottom();
            } else if (event === 'tool_start') {
              currentAssistantMsg.tool_calls.push({
                id: parsedPayload.id,
                name: parsedPayload.name,
                args: parsedPayload.args,
                status: 'running',
                result: '',
                isExpanded: false
              });
              await scrollToBottom();
            } else if (event === 'tool_result') {
              const tc = currentAssistantMsg.tool_calls.find(t => t.id === parsedPayload.tool_call_id)
                         || currentAssistantMsg.tool_calls[currentAssistantMsg.tool_calls.length - 1];
              if (tc) {
                tc.status = 'completed';
                tc.result = parsedPayload.content;
              }
              await scrollToBottom();
            } else if (event === 'hitl_suspend') {
              hitlModal.session_id = parsedPayload.session_id;
              hitlModal.action_name = parsedPayload.action_name;
              hitlModal.reason = parsedPayload.reason;
              hitlModal.level = parsedPayload.level;
              hitlModal.params = parsedPayload.params;
              hitlModal.items_meta = parsedPayload.items_meta || [];
              hitlModal.is_conflict = !!parsedPayload.is_conflict;
              hitlModal.is_downgrade = !!parsedPayload.is_downgrade;
              hitlModal.max_asset_level = parsedPayload.max_asset_level || 1;
              hitlModal.new_name = '';
              hitlModal.password = '';
              hitlModal.visible = true;
              await nextTick();
              lucide.createIcons();
            } else if (event === 'abort') {
              currentAssistantMsg.content += `\n\n${parsedPayload}`;
              currentAssistantMsg.tool_calls.forEach(t => { if (t.status === 'running') t.status = 'aborted'; });
            } else if (event === 'error') {
              currentAssistantMsg.content += `\n\n❌ **错误**: ${parsedPayload}`;
              currentAssistantMsg.tool_calls.forEach(t => { if (t.status === 'running') t.status = 'error'; });
            } else if (event === 'done') {
              currentAssistantMsg.thinkExpanded = false;
            }
          }
        }
      } catch (err) {
        if (err.name !== 'AbortError') {
          currentAssistantMsg.content += `\n\n❌ **通信异常**: ${err.message}`;
        }
      } finally {
        isStreaming.value = false;
        currentAbortController = null;
        await refreshConfigs();
        await checkUndoStatus();
        // 【界面与上下文窗口实时同步】本轮结束后按后端真实窗口重建：
        // 窗口滚动出去的旧消息会从界面消失，顶部提示"更早还有 N 条"。
        await loadChatHistoryToUI();
      }
    };

    // ==================== 恢复执行：密码鉴权与换名分支 ====================
    const resolveHITL = async (authorized, conflictAction = 'rename') => {
      try {
        const isOverwrite = (conflictAction === 'overwrite');
        const isCriticalAsset = (hitlModal.max_asset_level === 3);
        const isDestructive = (hitlModal.level === 'DESTRUCTIVE');
        // 覆盖替换类工具（含 write_file / compress_files / extract_archive）一律需要主密码，
        // 与后端 agent_resume_endpoint 的强校验保持一致，避免"前端不问、后端直接 403"的割裂体验。

        if (authorized && (isOverwrite || isCriticalAsset || isDestructive)) {
          if (!state.has_password) {
            alert('系统尚未初始化主管理密码，请先设置主密码！');
            openPasswordModal(true);
            return;
          }
          if (!hitlModal.password.trim()) {
            alert('⚠️ 操作涉及 3 级机密资产、破坏性操作或文件覆盖，必须输入主管理密码后方可授权！');
            return;
          }
        }

        const payload = {
          session_id: hitlModal.session_id,
          authorized: authorized,
          password: hitlModal.password,
          skip_this_session: hitlModal.skipThisSession,
          conflict_action: conflictAction,
          new_name: (conflictAction === 'rename' && hitlModal.new_name) ? hitlModal.new_name.trim() : null
        };

        const res = await fetch('/api/agent/resume', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (!res.ok) {
          const errData = await res.json();
          alert(errData.detail || '鉴权或恢复执行失败！');
          return;
        }
        hitlModal.visible = false;
        hitlModal.password = '';
      } catch (e) {
        alert('恢复执行发生异常: ' + e.message);
      }
    };

    // 对话记录的窗口状态：更早有多少条没载入内存、记录文件多大
    const refreshHistoryWindow = async () => {
      try {
        const res = await fetch('/api/chat/status?session_id=default');
        const data = await res.json();
        if (data && data.success) {
          historyWindow.dropped = data.dropped || 0;
          historyWindow.total_messages = data.total_messages || 0;
          historyWindow.in_window = data.in_window || 0;
          historyWindow.size_bytes = data.size_bytes || 0;
          historyWindow.window_rounds = data.window_rounds || 0;
          historyWindow.warning = data.warning || '';
        }
      } catch (e) {
        // 状态查询失败不影响对话
      }
    };

    // 【界面与后端窗口对齐】消息气泡此前只活在浏览器内存里：
    // 启动、或接续某份历史对话之后，界面都是空白（后端其实已经有内容）。
    // 这里从后端按真实窗口重建消息列表。
    // 正在流式输出时不覆盖，避免把刚出现的回答冲掉。
    const loadChatHistoryToUI = async () => {
      if (isStreaming.value || isFinalizing.value) return;
      try {
        const res = await fetch('/api/chat/history?session_id=default');
        const data = await res.json();
        if (!data || !data.success) return;
        const list = Array.isArray(data.messages) ? data.messages : [];
        const rendered = list.map(m => ({
          role: m.role,
          content: m.content,
          image: m.image || null,
          thought: m.thought || '',
          thinkExpanded: false,
          tool_calls: m.tool_calls || []
        }));
        // 窗口为空（新对话）时补回开场白，否则界面没有任何内容
        messages.value = rendered.length > 0 ? rendered : [{ ...WELCOME_MESSAGE }];
        historyWindow.dropped = data.dropped || 0;
        historyWindow.total_messages = data.total_messages || 0;
        historyWindow.in_window = data.in_window || 0;
        historyWindow.size_bytes = data.size_bytes || 0;
        historyWindow.window_rounds = data.window_rounds || 0;
        await nextTick();
        await scrollToBottom();
      } catch (e) {
        // 拉取失败时保留界面上已有内容，不清空
      }
    };

    const abortCurrentStream = async () => {
      if (currentAbortController) currentAbortController.abort();
      // 【收尾中】从这里开始，界面处于"发不出去"的状态，直到服务端确认
      // 上一回合已收尾完成。中止接口的返回时刻 == 收尾完成时刻，
      // 所以只需等这一次请求，不需要轮询、也不需要新接口。
      isFinalizing.value = true;
      isStreaming.value = false;
      try {
        const res = await fetch('/api/agent/abort?session_id=default', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (data && data.confirmed === false) {
          // 服务端没能确认收尾完成：如实告知，不假装没事
          window.alert(data.message || '上一回合未能确认收尾完成，已阻止其写入对话记录。');
        }
      } catch (e) {
        // 网络异常等情况：解除等待，避免界面永久卡在加载中
      } finally {
        isFinalizing.value = false;
        await refreshHistoryWindow();
      }
    };

    const clearMessages = async () => {
      // 新对话：服务端新建一份记录文件（旧文件保留），内存窗口清空
      await fetch('/api/chat/clear?session_id=default', { method: 'POST' });
      messages.value = [{ ...WELCOME_MESSAGE }];
      await refreshConfigs();
      await refreshHistoryWindow();
    };

    // 【确定性失败的处理】嵌入模型加载失败这类"必然复发"的情况：
    // 暂停本次工作流，让用户选择 中断 / 跳过语义索引继续 / 重试。
    // 重试前的等待由本函数的 finally 决定（isSyncingDb 直到用户选择后才归位）。
    const handleRetryableSyncFailure = (detail) => {
      const advisory =
        '⚠️ 语义索引未完成（可重试）\n\n' + detail + '\n\n' +
        '原因通常是：嵌入模型未缓存且当前无法下载（网络不可用/被拒绝）。\n\n' +
        '本次同步已暂停。请选择：\n' +
        '  • 确定 = 重试（模型就绪后会继续构建）\n' +
        '  • 取消 = 打开「跳过 / 中断」选择\n\n' +
        '说明：即使跳过，资产的 SQLite 索引与关键词检索仍然正常，' +
        '只是语义检索暂时无法命中这些资产。';

      if (window.confirm(advisory)) {
        return 'retry';
      }
      const skip = window.confirm(
        '要跳过本次语义索引并继续吗？\n\n' +
        '  • 确定 = 继续（其余工作正常，向量索引留待下次同步）\n' +
        '  • 取消 = 中断本次同步（不做任何进一步处理，稍后可在设置里重新同步）'
      );
      return skip ? 'continue' : 'abort';
    };

    const runSyncDb = async (silent = false) => {
      try {
        const resp = await fetch('/api/db/sync?session_id=default', { method: 'POST' });
        // 注意：不能直接 resp.json() —— 后端异常时会返回非 JSON 的 500 页面，
        // 过去那种写法会静默把"出错"变成"看起来没事"。
        const data = await resp.json().catch(() => null);

        if (!resp.ok) {
          alert('❌ 同步数据库失败（HTTP ' + resp.status + '）' +
                (data && data.detail ? '：' + data.detail : ''));
          return;
        }
        if (!data) {
          alert('❌ 同步数据库返回了无法解析的响应');
          return;
        }

        if (data.success === false) {
          const detail = data.warning || (data.vector && data.vector.message) || '未知原因';
          if (data.retryable) {
            const choice = handleRetryableSyncFailure(detail);
            if (choice === 'retry') {
              return runSyncDb(silent);          // 用户选择重试
            }
            if (choice === 'continue') {
              alert('已跳过本次语义索引。其余工作不受影响，可稍后再次点击「同步数据库」。');
              return;
            }
            alert('已中断本次同步，未做任何进一步处理。');
            return;
          }
          // 非可重试的部分失败（例如个别资产内容无法提取）：如实告知，不阻断流程
          alert(
            '⚠️ 部分资产未能完成语义索引\n\n' + detail +
            '\n\n这些资产仍可按文件名/内容关键词检索，' +
            '但暂时无法被语义检索命中。\n再次点击「同步数据库」可自动重试。'
          );
          return;
        }

        if (!silent && data.vector && data.vector.message) {
          alert('✅ ' + data.vector.message);
        }
      } catch (e) {
        alert('❌ 同步数据库异常：' + e.message);
      }
    };

    const triggerSyncDb = async () => {
      isSyncingDb.value = true;
      try {
        await runSyncDb(false);
        await refreshConfigs();
      } finally {
        // 只有用户完成选择（含重试链路走完）之后才恢复，期间界面保持"同步中"
        isSyncingDb.value = false;
      }
    };

    onMounted(async () => {
      await loadPresets();
      await refreshConfigs();
      await checkUndoStatus();
      await refreshHistoryWindow();
      // 启动时按后端真实窗口重建对话界面（此前界面永远是空的欢迎语）
      await loadChatHistoryToUI();
      lucide.createIcons();
    });

    return {
      state,
      isDarkMode,
      toggleTheme,
      platformPresets,
      availableModels,
      auditLogs,
      isUndoing,
      canUndo,
      isStreaming,
      isFinalizing,
      historyWindow,
      refreshHistoryWindow,
      loadChatHistoryToUI,
      chatLogs,
      chatLogDir,
      isLoadingChatLogs,
      fetchChatLogs,
      switchChatLog,
      deleteChatLog,
      openChatLogDirHint,
      isSyncingDb,
      isEstimating,
      isFetchingModels,
      isBrowsingDir,
      isRescanningPersistent,
      isPasswordGuideMode,
      estimateResult,
      messages,
      inputMessage,
      attachedFile,
      chatContainer,
      messageInputRef,
      hitlModal,
      hitlAssetAnalysis,
      permSkipWarning,
      modals,
      formApi,
      formScan,
      formPassword,
      formFastChats,
      tempSysPrompt,
      formTempPrompt,
      formEditTempPrompt,
      securityAssetsList,
      selectedAssetPaths,
      securityPassword,
      securityPending,
      currentBrowseDir,
      isLoadingAssets,
      isUpdatingSecurityLevels,
      isAllCurrentSelected,
      openSecurityLevelsModal,
      loadAssetBrowseDir,
      navigateParentAssetDir,
      toggleAssetSelection,
      selectAllAssets,
      invertSelectAssets,
      clearAssetSelection,
      toggleSelectAllCurrent,
      applyBatchSecurityLevel,
      onSingleAssetLevelChange,
      handleFileUpload,
      openModal,
      closeModal,
      openPasswordModal,
      submitPasswordChange,
      handleTogglePermSensitive,
      handleTogglePermDestructive,
      confirmPermSkip,
      runTokenEstimation,
      browseDirectory,
      onPlatformChange,
      fetchOnlineModels,
      saveApiProfile,
      switchProfile,
      selectProfileToEdit,
      deleteApiProfile,
      saveScanConfig,
      saveFastChats,
      saveSystemPrompt,
      resetSystemPromptDefault,
      saveTempPrompt,
      openEditTempPrompt,
      saveEditTempPrompt,
      moveTempPrompt,
      rescanPersistentPrompts,
      sendMessage,
      abortCurrentStream,
      resolveHITL,
      renderMarkdown,
      formatTokens,
      togglePersistent,
      deleteTempPrompt,
      clearMessages,
      triggerSyncDb,
      triggerFastChat,
      triggerUndo,
      checkUndoStatus,
      fetchAuditLogs,
      refreshConfigs
    };
  }
}).mount('#app');