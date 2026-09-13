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

    const messages = ref([
      {
        role: 'assistant',
        content: '你好！我是基于 **LangGraph 工业级图状态机** 驱动的本地资产智能管理 Agent。\n系统已搭载 **三级资产安全防护引擎**，支持文件夹动态等级继承、操作提醒、主密码高危防护与降级预警。',
        thought: '',
        thinkExpanded: false,
        tool_calls: []
      }
    ]);

    const inputMessage = ref('');
    const attachedFile = ref(null);
    const isStreaming = ref(false);
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
      permanent_skip_destructive: false
    });

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

    // ==================== 资产安全等级管理逻辑 ====================
    const openSecurityLevelsModal = async () => {
      selectedAssetPaths.value = new Set();
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

    const toggleAssetSelection = (item) => {
      const p = item.rel_path;
      if (selectedAssetPaths.value.has(p)) {
        selectedAssetPaths.value.delete(p);
      } else {
        selectedAssetPaths.value.add(p);
      }
    };

    const selectAllAssets = () => {
      securityAssetsList.value.forEach(item => {
        selectedAssetPaths.value.add(item.rel_path);
      });
    };

    const invertSelectAssets = () => {
      securityAssetsList.value.forEach(item => {
        if (selectedAssetPaths.value.has(item.rel_path)) {
          selectedAssetPaths.value.delete(item.rel_path);
        } else {
          selectedAssetPaths.value.add(item.rel_path);
        }
      });
    };

    const clearAssetSelection = () => {
      selectedAssetPaths.value.clear();
    };

    const toggleSelectAllCurrent = () => {
      if (isAllCurrentSelected.value) {
        securityAssetsList.value.forEach(item => selectedAssetPaths.value.delete(item.rel_path));
      } else {
        securityAssetsList.value.forEach(item => selectedAssetPaths.value.add(item.rel_path));
      }
    };

    const applyBatchSecurityLevel = async (targetLevel) => {
      if (selectedAssetPaths.value.size === 0) return alert('请先勾选需要设置安全等级的资产！');

      if (targetLevel === 3 && !state.has_password) {
        alert('将资产设为 3 级（机密）前，系统强制要求先设置主管理密码！');
        openPasswordModal(true);
        return;
      }

      isUpdatingSecurityLevels.value = true;
      const itemsPayload = [];
      for (const it of securityAssetsList.value) {
        if (selectedAssetPaths.value.has(it.rel_path)) {
          itemsPayload.push({ path: it.abs_path, is_dir: it.is_dir });
        }
      }

      try {
        const res = await fetch('/api/security/levels/update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            session_id: 'default',
            items: itemsPayload,
            target_level: targetLevel
          })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          alert(data.message || '安全等级更新完成');
          selectedAssetPaths.value.clear();
          await loadAssetBrowseDir(currentBrowseDir.value);
        } else if (res.status === 428) {
          alert(data.detail || '请先设置主管理密码');
          openPasswordModal(true);
        } else {
          alert(data.detail || '更新失败');
        }
      } catch (e) {
        alert('调用批量更新等级异常: ' + e.message);
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

      try {
        const res = await fetch('/api/security/levels/update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            session_id: 'default',
            items: [{ path: item.abs_path, is_dir: item.is_dir }],
            target_level: newLvl
          })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          await loadAssetBrowseDir(currentBrowseDir.value);
        } else {
          event.target.value = item.explicit_level;
          alert(data.detail || '设置等级失败');
        }
      } catch (e) {
        event.target.value = item.explicit_level;
        alert('设置等级异常: ' + e.message);
      }
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
      await fetch('/api/prompt/system', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: 'default', prompt: tempSysPrompt.value })
      });
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
      try {
        await fetch('/api/prompt/temp/update', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            session_id: 'default',
            prompt_id: formEditTempPrompt.prompt_id,
            title: formEditTempPrompt.title,
            content: formEditTempPrompt.content
          })
        });
        closeModal('edit_temp_prompt');
        await refreshConfigs();
      } catch (e) {
        alert('更新临时提示词失败: ' + e.message);
      }
    };

    const moveTempPrompt = async (srcIdx, direction) => {
      const destIdx = srcIdx + direction;
      if (destIdx < 0 || destIdx >= state.temp_prompts.length) return;
      try {
        await fetch('/api/prompt/temp/reorder', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ session_id: 'default', src_idx: srcIdx, dest_idx: destIdx })
        });
        await refreshConfigs();
      } catch (e) {
        alert('调整顺序失败: ' + e.message);
      }
    };

    const saveTempPrompt = async () => {
      if (!formTempPrompt.title.trim()) return alert('标题不能为空');
      await fetch('/api/prompt/temp/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: 'default', title: formTempPrompt.title, content: formTempPrompt.content })
      });
      closeModal('add_temp_prompt');
      await refreshConfigs();
    };

    const deleteTempPrompt = async (id) => {
      await fetch(`/api/prompt/temp/${id}?session_id=default`, { method: 'DELETE' });
      await refreshConfigs();
    };

    const togglePersistent = async (id, enabled) => {
      await fetch('/api/prompt/persistent/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: 'default', prompt_id: id, enabled: enabled })
      });
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
      await fetch('/api/config/api/save', {
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
      });
      closeModal('api');
      await refreshConfigs();
    };

    const saveScanConfig = async () => {
      const bl = formScan.blacklist_str.split('\n').map(s => s.trim()).filter(Boolean);
      await fetch('/api/config/scan/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_path: formScan.target_path.trim(),
          max_depth: formScan.max_depth,
          blacklist_paths: bl,
          tool_token_warning_threshold: formScan.tool_token_warning_threshold,
          new_password: null,
          permanent_skip_sensitive: formScan.permanent_skip_sensitive,
          permanent_skip_destructive: formScan.permanent_skip_destructive
        })
      });
      closeModal('scan_config');
      await refreshConfigs();
    };

    const saveFastChats = async () => {
      await fetch('/api/config/fast_chats/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fast_chats: formFastChats.value })
      });
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
        await scrollToBottom();
      }
    };

    // ==================== 恢复执行：密码鉴权与换名分支 ====================
    const resolveHITL = async (authorized, conflictAction = 'rename') => {
      try {
        const isOverwrite = (conflictAction === 'overwrite');
        const isCriticalAsset = (hitlModal.max_asset_level === 3);
        const isDestructive = (hitlModal.level === 'DESTRUCTIVE');

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

    const abortCurrentStream = async () => {
      if (currentAbortController) currentAbortController.abort();
      await fetch('/api/agent/abort?session_id=default', { method: 'POST' });
      isStreaming.value = false;
    };

    const clearMessages = async () => {
      await fetch('/api/chat/clear?session_id=default', { method: 'POST' });
      messages.value = [];
      await refreshConfigs();
    };

    const triggerSyncDb = async () => {
      isSyncingDb.value = true;
      try {
        await fetch('/api/db/sync?session_id=default', { method: 'POST' });
        await refreshConfigs();
      } finally {
        isSyncingDb.value = false;
      }
    };

    onMounted(async () => {
      await loadPresets();
      await refreshConfigs();
      await checkUndoStatus();
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