// 简化版app.js - 只包含DOM定义和基本功能

// 初始化日志系统
const logger = window.logger || console;

const views = {
  login: document.getElementById("view-login"),
  dashboard: document.getElementById("view-dashboard"),
  config: document.getElementById("view-config"),
  register: document.getElementById("view-register"),
  baseline: document.getElementById("view-baseline"),
  situation: document.getElementById("view-situation"),
  defense: document.getElementById("view-defense"),
  av: document.getElementById("view-av"),
  edge: document.getElementById("view-edge"),
  aiChat: document.getElementById("view-ai-chat"),
  ids: document.getElementById("view-ids"),
  logging: document.getElementById("view-logging"),
  incidentResponse: document.getElementById("view-incident-response")
};

// 所有DOM元素引用
const cidrEl = document.getElementById("cidr");
const modelEl = document.getElementById("model");
const portsEl = document.getElementById("ports");
const startBtn = document.getElementById("start");
const statusEl = document.getElementById("status");
const reportEl = document.getElementById("report");
const tableEl = document.getElementById("table");
const portTableEl = document.getElementById("port-table");
const intelEl = document.getElementById("intel");
const btnRemediate = document.getElementById("btn-remediate");
const remediationEl = document.getElementById("remediation");
const btnPrint = document.getElementById("btn-print");
const btnSitStart = document.getElementById("btn-sit-start");
const sitStatus = document.getElementById("sit-status");
const sitFeeds = document.getElementById("sit-feeds");
const sitIntel = document.getElementById("sit-intel");
const sitReport = document.getElementById("sit-report");
const btnSitPrint = document.getElementById("btn-sit-print");
const dfAuto = document.getElementById("df-auto");
const dfInterval = document.getElementById("df-interval");
const btnDfStart = document.getElementById("btn-df-start");
const btnDfStop = document.getElementById("btn-df-stop");
const dfStatus = document.getElementById("df-status");
const dfReport = document.getElementById("df-report");
const dfActions = document.getElementById("df-actions");
const btnDfPrint = document.getElementById("btn-df-print");
const avFile = document.getElementById("av-file");
const btnAvUpload = document.getElementById("btn-av-upload");
const avStatus = document.getElementById("av-status");
const avHash = document.getElementById("av-hash");
const btnAvHash = document.getElementById("btn-av-hash");
const avText = document.getElementById("av-text");
const btnAvPoison = document.getElementById("btn-av-poison");
const avPoison = document.getElementById("av-poison");
const avReport = document.getElementById("av-report");
const btnAvReport = document.getElementById("btn-av-report");
const edgeTable = document.getElementById("edge-table");
const edgeRules = document.getElementById("edge-rules");
const edgeStatus = document.getElementById("edge-status");
const btnEdgeRefresh = document.getElementById("btn-edge-refresh");
const btnEdgePrint = document.getElementById("btn-edge-print");
const aiInput = document.getElementById("chat-input") || document.getElementById("ai-input");
const btnAiSend = document.getElementById("chat-send") || document.getElementById("btn-ai-send");
const aiOutput = document.getElementById("chat-history") || document.getElementById("ai-output");
const aiStatus = document.getElementById("chat-status") || document.getElementById("ai-status");
const aiModel = document.getElementById("ai-model");
const btnAiClear = document.getElementById("btn-ai-clear");
const idsEvents = document.getElementById("ids-events");
const idsStatus = document.getElementById("ids-status");
const btnIdsStart = document.getElementById("btn-ids-start");
const btnIdsStop = document.getElementById("btn-ids-stop");
const btnIdsPrint = document.getElementById("btn-ids-print");
const loggingEvents = document.getElementById("logging-events");
const loggingStatus = document.getElementById("logging-status");
const btnLoggingStart = document.getElementById("btn-logging-start");
const btnLoggingStop = document.getElementById("btn-logging-stop");
const btnLoggingPrint = document.getElementById("btn-logging-print");
const incidentTable = document.getElementById("incident-table");
const incidentStatus = document.getElementById("incident-status");
const btnIncidentRefresh = document.getElementById("btn-incident-refresh");
const btnIncidentPrint = document.getElementById("btn-incident-print");
const loginUsername = document.getElementById("login-username");
const loginPassword = document.getElementById("login-password");
const btnLogin = document.getElementById("btn-login");
const loginError = document.getElementById("login-error");
const registerUsername = document.getElementById("register-username");
const registerPassword = document.getElementById("register-password");
const registerConfirm = document.getElementById("register-confirm");
const btnRegister = document.getElementById("btn-register");
const registerError = document.getElementById("register-error");
const registerSuccess = document.getElementById("register-success");
const configApiKey = document.getElementById("config-api-key");
const configApiUrl = document.getElementById("config-api-url");
const configUpdateInterval = document.getElementById("config-update-interval");
const configTheme = document.getElementById("config-theme");
const configLanguage = document.getElementById("config-language");
const btnConfigSave = document.getElementById("btn-config-save");
const configSuccess = document.getElementById("config-success");
const btnConfigPrint = document.getElementById("btn-config-print");
const btnLogout = document.getElementById("btn-logout");
const menuDashboard = document.getElementById("nav-dashboard");
const menuBaseline = document.getElementById("nav-baseline");
const menuSituation = document.getElementById("nav-situation");
const menuDefense = document.getElementById("nav-defense");
const menuAv = document.getElementById("nav-av");
const menuEdge = document.getElementById("nav-edge");
const menuAiChat = document.getElementById("nav-ai-chat");
const menuIds = document.getElementById("nav-ids");
const menuLogging = document.getElementById("nav-logging");
const menuIncidentResponse = document.getElementById("nav-incident-response");
const menuConfig = document.getElementById("nav-config");
const menuLogin = document.getElementById("nav-login");
const menuRegister = document.getElementById("nav-register");
const currentUser = document.getElementById("current-user");
const menuUsername = document.getElementById("menu-username");
const menuUserDropdown = document.getElementById("menu-user-dropdown");
const menuUserSettings = document.getElementById("menu-user-settings");
const menuUserLogout = document.getElementById("menu-user-logout");
const overlay = document.getElementById("overlay");
const loading = document.getElementById("loading");
const toastContainer = document.getElementById("toast-container");
const notifications = document.getElementById("notifications");
const btnNotifications = document.getElementById("btn-notifications");
const notificationDropdown = document.getElementById("notification-dropdown");
const timeZone = document.getElementById("time-zone");
const dateTime = document.getElementById("date-time");
const weatherInfo = document.getElementById("weather-info");
const systemHealth = document.getElementById("system-health");
const networkStatus = document.getElementById("network-status");
const storageInfo = document.getElementById("storage-info");
const memoryUsage = document.getElementById("memory-usage");
const cpuUsage = document.getElementById("cpu-usage");
const uptime = document.getElementById("uptime");
const bandwidth = document.getElementById("bandwidth");
const dashboardCards = document.getElementById("dashboard-cards");
const dashboardCharts = document.getElementById("dashboard-charts");
const dashboardStats = document.getElementById("dashboard-stats");
const dashboardQuickActions = document.getElementById("dashboard-quick-actions");
// 态势感知视图附加元素
const securityRecommendationsEl = document.getElementById("recommendations-list");
const threatDetailsEl = document.getElementById("threat-details");
const threatDetailsToggle = document.getElementById("threat-details-toggle");
const realtimeIndicatorEl = document.getElementById("realtime-indicator");

async function getOrCreateMasterKey() {
  try {
    const b64 = localStorage.getItem('SMK_B64');
    if (b64) {
      const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
      return await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt','decrypt']);
    }
    const raw = new Uint8Array(32);
    crypto.getRandomValues(raw);
    const b64New = btoa(String.fromCharCode(...raw));
    localStorage.setItem('SMK_B64', b64New);
    return await crypto.subtle.importKey('raw', raw.buffer, 'AES-GCM', false, ['encrypt','decrypt']);
  } catch { return null; }
}

function toB64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromB64(b64) {
  const binary = atob(b64 || '');
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function encryptText(text) {
  const key = await getOrCreateMasterKey();
  if (!key) return null;
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const data = new TextEncoder().encode(text || '');
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { cipherB64: toB64(cipher), ivB64: toB64(iv.buffer) };
}

async function decryptText(cipherB64, ivB64) {
  try {
    const key = await getOrCreateMasterKey();
    if (!key) return '';
    const cipher = fromB64(cipherB64 || '');
    const iv = new Uint8Array(fromB64(ivB64 || ''));
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher);
    return new TextDecoder().decode(plain);
  } catch { return ''; }
}

async function saveSecurityModelKey(plain) {
  try {
    if (!plain) {
      localStorage.removeItem('SECURITY_MODEL_API_KEY_ENC');
      localStorage.removeItem('SECURITY_MODEL_API_KEY_IV');
      localStorage.removeItem('SECURITY_MODEL_API_KEY');
      return;
    }
    const enc = await encryptText(plain);
    if (!enc) return;
    localStorage.setItem('SECURITY_MODEL_API_KEY_ENC', enc.cipherB64);
    localStorage.setItem('SECURITY_MODEL_API_KEY_IV', enc.ivB64);
    localStorage.removeItem('SECURITY_MODEL_API_KEY');
  } catch {}
}

async function loadSecurityModelKey() {
  const enc = localStorage.getItem('SECURITY_MODEL_API_KEY_ENC');
  const iv = localStorage.getItem('SECURITY_MODEL_API_KEY_IV');
  if (!enc || !iv) return '';
  return await decryptText(enc, iv);
}

async function clearSecurityKeys(reason) {
  try {
    localStorage.removeItem('SECURITY_MODEL_API_KEY_ENC');
    localStorage.removeItem('SECURITY_MODEL_API_KEY_IV');
    localStorage.removeItem('SECURITY_MODEL_API_KEY');
    showToast('已清除本地密钥', 'warning');
    addNotification('密钥已清除', reason || '环境变化触发清理', 'warning');
  } catch {}
}

async function computeProjectHash() {
  try {
    const res = await fetch('/index.html');
    const txt = await res.text();
    const data = new TextEncoder().encode(txt + (location.origin || '') + (location.pathname || ''));
    const digest = await crypto.subtle.digest('SHA-256', data);
    return toB64(digest);
  } catch { return ''; }
}

async function ensureMigrationCleanup() {
  const prevOrigin = localStorage.getItem('PROJECT_ORIGIN') || '';
  const prevHash = localStorage.getItem('PROJECT_HASH') || '';
  const curOrigin = location.origin || '';
  const curHash = await computeProjectHash();
  if (prevOrigin && prevHash && (prevOrigin !== curOrigin || (curHash && prevHash !== curHash))) {
    await clearSecurityKeys('检测到项目迁移或版本变化');
  }
  localStorage.setItem('PROJECT_ORIGIN', curOrigin);
  if (curHash) localStorage.setItem('PROJECT_HASH', curHash);
}

// 基本功能 - 简化版
const state = {
  user: null,
  isLoading: false,
  notifications: []
};

// 简化的显示视图函数
function showView(viewName) {
  // 需要登录才能访问的视图列表
  const protectedViews = ['dashboard', 'baseline', 'situation', 'defense', 'av', 'edge', 'aiChat', 'ids', 'logging', 'incidentResponse', 'config'];
  
  // 检查是否需要登录且用户未登录
  if (protectedViews.includes(viewName) && !state.user) {
    // 跳转到登录页面
    if (views['login']) {
      views['login'].style.display = 'block';
    }
    // 隐藏其他所有视图
    Object.keys(views).forEach(key => {
      if (key !== 'login' && views[key]) {
        views[key].style.display = 'none';
      }
    });
    showError('请先登录后再访问该功能');
    return;
  }
  
  // 隐藏所有视图
  Object.values(views).forEach(view => {
    if (view) {
      view.style.display = 'none';
      view.classList?.remove('active');
    }
  });
  
  // 显示指定视图
  if (views[viewName]) {
    views[viewName].style.display = 'block';
    views[viewName].classList?.add('active');
  }
  updateActiveNav(viewName);
}

// 简化的加载函数
function showLoading() {
  if (overlay) overlay.style.display = 'flex';
  if (loading) loading.style.display = 'block';
}

function hideLoading() {
  if (overlay) overlay.style.display = 'none';
  if (loading) loading.style.display = 'none';
}

// 简化的错误处理
function showError(message) {
  logger.error(message);
  // 可以在这里添加toast通知逻辑
}

// 日志记录功能
function setupLogging() {
  logger.info('设置日志记录功能');
  
  // 日志记录状态
  let isLoggingActive = false;
  let loggingInterval = null;
  
  // 开始日志记录
  if (btnLoggingStart) {
    btnLoggingStart.addEventListener('click', () => {
      if (isLoggingActive) {
        showError('日志记录已在运行');
        return;
      }
      
      isLoggingActive = true;
      loggingStatus.textContent = '运行中';
      loggingStatus.className = 'status success';
      
      // 定期更新日志显示
      loggingInterval = setInterval(() => {
        updateLoggingDisplay();
      }, 1000);
      
      logger.info('日志记录已启动');
    });
  }
  
  // 停止日志记录
  if (btnLoggingStop) {
    btnLoggingStop.addEventListener('click', () => {
      if (!isLoggingActive) {
        showError('日志记录未在运行');
        return;
      }
      
      isLoggingActive = false;
      clearInterval(loggingInterval);
      loggingStatus.textContent = '已停止';
      loggingStatus.className = 'status';
      
      logger.info('日志记录已停止');
    });
  }
  
  // 打印日志
  if (btnLoggingPrint) {
    btnLoggingPrint.addEventListener('click', () => {
      window.print();
      logger.info('日志已打印');
    });
  }
  
  // 初始化日志显示
  updateLoggingDisplay();
}

// 更新日志显示
function updateLoggingDisplay() {
  if (!loggingEvents) return;
  
  // 获取日志统计信息
  const stats = logger.getStats ? logger.getStats() : { total: 0, info: 0, warn: 0, error: 0, critical: 0 };
  
  // 更新日志显示
  loggingEvents.innerHTML = `
    <div class="logging-stats">
      <h3>日志统计</h3>
      <div class="stat-grid">
        <div class="stat-item">
          <div class="stat-value">${stats.total || 0}</div>
          <div class="stat-label">总日志数</div>
        </div>
        <div class="stat-item info">
          <div class="stat-value">${stats.info || 0}</div>
          <div class="stat-label">信息</div>
        </div>
        <div class="stat-item warning">
          <div class="stat-value">${stats.warn || 0}</div>
          <div class="stat-label">警告</div>
        </div>
        <div class="stat-item error">
          <div class="stat-value">${stats.error || 0}</div>
          <div class="stat-label">错误</div>
        </div>
        <div class="stat-item critical">
          <div class="stat-value">${stats.critical || 0}</div>
          <div class="stat-label">严重</div>
        </div>
      </div>
    </div>
    <div class="logging-latest">
      <h3>最新日志</h3>
      <div class="log-list">
        <div class="log-item info">
          <span class="log-time">${new Date().toLocaleTimeString()}</span>
          <span class="log-level">INFO</span>
          <span class="log-message">系统运行正常</span>
        </div>
        <div class="log-item info">
          <span class="log-time">${new Date().toLocaleTimeString()}</span>
          <span class="log-level">INFO</span>
          <span class="log-message">日志记录功能已初始化</span>
        </div>
      </div>
    </div>
  `;
}

// 初始化
function init() {
  logger.info('应用初始化');
  // 检查登录状态（简化版）
  const savedUser = localStorage.getItem('user');
  if (savedUser) {
    try {
      state.user = JSON.parse(savedUser);
      logger.info('用户已登录:', state.user.username);
      showView('dashboard');
    } catch (e) {
      logger.error('解析用户数据失败:', e);
      showError('解析用户数据失败');
      showView('login');
    }
  } else {
    logger.info('用户未登录，显示登录页面');
    showView('login');
  }
  
  // 设置导航
  setupNavigation();
  
  // 设置登录功能
  setupLogin();
  
  // 设置注册功能
  setupRegister();
  
  // 设置日志记录功能
  setupLogging();
  
  // 更新导航状态
  updateNavigation();
  
  // 更新系统信息
  updateSystemInfo();
}

// 导航菜单事件处理
function setupNavigation() {
  // 导航菜单项点击事件
  const menuItems = [
    { id: menuDashboard, view: 'dashboard' },
    { id: menuBaseline, view: 'baseline' },
    { id: menuSituation, view: 'situation' },
    { id: menuDefense, view: 'defense' },
    { id: menuAv, view: 'av' },
    { id: menuEdge, view: 'edge' },
    { id: menuAiChat, view: 'aiChat' },
    { id: menuIds, view: 'ids' },
    { id: menuLogging, view: 'logging' },
    { id: menuIncidentResponse, view: 'incidentResponse' },
    { id: menuConfig, view: 'config' },
    { id: menuLogin, view: 'login' },
    { id: menuRegister, view: 'register' }
  ];

  menuItems.forEach(item => {
    if (item.id) {
      item.id.addEventListener('click', (e) => {
        e.preventDefault();
        showView(item.view);
        updateNavigation();
      });
    }
  });

  // 登出功能
  if (btnLogout) {
    btnLogout.addEventListener('click', () => {
      logout();
    });
  }

  if (menuUserLogout) {
    menuUserLogout.addEventListener('click', () => {
      logout();
    });
  }

  // 用户下拉菜单
  if (menuUsername) {
    menuUsername.addEventListener('click', () => {
      if (menuUserDropdown) {
        menuUserDropdown.style.display = menuUserDropdown.style.display === 'block' ? 'none' : 'block';
      }
    });
  }

  // 通知按钮
  if (btnNotifications) {
    btnNotifications.addEventListener('click', () => {
      if (notificationDropdown) {
        notificationDropdown.style.display = notificationDropdown.style.display === 'block' ? 'none' : 'block';
      }
    });
  }

  // 点击页面其他地方关闭下拉菜单
  document.addEventListener('click', (e) => {
    if (menuUserDropdown && !menuUsername?.contains(e.target) && !menuUserDropdown.contains(e.target)) {
      menuUserDropdown.style.display = 'none';
    }
    if (notificationDropdown && !btnNotifications?.contains(e.target) && !notificationDropdown.contains(e.target)) {
      notificationDropdown.style.display = 'none';
    }
  });
}

// 更新导航状态
function updateNavigation() {
  // 更新用户信息显示
  if (state.user) {
    if (currentUser) currentUser.textContent = state.user.username;
    if (menuUsername) menuUsername.textContent = state.user.username;
    
    // 显示用户相关菜单，隐藏登录/注册
    if (menuLogin) menuLogin.style.display = 'none';
    if (menuRegister) menuRegister.style.display = 'none';
    if (menuUsername) menuUsername.style.display = 'block';
    if (btnLogout) btnLogout.style.display = 'block';
  } else {
    // 显示登录/注册菜单，隐藏用户相关
    if (menuLogin) menuLogin.style.display = 'block';
    if (menuRegister) menuRegister.style.display = 'block';
    if (menuUsername) menuUsername.style.display = 'none';
    if (btnLogout) btnLogout.style.display = 'none';
  }
  
  // 更新通知计数
  updateNotificationCount();
}

function updateActiveNav(viewName) {
  const navItems = [
    menuDashboard,
    menuBaseline,
    menuSituation,
    menuDefense,
    menuAv,
    menuEdge,
    menuAiChat,
    menuIds,
    menuLogging,
    menuIncidentResponse,
    menuConfig,
    menuLogin,
    menuRegister
  ];
  navItems.forEach(el => {
    if (el) el.classList.remove('active');
  });
  const map = {
    login: menuLogin,
    dashboard: menuDashboard,
    config: menuConfig,
    register: menuRegister,
    baseline: menuBaseline,
    situation: menuSituation,
    defense: menuDefense,
    av: menuAv,
    edge: menuEdge,
    aiChat: menuAiChat,
    ids: menuIds,
    logging: menuLogging,
    incidentResponse: menuIncidentResponse
  };
  const activeEl = map[viewName];
  if (activeEl) activeEl.classList.add('active');
}

// 登录功能
function setupLogin() {
  if (!btnLogin) return;
  
  btnLogin.addEventListener('click', () => {
    const username = loginUsername?.value.trim() || '';
    const password = loginPassword?.value.trim() || '';
    
    // 简单的表单验证
    if (!username || !password) {
      if (loginError) {
        loginError.textContent = '请输入用户名和密码';
        loginError.style.display = 'block';
      }
      return;
    }
    
    showLoading();
    
    // 模拟登录请求
    setTimeout(() => {
      // 模拟用户数据
      const userData = {
        id: Date.now(),
        username: username,
        email: `${username}@example.com`,
        role: 'admin',
        permissions: ['read', 'write', 'admin'],
        lastLogin: new Date().toISOString()
      };
      
      // 保存用户数据
      state.user = userData;
      localStorage.setItem('user', JSON.stringify(userData));
      
      // 重置错误提示
      if (loginError) {
        loginError.textContent = '';
        loginError.style.display = 'none';
      }
      
      // 重置表单
      if (loginUsername) loginUsername.value = '';
      if (loginPassword) loginPassword.value = '';
      
      // 更新界面
      showView('dashboard');
      updateNavigation();
      initDashboard();
      showToast('登录成功', 'success');
      addNotification('用户登录', `${username} 已成功登录系统`, 'info');
      
      hideLoading();
    }, 1000);
  });
}

// 注册功能
function setupRegister() {
  if (!btnRegister) return;
  
  btnRegister.addEventListener('click', () => {
    const username = registerUsername?.value.trim() || '';
    const password = registerPassword?.value.trim() || '';
    const confirmPassword = registerConfirm?.value.trim() || '';
    
    // 简单的表单验证
    if (!username || !password || !confirmPassword) {
      if (registerError) {
        registerError.textContent = '请填写所有必填字段';
        registerError.style.display = 'block';
      }
      return;
    }
    
    if (password !== confirmPassword) {
      if (registerError) {
        registerError.textContent = '两次输入的密码不一致';
        registerError.style.display = 'block';
      }
      return;
    }
    
    if (password.length < 6) {
      if (registerError) {
        registerError.textContent = '密码长度至少为6位';
        registerError.style.display = 'block';
      }
      return;
    }
    
    showLoading();
    
    // 模拟注册请求
    setTimeout(() => {
      // 模拟成功注册
      const newUser = {
        id: Date.now(),
        username: username,
        email: `${username}@example.com`,
        role: 'user',
        permissions: ['read'],
        registrationDate: new Date().toISOString()
      };
      
      // 重置错误提示
      if (registerError) {
        registerError.textContent = '';
        registerError.style.display = 'none';
      }
      
      // 显示成功消息
      if (registerSuccess) {
        registerSuccess.textContent = '注册成功！请登录';
        registerSuccess.style.display = 'block';
      }
      
      // 重置表单
      if (registerUsername) registerUsername.value = '';
      if (registerPassword) registerPassword.value = '';
      if (registerConfirm) registerConfirm.value = '';
      
      // 添加通知
      addNotification('新用户注册', `用户 ${username} 已成功注册`, 'success');
      
      // 3秒后跳转到登录页面
      setTimeout(() => {
        showView('login');
        if (registerSuccess) {
          registerSuccess.textContent = '';
          registerSuccess.style.display = 'none';
        }
      }, 3000);
      
      hideLoading();
    }, 1500);
  });
}

// 资产扫描和分析功能
function setupAssetScanning() {
  if (!startBtn) return;
  
  // 扫描状态
  let isScanning = false;
  let scanInterval = null;
  let progress = 0;
  
  // 开始扫描按钮点击事件
  startBtn.addEventListener('click', () => {
    if (isScanning) {
      // 如果正在扫描，则停止扫描
      stopScan();
      return;
    }
    
    // 获取扫描参数
    const cidr = cidrEl?.value.trim() || '';
    const model = modelEl?.value || 'basic';
    const ports = portsEl?.value.trim() || '';
    
    // 简单的表单验证
    if (!cidr) {
      showToast('请输入CIDR地址范围', 'error');
      return;
    }
    
    // 验证CIDR格式（简单验证）
    const cidrPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/;
    if (!cidrPattern.test(cidr)) {
      showToast('CIDR格式不正确，请使用类似 192.168.1.0/24 的格式', 'error');
      return;
    }
    
    // 开始扫描
    startScan(cidr, model, ports);
  });
  
  // 开始扫描
  function startScan(cidr, model, ports) {
    isScanning = true;
    progress = 0;
    
    // 更新UI状态
    if (startBtn) startBtn.textContent = '停止扫描';
    if (statusEl) statusEl.textContent = '扫描中...';
    
    showLoading();
    
    // 添加通知和日志
    logger.info(`开始扫描网络 ${cidr}，使用 ${model} 模式`);
    addNotification('扫描开始', `开始扫描网络 ${cidr}，使用 ${model} 模式`, 'info');
    
    // 模拟扫描进度
    setTimeout(() => {
      hideLoading();
      
      scanInterval = setInterval(() => {
        progress += 5;
        
        if (statusEl) {
          statusEl.textContent = `扫描中... ${progress}%`;
        }
        
        // 模拟发现资产
        if (Math.random() > 0.7) {
          simulateAssetDiscovery();
        }
        
        if (progress >= 100) {
          completeScan();
        }
      }, 300);
    }, 1000);
  }
  
  // 停止扫描
  function stopScan() {
    isScanning = false;
    
    if (scanInterval) {
      clearInterval(scanInterval);
      scanInterval = null;
    }
    
    // 更新UI状态
    if (startBtn) startBtn.textContent = '开始扫描';
    if (statusEl) statusEl.textContent = '扫描已停止';
    
    addNotification('扫描停止', '资产扫描已手动停止', 'warning');
  }
  
  // 完成扫描
  function completeScan() {
    isScanning = false;
    
    if (scanInterval) {
      clearInterval(scanInterval);
      scanInterval = null;
    }
    
    // 更新UI状态
    if (startBtn) startBtn.textContent = '开始扫描';
    if (statusEl) statusEl.textContent = '扫描完成';
    
    // 生成并显示扫描报告
    const scanResults = generateScanReport();
    
    // 执行资产分析
    const analysisResults = analyzeAssets(scanResults);
    
    // 更新资产分析结果
    updateAssetAnalysis(analysisResults);
    
    logger.info('资产扫描和分析已完成');
    addNotification('扫描完成', '资产扫描已成功完成', 'success');
    showToast('扫描完成', 'success');
  }
  
  // 模拟资产发现
  function simulateAssetDiscovery() {
    // 这里可以添加实时发现资产的逻辑
    console.log('发现新资产');
  }
  
  // 生成扫描报告
  function generateScanReport() {
    // 模拟扫描结果
    const hostsFound = Math.floor(Math.random() * 20) + 5;
    const openPorts = Math.floor(Math.random() * 100) + 20;
    const vulnerabilities = Math.floor(Math.random() * 15) + 3;
    
    // 更新报告内容
    if (reportEl) {
      reportEl.innerHTML = `
        <div class="scan-summary">
          <h3>扫描摘要</h3>
          <div class="summary-item">
            <span>扫描时间:</span>
            <span>${new Date().toLocaleString()}</span>
          </div>
          <div class="summary-item">
            <span>扫描范围:</span>
            <span>${cidrEl?.value || '未指定'}</span>
          </div>
          <div class="summary-item">
            <span>扫描模式:</span>
            <span>${modelEl?.value || 'basic'}</span>
          </div>
          <div class="summary-item">
            <span>发现主机:</span>
            <span class="highlight">${hostsFound}</span>
          </div>
          <div class="summary-item">
            <span>开放端口:</span>
            <span class="highlight">${openPorts}</span>
          </div>
          <div class="summary-item">
            <span>发现漏洞:</span>
            <span class="warning">${vulnerabilities}</span>
          </div>
        </div>
      `;
    }
    
    // 更新主机列表
    if (tableEl) {
      let tableHTML = `
        <table class="scan-results-table">
          <thead>
            <tr>
              <th>IP地址</th>
              <th>主机名</th>
              <th>操作系统</th>
              <th>开放端口</th>
              <th>风险等级</th>
            </tr>
          </thead>
          <tbody>
      `;
      
      // 模拟生成主机数据
      for (let i = 0; i < hostsFound; i++) {
        const ip = `192.168.1.${100 + i}`;
        const hostname = `host-${i + 1}`;
        const os = ['Windows 10', 'Ubuntu 20.04', 'CentOS 7', 'macOS Catalina', 'Unknown'][Math.floor(Math.random() * 5)];
        const portCount = Math.floor(Math.random() * 10) + 1;
        const riskLevel = ['低', '中', '高', '严重'][Math.floor(Math.random() * 4)];
        
        tableHTML += `
          <tr>
            <td>${ip}</td>
            <td>${hostname}</td>
            <td>${os}</td>
            <td>${portCount}</td>
            <td class="risk-${riskLevel}">${riskLevel}</td>
          </tr>
        `;
      }
      
      tableHTML += `
          </tbody>
        </table>
      `;
      
      tableEl.innerHTML = tableHTML;
    }
    
    // 更新端口详情
    if (portTableEl) {
      let portTableHTML = `
        <table class="port-details-table">
          <thead>
            <tr>
              <th>端口</th>
              <th>服务</th>
              <th>版本</th>
              <th>状态</th>
              <th>风险</th>
            </tr>
          </thead>
          <tbody>
      `;
      
      // 常用服务端口列表
      const commonPorts = [
        { port: 21, service: 'FTP', versions: ['vsftpd 2.3.4', 'ProFTPD 1.3.3c', 'FileZilla 0.9.41'] },
        { port: 22, service: 'SSH', versions: ['OpenSSH 7.6p1', 'OpenSSH 8.2p1', 'Dropbear 2019.78'] },
        { port: 23, service: 'Telnet', versions: ['tnftpd 20100324', 'in.telnetd'] },
        { port: 25, service: 'SMTP', versions: ['Postfix 3.4.13', 'Sendmail 8.15.2', 'Exim 4.94'] },
        { port: 80, service: 'HTTP', versions: ['Apache 2.4.41', 'Nginx 1.18.0', 'IIS 10.0'] },
        { port: 443, service: 'HTTPS', versions: ['Apache 2.4.41', 'Nginx 1.18.0', 'IIS 10.0'] },
        { port: 3306, service: 'MySQL', versions: ['5.7.32', '8.0.22', 'MariaDB 10.4.13'] },
        { port: 5432, service: 'PostgreSQL', versions: ['9.6.20', '12.4', '13.0'] },
        { port: 8080, service: 'HTTP-Proxy', versions: ['Apache Tomcat 8.5.57', 'Nginx 1.18.0', 'Jetty 9.4.31'] },
        { port: 8443, service: 'HTTPS-Proxy', versions: ['Apache Tomcat 8.5.57', 'Nginx 1.18.0'] }
      ];
      
      // 随机选择一些开放端口
      const selectedPorts = [];
      while (selectedPorts.length < Math.min(openPorts, 20)) {
        const randomPort = commonPorts[Math.floor(Math.random() * commonPorts.length)];
        if (!selectedPorts.find(p => p.port === randomPort.port)) {
          selectedPorts.push(randomPort);
        }
      }
      
      // 生成端口表格
      selectedPorts.forEach(portInfo => {
        const version = portInfo.versions[Math.floor(Math.random() * portInfo.versions.length)];
        const status = ['开放', '过滤'][Math.floor(Math.random() * 2)];
        const risk = ['低', '中', '高'][Math.floor(Math.random() * 3)];
        
        portTableHTML += `
          <tr>
            <td>${portInfo.port}</td>
            <td>${portInfo.service}</td>
            <td>${version}</td>
            <td>${status}</td>
            <td class="risk-${risk}">${risk}</td>
          </tr>
        `;
      });
      
      portTableHTML += `
          </tbody>
        </table>
      `;
      
      portTableEl.innerHTML = portTableHTML;
    }
    
    // 更新情报信息
    if (intelEl) {
      intelEl.innerHTML = `
        <div class="threat-intel">
          <h3>威胁情报摘要</h3>
          <p>在扫描过程中发现了 ${vulnerabilities} 个潜在的安全问题。</p>
          <p>建议对高风险和严重风险的主机进行进一步检查和加固。</p>
          <div class="intel-tips">
            <h4>安全建议:</h4>
            <ul>
              <li>关闭不必要的开放端口</li>
              <li>更新所有服务到最新版本</li>
              <li>配置防火墙规则限制访问</li>
              <li>定期进行安全扫描和渗透测试</li>
            </ul>
          </div>
        </div>
      `;
    }
  }
  
  // 修复按钮事件
  if (btnRemediate) {
    btnRemediate.addEventListener('click', () => {
      showLoading();
      
      // 模拟修复过程
      setTimeout(() => {
        if (remediationEl) {
          remediationEl.innerHTML = `
            <div class="remediation-report">
              <h3>修复报告</h3>
              <p>已应用以下修复措施:</p>
              <ul>
                <li>关闭了3个高风险端口</li>
                <li>更新了2个过时的服务</li>
                <li>应用了防火墙规则限制访问</li>
                <li>禁用了不必要的服务</li>
              </ul>
              <p class="remediation-status success">修复过程完成，建议重新扫描验证修复效果。</p>
            </div>
          `;
        }
        
        addNotification('修复完成', '自动修复措施已成功应用', 'success');
        showToast('修复完成', 'success');
        
        hideLoading();
      }, 2000);
    });
  }
  
  // 打印按钮事件
  if (btnPrint) {
    btnPrint.addEventListener('click', () => {
      // 模拟打印功能
      showToast('正在准备打印报告...');
      setTimeout(() => {
        window.print();
      }, 500);
    });
  }
}

// 安全态势感知功能
function setupSecurityPosture() {
  logger.info('设置安全态势感知功能');
  
  // 初始化态势感知仪表盘
  initSecurityDashboard();
  
  // 设置事件监听
  const btnSitStart = document.getElementById('btn-sit-start');
  if (btnSitStart) {
    btnSitStart.addEventListener('click', refreshSecurityDashboard);
  }
  
  // 告警严重级别筛选
  const alertSeverityFilter = document.getElementById('alert-severity-filter');
  if (alertSeverityFilter) {
    alertSeverityFilter.addEventListener('change', () => {
      filterAlerts();
    });
  }
  
  // 刷新告警按钮
  const refreshAlertsBtn = document.getElementById('refresh-alerts-btn');
  if (refreshAlertsBtn) {
    refreshAlertsBtn.addEventListener('click', generateRealTimeAlerts);
  }
}

// 初始化安全仪表盘
function initSecurityDashboard() {
  // 生成安全评分
  generateSecurityScore();
  
  // 生成风险指标
  generateRiskMetrics();
  
  // 生成威胁统计
  generateThreatStats();
  
  // 生成事件时间线
  generateEventTimeline();
  
  // 生成资产分布
  generateAssetDistribution();
  
  // 生成安全建议
  generateSecurityRecommendations();
  
  // 生成实时告警
  generateRealTimeAlerts();
  
  // 启动实时监控
  startRealTimeMonitoring();
}

function generateRealTimeAlerts() {
  const list = document.getElementById('alerts-list');
  const filter = document.getElementById('alert-severity-filter');
  if (!list) return;
  const severity = filter?.value || 'all';
  const severities = ['critical','high','medium','low'];
  const samples = Array.from({ length: 8 }).map(() => {
    const s = severities[Math.floor(Math.random()*severities.length)];
    return {
      time: new Date(Date.now()-Math.floor(Math.random()*3600000)).toLocaleString(),
      type: ['DDoS','端口扫描','暴力破解','SQL注入','XSS','恶意软件'][Math.floor(Math.random()*6)],
      severity: s,
      source: `192.168.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`
    };
  });
  const data = severity==='all' ? samples : samples.filter(x=>x.severity===severity);
  let html = '';
  data.forEach(item => {
    html += `<div class="alert-item alert-${item.severity}">\n`+
            `  <div class="alert-time">${item.time}</div>\n`+
            `  <div class="alert-type">${item.type}</div>\n`+
            `  <div class="alert-source">来源IP: ${item.source}</div>\n`+
            `  <div class="alert-severity">${item.severity}</div>\n`+
            `</div>`;
  });
  list.innerHTML = html || '<div class="status">暂无告警</div>';
}

// 刷新安全仪表盘
function refreshSecurityDashboard() {
  showLoading();
  
  // 模拟数据加载延迟
  setTimeout(() => {
    initSecurityDashboard();
    hideLoading();
    addNotification('仪表盘已刷新', '安全态势数据已更新', 'success');
  }, 1000);
}

// 生成安全评分
function generateSecurityScore() {
  // 模拟安全评分
  const score = Math.floor(Math.random() * 20) + 70; // 70-90之间的分数
  
  // 更新风险评分
  const riskScoreEl = document.getElementById('risk-score');
  if (riskScoreEl) {
    riskScoreEl.textContent = score;
  }
  
  // 更新威胁数量
  const threatCountEl = document.getElementById('threat-count');
  if (threatCountEl) {
    threatCountEl.textContent = Math.floor(Math.random() * 50) + 10; // 10-60之间的威胁数量
  }
  
  // 更新资产数量
  const assetCountEl = document.getElementById('asset-count');
  if (assetCountEl) {
    assetCountEl.textContent = Math.floor(Math.random() * 200) + 50; // 50-250之间的资产数量
  }
  
  // 更新事件数量
  const incidentCountEl = document.getElementById('incident-count');
  if (incidentCountEl) {
    incidentCountEl.textContent = Math.floor(Math.random() * 30) + 5; // 5-35之间的事件数量
  }
}

// 生成风险指标
function generateRiskMetrics() {
  // 更新态势报告
  const sitReportEl = document.getElementById('sit-report');
  if (sitReportEl) {
    const metrics = [
      { name: '高危漏洞', value: Math.floor(Math.random() * 5) + 1, unit: '个', type: 'high' },
      { name: '中危漏洞', value: Math.floor(Math.random() * 15) + 5, unit: '个', type: 'medium' },
      { name: '开放端口', value: Math.floor(Math.random() * 50) + 20, unit: '个', type: 'info' },
      { name: '异常登录', value: Math.floor(Math.random() * 10) + 1, unit: '次', type: 'warning' },
      { name: '可疑活动', value: Math.floor(Math.random() * 20) + 5, unit: '次', type: 'warning' },
      { name: '合规项', value: Math.floor(Math.random() * 10) + 80, unit: '%', type: 'good' }
    ];
    
    let reportContent = '=== 风险指标 ===\n\n';
    metrics.forEach(metric => {
      reportContent += `${metric.name}: ${metric.value}${metric.unit}\n`;
    });
    
    sitReportEl.textContent = reportContent;
  }
}

// 生成威胁统计
function generateThreatStats() {
  // 更新情报趋势
  const sitFeedsEl = document.getElementById('sit-feeds');
  if (sitFeedsEl) {
    const threats = [
      { type: 'DDoS攻击', count: Math.floor(Math.random() * 20) + 5, trend: Math.random() > 0.5 ? 'up' : 'down' },
      { type: '恶意软件', count: Math.floor(Math.random() * 15) + 3, trend: Math.random() > 0.5 ? 'up' : 'down' },
      { type: '暴力破解', count: Math.floor(Math.random() * 30) + 10, trend: Math.random() > 0.5 ? 'up' : 'down' },
      { type: '数据泄露', count: Math.floor(Math.random() * 5) + 1, trend: Math.random() > 0.5 ? 'up' : 'down' },
      { type: '内部威胁', count: Math.floor(Math.random() * 8) + 2, trend: Math.random() > 0.5 ? 'up' : 'down' },
      { type: '钓鱼攻击', count: Math.floor(Math.random() * 25) + 8, trend: Math.random() > 0.5 ? 'up' : 'down' }
    ];
    
    let feedsHTML = '<h3>威胁趋势</h3><div class="threat-trends">';
    
    threats.forEach(threat => {
      const trendIcon = threat.trend === 'up' ? '↑' : '↓';
      const trendColor = threat.trend === 'up' ? 'warning' : 'success';
      
      feedsHTML += `
        <div class="threat-trend-item">
          <div class="threat-type">${threat.type}</div>
          <div class="threat-count">${threat.count}</div>
          <div class="threat-trend ${trendColor}">${trendIcon}</div>
        </div>
      `;
    });
    
    feedsHTML += '</div>';
    sitFeedsEl.innerHTML = feedsHTML;
  }
}

// 生成事件时间线
function generateEventTimeline() {
  // 更新资产情报
  const sitIntelEl = document.getElementById('sit-intel');
  if (sitIntelEl) {
    const eventTypes = [
      '安全扫描完成',
      '发现新漏洞',
      '用户异常登录',
      '系统更新',
      '防火墙规则变更',
      '检测到可疑流量',
      '服务重启',
      '配置更改'
    ];
    
    const eventSeverity = ['low', 'medium', 'high', 'critical'];
    
    let intelHTML = '<h3>最近安全事件</h3><div class="event-timeline">';
    
    // 生成最近24小时的事件
    for (let i = 23; i >= 0; i -= Math.floor(Math.random() * 3) + 1) {
      const hour = i;
      const eventType = eventTypes[Math.floor(Math.random() * eventTypes.length)];
      const severity = eventSeverity[Math.floor(Math.random() * eventSeverity.length)];
      const timestamp = `${hour.toString().padStart(2, '0')}:${Math.floor(Math.random() * 60).toString().padStart(2, '0')}`;
      
      intelHTML += `
        <div class="event-item event-${severity}">
          <div class="event-time">${timestamp}</div>
          <div class="event-content">
            <div class="event-type">${eventType}</div>
            <div class="event-desc">这是一个${severity === 'low' ? '低风险' : severity === 'medium' ? '中风险' : severity === 'high' ? '高风险' : '严重'}的安全事件</div>
          </div>
        </div>
      `;
    }
    
    intelHTML += '</div>';
    sitIntelEl.innerHTML = intelHTML;
  }
}

// 生成资产分布
function generateAssetDistribution() {
  // 更新态势报告
  const sitReportEl = document.getElementById('sit-report');
  if (sitReportEl) {
    const assets = [
      { type: '服务器', count: Math.floor(Math.random() * 50) + 10 },
      { type: '工作站', count: Math.floor(Math.random() * 100) + 30 },
      { type: '网络设备', count: Math.floor(Math.random() * 30) + 5 },
      { type: '数据库', count: Math.floor(Math.random() * 15) + 3 },
      { type: '应用服务', count: Math.floor(Math.random() * 25) + 8 },
      { type: 'IoT设备', count: Math.floor(Math.random() * 40) + 15 }
    ];
    
    // 获取当前报告内容
    let reportContent = sitReportEl.textContent;
    
    // 添加资产分布
    reportContent += '\n\n=== 资产分布 ===\n\n';
    assets.forEach(asset => {
      const percentage = Math.round((asset.count / assets.reduce((sum, a) => sum + a.count, 0)) * 100);
      reportContent += `${asset.type}: ${asset.count} (${percentage}%)\n`;
    });
    
    sitReportEl.textContent = reportContent;
  }
}

// 生成安全建议
function generateSecurityRecommendations() {
  if (securityRecommendationsEl) {
    const recommendations = [
      { title: '更新操作系统和软件', priority: 'high', description: '发现多个系统和应用程序版本过旧，存在已知漏洞。' },
      { title: '加强密码策略', priority: 'medium', description: '建议实施更严格的密码策略，包括复杂性要求和定期更换。' },
      { title: '配置入侵检测系统', priority: 'high', description: '启用并配置IDS/IPS系统以实时监控可疑活动。' },
      { title: '定期安全培训', priority: 'low', description: '为员工提供安全意识培训，特别是针对钓鱼攻击的识别。' },
      { title: '实施网络分段', priority: 'medium', description: '将网络划分为不同的安全区域，限制横向移动。' },
      { title: '备份关键数据', priority: 'high', description: '确保所有关键数据都有定期备份，并测试恢复流程。' }
    ];
    
    let recommendationsHTML = '<div class="security-recommendations">';
    
    recommendations.forEach((rec, index) => {
      recommendationsHTML += `
        <div class="recommendation-item priority-${rec.priority}">
          <div class="rec-header">
            <div class="rec-title">${rec.title}</div>
            <div class="rec-priority">${rec.priority === 'high' ? '高' : rec.priority === 'medium' ? '中' : '低'}优先级</div>
          </div>
          <div class="rec-description">${rec.description}</div>
          <button class="rec-action" onclick="window.app.markRecommendationAsDone(${index})")>标记为已完成</button>
        </div>
      `;
    });
    
    recommendationsHTML += '</div>';
    securityRecommendationsEl.innerHTML = recommendationsHTML;
  }
}

// 标记建议为已完成
function markRecommendationAsDone(index) {
  addNotification('建议已更新', '已将安全建议标记为已完成', 'info');
  // 这里可以添加更多逻辑，比如更新UI或存储状态
}

// 切换威胁详情显示
function toggleThreatDetails() {
  if (threatDetailsEl) {
    threatDetailsEl.classList.toggle('hidden');
    if (threatDetailsToggle) {
      threatDetailsToggle.textContent = threatDetailsEl.classList.contains('hidden') ? '显示详情' : '隐藏详情';
    }
  }
}

// 启动实时监控
function startRealTimeMonitoring() {
  // 模拟实时监控，定期生成新事件
  setInterval(() => {
    if (Math.random() > 0.7) { // 30%的概率生成新事件
      const eventTypes = [
        { type: '新威胁检测', severity: 'high' },
        { type: '异常行为', severity: 'medium' },
        { type: '新资产发现', severity: 'info' },
        { type: '配置更改', severity: 'warning' }
      ];
      
      const randomEvent = eventTypes[Math.floor(Math.random() * eventTypes.length)];
      addNotification(randomEvent.type, `检测到${randomEvent.type}事件`, randomEvent.severity);
      
      // 更新实时状态指示器
      if (realtimeIndicatorEl) {
        realtimeIndicatorEl.classList.add('pulse');
        setTimeout(() => {
          realtimeIndicatorEl.classList.remove('pulse');
        }, 1000);
      }
    }
  }, 15000); // 每15秒检查一次
}

// 登出函数
function logout() {
  const username = state.user?.username || '未知用户';
  state.user = null;
  localStorage.removeItem('user');
  showView('login');
  updateNavigation();
  showToast('已成功登出', 'success');
  addNotification('用户登出', `${username} 已登出系统`, 'info');
}

// 通知功能
function showToast(message, type = 'info') {
  if (!toastContainer) return;
  
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  
  toastContainer.appendChild(toast);
  
  setTimeout(() => {
    toast.classList.add('show');
  }, 10);
  
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => {
      if (toastContainer.contains(toast)) {
        toastContainer.removeChild(toast);
      }
    }, 300);
  }, 3000);
}

// 添加通知
function addNotification(title, message, type = 'info') {
  const notification = {
    id: Date.now(),
    title,
    message,
    type,
    time: new Date().toLocaleString()
  };
  
  state.notifications.unshift(notification);
  
  // 限制通知数量
  if (state.notifications.length > 20) {
    state.notifications.pop();
  }
  
  updateNotificationList();
  updateNotificationCount();
  try {
    window.dispatchEvent(new CustomEvent('app:notification', { detail: notification }));
  } catch {}
  
  return notification.id;
}

// 更新通知列表
function updateNotificationList() {
  if (!notifications) return;
  
  notifications.innerHTML = '';
  
  state.notifications.forEach(notification => {
    const item = document.createElement('div');
    item.className = `notification notification-${notification.type}`;
    
    item.innerHTML = `
      <div class="notification-title">${notification.title}</div>
      <div class="notification-message">${notification.message}</div>
      <div class="notification-time">${notification.time}</div>
    `;
    
    notifications.appendChild(item);
  });
}

// 更新通知计数
function updateNotificationCount() {
  const notificationBadge = document.createElement('span');
  notificationBadge.className = 'notification-badge';
  notificationBadge.textContent = state.notifications.length;
  
  if (btnNotifications && state.notifications.length > 0) {
    // 移除旧的徽章
    const oldBadge = btnNotifications.querySelector('.notification-badge');
    if (oldBadge) btnNotifications.removeChild(oldBadge);
    
    btnNotifications.appendChild(notificationBadge);
  } else if (btnNotifications && state.notifications.length === 0) {
    const oldBadge = btnNotifications.querySelector('.notification-badge');
    if (oldBadge) btnNotifications.removeChild(oldBadge);
  }
}

// 更新系统信息
function updateSystemInfo() {
  // 更新日期时间
  if (dateTime) {
    setInterval(() => {
      dateTime.textContent = new Date().toLocaleString('zh-CN');
    }, 1000);
    dateTime.textContent = new Date().toLocaleString('zh-CN');
  }
  
  // 更新时区
  if (timeZone) {
    timeZone.textContent = Intl.DateTimeFormat().resolvedOptions().timeZone;
  }
  
  // 模拟系统状态更新
  if (systemHealth) systemHealth.textContent = '良好';
  if (networkStatus) networkStatus.textContent = '已连接';
  
  // 模拟资源使用情况
  updateResourceUsage();
  setInterval(updateResourceUsage, 5000);
}

// 更新资源使用情况
function updateResourceUsage() {
  // 模拟CPU使用率
  if (cpuUsage) {
    const cpuValue = Math.floor(Math.random() * 30) + 5; // 5-35%
    cpuUsage.textContent = `${cpuValue}%`;
  }
  
  // 模拟内存使用率
  if (memoryUsage) {
    const memValue = Math.floor(Math.random() * 40) + 20; // 20-60%
    memoryUsage.textContent = `${memValue}%`;
  }
  
  // 模拟存储信息
  if (storageInfo) {
    storageInfo.textContent = '75% 已使用';
  }
  
  // 模拟带宽使用
  if (bandwidth) {
    const bandwidthValue = (Math.random() * 100).toFixed(2);
    bandwidth.textContent = `${bandwidthValue} MB/s`;
  }
  
  // 模拟运行时间
  if (uptime) {
    uptime.textContent = '12h 35m 22s';
  }
}

// 初始化仪表盘数据
function initDashboard() {
  if (!dashboardCards || !dashboardStats || !dashboardQuickActions) return;
  
  // 设置仪表盘卡片
  dashboardCards.innerHTML = `
    <div class="card">
      <h3>安全事件</h3>
      <div class="card-value">12</div>
      <div class="card-change">+2 今日</div>
    </div>
    <div class="card">
      <h3>活跃威胁</h3>
      <div class="card-value">3</div>
      <div class="card-change">0 今日</div>
    </div>
    <div class="card">
      <h3>扫描主机</h3>
      <div class="card-value">45</div>
      <div class="card-change">+5 今日</div>
    </div>
    <div class="card">
      <h3>开放端口</h3>
      <div class="card-value">128</div>
      <div class="card-change">+10 今日</div>
    </div>
  `;
  
  // 设置仪表盘统计
  dashboardStats.innerHTML = `
    <div class="stats-row">
      <span>平均响应时间: 2.3s</span>
      <span>威胁检测率: 98.7%</span>
      <span>误报率: 1.2%</span>
    </div>
  `;
  
  // 设置快速操作
  dashboardQuickActions.innerHTML = `
    <button class="quick-action" onclick="showView('baseline')">开始基线扫描</button>
    <button class="quick-action" onclick="showView('situation')">查看安全态势</button>
    <button class="quick-action" onclick="showView('ids')">启动IDS</button>
    <button class="quick-action" onclick="showView('defense')">配置防御策略</button>
  `;
  
  // 设置仪表盘图表（占位符）
  if (dashboardCharts) {
    dashboardCharts.innerHTML = `<div class="chart-placeholder">安全事件趋势图表</div>`;
  }
}

// 增强的初始化函数
  function init() {
    logger.info('应用初始化');
    
    // 检查登录状态
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      try {
        state.user = JSON.parse(savedUser);
        logger.info('用户已登录:', state.user.username);
      } catch (e) {
        logger.error('解析用户数据失败:', e);
        showError('解析用户数据失败');
      }
    }
    
    // 设置导航
    setupNavigation();
    
    // 设置登录功能
    setupLogin();
    
    // 设置注册功能
    setupRegister();
    
    // 设置资产扫描功能
    setupAssetScanning();
    
    // 设置安全态势感知功能
    setupSecurityPosture();
    
    // 设置日志记录功能
    setupLogging();
    
    // 设置应急响应功能
    setupIncidentResponse();
    
    // 设置漏洞修复功能
    setupVulnerabilityRemediation();
    
    // 设置AI对话功能
    setupAIChat();
    
    // 设置基线排查功能
    setupBaselineScanning();
    
    // 设置自动防御（无人值守）功能
    setupDefense();
    
    // 设置边缘设备管理功能
    setupEdgeDeviceManagement();
    
    // 设置配置功能
    setupConfig();
    
    // 设置入侵检测系统功能
    setupIDS();
    
    // 更新导航状态
    updateNavigation();
    
    // 更新系统信息
    updateSystemInfo();
    
    // 初始化仪表盘（如果已登录）
    if (state.user) {
      showView('dashboard');
      initDashboard();
      addNotification('自动登录', `欢迎回来，${state.user.username}`, 'success');
    } else {
      showView('login');
    }
    
    // 添加示例通知
    addNotification('系统启动', '安全监控系统已成功启动', 'success');
    
    console.log('初始化完成');
  }
  
  // 资产分析函数
  function analyzeAssets(scanResults) {
    logger.info('开始资产分析');
    
    // 计算风险分布
    const riskDistribution = {
      low: Math.floor(scanResults.hostsFound * 0.6),
      medium: Math.floor(scanResults.hostsFound * 0.3),
      high: Math.floor(scanResults.hostsFound * 0.1)
    };
    
    // 计算资产分类
    const assetCategories = {
      servers: Math.floor(scanResults.hostsFound * 0.4),
      workstations: Math.floor(scanResults.hostsFound * 0.5),
      networkDevices: Math.floor(scanResults.hostsFound * 0.1)
    };
    
    // 计算漏洞统计
    const vulnerabilityStats = {
      critical: Math.floor(scanResults.vulnerabilities * 0.2),
      high: Math.floor(scanResults.vulnerabilities * 0.3),
      medium: Math.floor(scanResults.vulnerabilities * 0.3),
      low: Math.floor(scanResults.vulnerabilities * 0.2)
    };
    
    // 计算开放服务统计
    const serviceStats = {
      web: Math.floor(scanResults.openPorts * 0.4),
      database: Math.floor(scanResults.openPorts * 0.2),
      remoteAccess: Math.floor(scanResults.openPorts * 0.2),
      other: Math.floor(scanResults.openPorts * 0.2)
    };
    
    // 生成安全建议
    const recommendations = [
      '关闭不必要的开放端口',
      '更新所有系统和服务到最新版本',
      '实施严格的访问控制策略',
      '加强网络分段',
      '定期进行漏洞扫描和安全审计'
    ];
    
    logger.info('资产分析完成');
    
    return {
      riskDistribution,
      assetCategories,
      vulnerabilityStats,
      serviceStats,
      recommendations,
      analysisTime: new Date()
    };
  }
  
  // 更新资产分析结果
  function updateAssetAnalysis(analysisResults) {
    logger.info('更新资产分析结果显示');
    
    // 创建资产分析结果显示区域
    const analysisContainer = document.createElement('div');
    analysisContainer.className = 'asset-analysis-container';
    
    analysisContainer.innerHTML = `
      <div class="asset-analysis-section">
        <h3>资产分析报告</h3>
        
        <div class="analysis-grid">
          <!-- 风险分布 -->
          <div class="analysis-card">
            <h4>风险分布</h4>
            <div class="risk-distribution">
              <div class="risk-item">
                <span class="risk-label">低风险:</span>
                <span class="risk-value">${analysisResults.riskDistribution.low}</span>
              </div>
              <div class="risk-item">
                <span class="risk-label">中风险:</span>
                <span class="risk-value">${analysisResults.riskDistribution.medium}</span>
              </div>
              <div class="risk-item">
                <span class="risk-label">高风险:</span>
                <span class="risk-value">${analysisResults.riskDistribution.high}</span>
              </div>
            </div>
          </div>
          
          <!-- 资产分类 -->
          <div class="analysis-card">
            <h4>资产分类</h4>
            <div class="asset-categories">
              <div class="category-item">
                <span class="category-label">服务器:</span>
                <span class="category-value">${analysisResults.assetCategories.servers}</span>
              </div>
              <div class="category-item">
                <span class="category-label">工作站:</span>
                <span class="category-value">${analysisResults.assetCategories.workstations}</span>
              </div>
              <div class="category-item">
                <span class="category-label">网络设备:</span>
                <span class="category-value">${analysisResults.assetCategories.networkDevices}</span>
              </div>
            </div>
          </div>
          
          <!-- 漏洞统计 -->
          <div class="analysis-card">
            <h4>漏洞统计</h4>
            <div class="vulnerability-stats">
              <div class="vuln-item">
                <span class="vuln-label">严重:</span>
                <span class="vuln-value">${analysisResults.vulnerabilityStats.critical}</span>
              </div>
              <div class="vuln-item">
                <span class="vuln-label">高:</span>
                <span class="vuln-value">${analysisResults.vulnerabilityStats.high}</span>
              </div>
              <div class="vuln-item">
                <span class="vuln-label">中:</span>
                <span class="vuln-value">${analysisResults.vulnerabilityStats.medium}</span>
              </div>
              <div class="vuln-item">
                <span class="vuln-label">低:</span>
                <span class="vuln-value">${analysisResults.vulnerabilityStats.low}</span>
              </div>
            </div>
          </div>
          
          <!-- 开放服务 -->
          <div class="analysis-card">
            <h4>开放服务</h4>
            <div class="service-stats">
              <div class="service-item">
                <span class="service-label">Web服务:</span>
                <span class="service-value">${analysisResults.serviceStats.web}</span>
              </div>
              <div class="service-item">
                <span class="service-label">数据库:</span>
                <span class="service-value">${analysisResults.serviceStats.database}</span>
              </div>
              <div class="service-item">
                <span class="service-label">远程访问:</span>
                <span class="service-value">${analysisResults.serviceStats.remoteAccess}</span>
              </div>
              <div class="service-item">
                <span class="service-label">其他:</span>
                <span class="service-value">${analysisResults.serviceStats.other}</span>
              </div>
            </div>
          </div>
        </div>
        
        <!-- 安全建议 -->
        <div class="analysis-card recommendations">
          <h4>安全建议</h4>
          <ul class="recommendations-list">
            ${analysisResults.recommendations.map(rec => `<li>${rec}</li>`).join('')}
          </ul>
        </div>
        
        <!-- 分析时间 -->
        <div class="analysis-footer">
          <span>分析时间: ${analysisResults.analysisTime.toLocaleString()}</span>
        </div>
      </div>
    `;
    
    // 将分析结果添加到页面
    const scanResultsContainer = document.querySelector('.scan-results');
    if (scanResultsContainer) {
      // 检查是否已存在分析结果，如果存在则替换
      const existingAnalysis = scanResultsContainer.querySelector('.asset-analysis-container');
      if (existingAnalysis) {
        existingAnalysis.remove();
      }
      scanResultsContainer.appendChild(analysisContainer);
    }
  }
  
  // 应急响应功能
  function setupIncidentResponse() {
    logger.info('设置应急响应功能');
    
    // 应急响应状态
    let isResponding = false;
    let currentIncident = null;
    
    // 加载应急响应预案
    const loadIncidentPlan = () => {
      logger.info('加载应急响应预案');
      
      const incidentResponseContent = document.getElementById('incident-response-content');
      if (incidentResponseContent) {
        incidentResponseContent.innerHTML = `
          <h2>应急响应预案</h2>
          
          <h3>1. 事件分级</h3>
          <div class="incident-levels">
            <div class="level-item">
              <h4>一级（特别重大）</h4>
              <p>影响范围极大，可能导致系统完全瘫痪或数据大规模泄露</p>
            </div>
            <div class="level-item">
              <h4>二级（重大）</h4>
              <p>影响范围较大，可能导致部分系统瘫痪或敏感数据泄露</p>
            </div>
            <div class="level-item">
              <h4>三级（较大）</h4>
              <p>影响范围有限，系统功能部分受限</p>
            </div>
            <div class="level-item">
              <h4>四级（一般）</h4>
              <p>影响范围很小，系统功能基本正常</p>
            </div>
          </div>
          
          <h3>2. 响应流程</h3>
          <div class="response-flow">
            <div class="flow-step">
              <span class="step-number">1</span>
              <div class="step-content">
                <h4>事件检测与报告</h4>
                <p>通过监控系统或人工发现安全事件，立即报告给应急响应团队</p>
              </div>
            </div>
            <div class="flow-step">
              <span class="step-number">2</span>
              <div class="step-content">
                <h4>事件分类与分级</h4>
                <p>根据事件性质、影响范围和严重程度进行分类和分级</p>
              </div>
            </div>
            <div class="flow-step">
              <span class="step-number">3</span>
              <div class="step-content">
                <h4>应急响应启动</h4>
                <p>根据事件级别启动相应的应急响应预案</p>
              </div>
            </div>
            <div class="flow-step">
              <span class="step-number">4</span>
              <div class="step-content">
                <h4>事件处置</h4>
                <p>采取措施遏制事件发展，消除威胁，恢复系统正常运行</p>
              </div>
            </div>
            <div class="flow-step">
              <span class="step-number">5</span>
              <div class="step-content">
                <h4>事件调查与分析</h4>
                <p>对事件进行深入调查，分析事件原因和影响</p>
              </div>
            </div>
            <div class="flow-step">
              <span class="step-number">6</span>
              <div class="step-content">
                <h4>恢复与总结</h4>
                <p>恢复系统正常运行，总结经验教训，完善安全措施</p>
              </div>
            </div>
          </div>
          
          <h3>3. 应急响应团队</h3>
          <div class="response-team">
            <div class="team-role">
              <h4>应急响应负责人</h4>
              <p>负责协调和指挥应急响应工作</p>
            </div>
            <div class="team-role">
              <h4>技术支持人员</h4>
              <p>负责技术分析和系统恢复工作</p>
            </div>
            <div class="team-role">
              <h4>安全分析师</h4>
              <p>负责事件分析和威胁评估</p>
            </div>
            <div class="team-role">
              <h4>通信联络员</h4>
              <p>负责内部和外部沟通协调</p>
            </div>
          </div>
        `;
      }
    };
    
    // 生成模拟事件数据
    const generateMockIncidents = () => {
      const incidents = [];
      const types = ['DDoS攻击', 'SQL注入', '恶意软件', '数据泄露', '权限提升'];
      const statuses = ['未处理', '处理中', '已解决', '已关闭'];
      
      for (let i = 0; i < 10; i++) {
        incidents.push({
          id: `INC-${2024}-${String(i + 1).padStart(3, '0')}`,
          type: types[Math.floor(Math.random() * types.length)],
          severity: ['低', '中', '高'][Math.floor(Math.random() * 3)],
          status: statuses[Math.floor(Math.random() * statuses.length)],
          time: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toLocaleString(),
          description: `检测到${types[Math.floor(Math.random() * types.length)]}事件，影响范围${['有限', '中等', '广泛'][Math.floor(Math.random() * 3)]}`
        });
      }
      
      return incidents;
    };
    
    // 更新事件列表
    const updateIncidentList = () => {
      logger.info('更新事件列表');
      
      const incidents = generateMockIncidents();
      
      if (incidentTable) {
        let tableHTML = `
          <table class="incident-table">
            <thead>
              <tr>
                <th>事件ID</th>
                <th>事件类型</th>
                <th>严重程度</th>
                <th>状态</th>
                <th>发生时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
        `;
        
        incidents.forEach(incident => {
          tableHTML += `
            <tr>
              <td>${incident.id}</td>
              <td>${incident.type}</td>
              <td class="severity-${incident.severity}">${incident.severity}</td>
              <td class="status-${incident.status}">${incident.status}</td>
              <td>${incident.time}</td>
              <td>
                <button class="btn-small" onclick="app.startIncidentResponse('${incident.id}')">响应</button>
                <button class="btn-small" onclick="app.viewIncidentDetails('${incident.id}')">详情</button>
              </td>
            </tr>
          `;
        });
        
        tableHTML += `
            </tbody>
          </table>
        `;
        
        incidentTable.innerHTML = tableHTML;
      }
      
      // 更新事件统计
      const incidentCount = document.getElementById('incident-count');
      if (incidentCount) {
        incidentCount.textContent = incidents.length;
      }
    };
    
    // 开始应急响应
    window.app.startIncidentResponse = (incidentId) => {
      logger.info(`开始处理事件: ${incidentId}`);
      
      isResponding = true;
      currentIncident = incidentId;
      
      if (incidentStatus) {
        incidentStatus.textContent = `正在处理事件: ${incidentId}`;
        incidentStatus.className = 'status warning';
      }
      
      showToast(`开始处理事件: ${incidentId}`, 'info');
      addNotification('应急响应启动', `开始处理事件: ${incidentId}`, 'warning');
    };
    
    // 查看事件详情
    window.app.viewIncidentDetails = (incidentId) => {
      logger.info(`查看事件详情: ${incidentId}`);
      showToast(`查看事件详情: ${incidentId}`, 'info');
    };
    
    // 刷新事件列表
    if (btnIncidentRefresh) {
      btnIncidentRefresh.addEventListener('click', () => {
        updateIncidentList();
        showToast('事件列表已刷新', 'success');
      });
    }
    
    // 打印应急响应预案
    const btnPrintPlan = document.getElementById('btn-print-plan');
    if (btnPrintPlan) {
      btnPrintPlan.addEventListener('click', () => {
        logger.info('打印应急响应预案');
        window.print();
      });
    }
    
    // 下载应急响应预案
    const btnDownloadPlan = document.getElementById('btn-download-plan');
    if (btnDownloadPlan) {
      btnDownloadPlan.addEventListener('click', () => {
        logger.info('下载应急响应预案');
        // 模拟下载功能
        showToast('应急响应预案已下载', 'success');
      });
    }
    
    // 初始化
    loadIncidentPlan();
    updateIncidentList();
    
    if (incidentStatus) {
      incidentStatus.textContent = '就绪';
      incidentStatus.className = 'status success';
    }
  }
  
  // 漏洞修复功能
  function setupVulnerabilityRemediation() {
    logger.info('设置漏洞修复功能');
    
    // 漏洞修复状态
    let isRemediating = false;
    let currentVulnerability = null;
    
    // 生成模拟漏洞数据
    const generateMockVulnerabilities = () => {
      const vulnerabilities = [];
      const types = ['SQL注入', 'XSS跨站脚本', '命令注入', '文件上传漏洞', '权限绕过', '敏感信息泄露', 'CSRF跨站请求伪造', 'XXE外部实体注入'];
      const severities = ['低', '中', '高', '严重'];
      const statuses = ['未修复', '修复中', '已修复', '已忽略'];
      
      for (let i = 0; i < 15; i++) {
        vulnerabilities.push({
          id: `VULN-${2024}-${String(i + 1).padStart(4, '0')}`,
          type: types[Math.floor(Math.random() * types.length)],
          severity: severities[Math.floor(Math.random() * severities.length)],
          status: statuses[Math.floor(Math.random() * statuses.length)],
          location: `http://example.com/api/v${i + 1}/endpoint`,
          description: `检测到${types[Math.floor(Math.random() * types.length)]}漏洞，可能导致${['数据泄露', '系统接管', '权限提升', '拒绝服务'][Math.floor(Math.random() * 4)]}`,
          cve: `CVE-2024-${String(Math.floor(Math.random() * 9999)).padStart(4, '0')}`,
          cvss: (Math.random() * 4 + 6).toFixed(1), // 6.0-10.0之间的CVSS评分
          discoveredTime: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toLocaleString()
        });
      }
      
      return vulnerabilities;
    };
    
    // 生成漏洞修复建议
    const generateRemediationSuggestions = (vulnerability) => {
      const suggestions = {
        'SQL注入': [
          '使用参数化查询或预编译语句',
          '避免直接拼接SQL语句',
          '实施最小权限原则',
          '使用ORM框架处理数据库操作'
        ],
        'XSS跨站脚本': [
          '对所有用户输入进行严格过滤和转义',
          '使用Content-Security-Policy (CSP)头',
          '避免使用innerHTML等不安全的DOM操作',
          '使用现代前端框架的自动转义功能'
        ],
        '命令注入': [
          '避免直接执行用户提供的命令',
          '使用白名单验证允许的命令和参数',
          '使用安全的API替代直接命令执行',
          '实施严格的输入验证和过滤'
        ],
        '文件上传漏洞': [
          '限制允许上传的文件类型',
          '使用随机文件名存储上传文件',
          '将上传文件存储在非Web可访问目录',
          '实施文件内容验证和扫描'
        ],
        '权限绕过': [
          '实施基于角色的访问控制(RBAC)',
          '对所有敏感操作进行权限检查',
          '避免使用可预测的访问控制机制',
          '实施最小权限原则'
        ],
        '敏感信息泄露': [
          '避免在日志中记录敏感信息',
          '使用HTTPS加密传输敏感数据',
          '对敏感数据进行加密存储',
          '实施数据脱敏处理'
        ],
        'CSRF跨站请求伪造': [
          '使用CSRF令牌验证',
          '验证Origin和Referer头',
          '使用SameSite Cookie属性',
          '实施双重提交Cookie技术'
        ],
        'XXE外部实体注入': [
          '禁用XML外部实体处理',
          '使用安全的XML解析器配置',
          '对XML输入进行严格验证',
          '使用JSON替代XML（如果可能）'
        ]
      };
      
      return suggestions[vulnerability.type] || [
        '进行全面的安全审计',
        '更新所有依赖到最新版本',
        '实施严格的输入验证',
        '加强访问控制机制'
      ];
    };
    
    // 显示漏洞修复建议
    const showRemediationSuggestions = () => {
      logger.info('显示漏洞修复建议');
      
      const vulnerabilities = generateMockVulnerabilities();
      
      if (remediationEl) {
        let remediationHTML = `
          <div class="vulnerability-remediation">
            <h3>漏洞修复建议</h3>
            <div class="vulnerability-list">
        `;
        
        vulnerabilities.slice(0, 5).forEach(vuln => {
          const suggestions = generateRemediationSuggestions(vuln);
          
          remediationHTML += `
            <div class="vulnerability-card severity-${vuln.severity}">
              <div class="vulnerability-header">
                <h4>${vuln.id} - ${vuln.type}</h4>
                <span class="cvss-score">CVSS: ${vuln.cvss}</span>
              </div>
              <div class="vulnerability-details">
                <div class="detail-item">
                  <span class="detail-label">严重程度:</span>
                  <span class="detail-value">${vuln.severity}</span>
                </div>
                <div class="detail-item">
                  <span class="detail-label">位置:</span>
                  <span class="detail-value">${vuln.location}</span>
                </div>
                <div class="detail-item">
                  <span class="detail-label">CVE:</span>
                  <span class="detail-value">${vuln.cve}</span>
                </div>
                <div class="detail-item">
                  <span class="detail-label">描述:</span>
                  <span class="detail-value">${vuln.description}</span>
                </div>
              </div>
              <div class="remediation-suggestions">
                <h5>修复建议:</h5>
                <ul>
                  ${suggestions.map(suggestion => `<li>${suggestion}</li>`).join('')}
                </ul>
              </div>
              <div class="remediation-actions">
                <button class="btn-small" onclick="app.remediateVulnerability('${vuln.id}')">立即修复</button>
                <button class="btn-small" onclick="app.ignoreVulnerability('${vuln.id}')">忽略</button>
              </div>
            </div>
          `;
        });
        
        remediationHTML += `
            </div>
          </div>
        `;
        
        remediationEl.innerHTML = remediationHTML;
      }
    };
    
    // 执行漏洞修复
    window.app.remediateVulnerability = (vulnId) => {
      logger.info(`开始修复漏洞: ${vulnId}`);
      
      isRemediating = true;
      currentVulnerability = vulnId;
      
      // 显示修复进度
      if (remediationEl) {
        remediationEl.innerHTML = `
          <div class="remediation-progress">
            <h3>正在修复漏洞</h3>
            <div class="progress-container">
              <div class="progress-bar">
                <div class="progress-fill" style="width: 0%"></div>
              </div>
              <div class="progress-text">0%</div>
            </div>
            <div class="remediation-status">正在修复漏洞: ${vulnId}</div>
          </div>
        `;
      }
      
      // 模拟修复进度
      let progress = 0;
      const progressInterval = setInterval(() => {
        progress += Math.random() * 15;
        if (progress >= 100) {
          progress = 100;
          clearInterval(progressInterval);
          
          // 修复完成
          setTimeout(() => {
            isRemediating = false;
            currentVulnerability = null;
            
            showRemediationSuggestions();
            showToast(`漏洞 ${vulnId} 修复完成`, 'success');
            addNotification('漏洞修复完成', `漏洞 ${vulnId} 已成功修复`, 'success');
          }, 500);
        }
        
        // 更新进度显示
        const progressFill = remediationEl?.querySelector('.progress-fill');
        const progressText = remediationEl?.querySelector('.progress-text');
        if (progressFill && progressText) {
          progressFill.style.width = `${progress}%`;
          progressText.textContent = `${Math.round(progress)}%`;
        }
      }, 500);
    };
    
    // 忽略漏洞
    window.app.ignoreVulnerability = (vulnId) => {
      logger.info(`忽略漏洞: ${vulnId}`);
      showToast(`漏洞 ${vulnId} 已忽略`, 'info');
      addNotification('漏洞已忽略', `漏洞 ${vulnId} 已被忽略`, 'info');
    };
    
    // 修复按钮点击事件
    if (btnRemediate) {
      btnRemediate.addEventListener('click', () => {
        if (isRemediating) {
          showError('正在进行漏洞修复，请稍后再试');
          return;
        }
        
        showRemediationSuggestions();
      });
    }
    
    // 初始化
    showRemediationSuggestions();
  }
  
  // AI对话功能
  function setupAIChat() {
    logger.info('设置AI对话功能');
    
    // AI对话状态
    let isGenerating = false;
    let conversationHistory = [];
    let currentModel = 'deepseek-chat';
    
    // 可用的AI模型列表
    const availableModels = [
      'deepseek-chat',
      'gpt-4',
      'claude-3',
      'gemini-pro',
      'llama-3'
    ];
    
    // 生成模拟AI响应
    const generateAIResponse = (prompt) => {
      const responses = {
        '你好': '你好！我是安全AI助手，有什么可以帮助你的吗？',
        '什么是SQL注入': 'SQL注入是一种常见的Web安全漏洞，攻击者通过在用户输入中插入恶意SQL代码，来操纵数据库查询，从而获取或修改敏感数据。',
        '如何防御XSS攻击': '防御XSS攻击的主要方法包括：1) 对所有用户输入进行严格过滤和转义；2) 使用Content-Security-Policy (CSP)头；3) 避免使用innerHTML等不安全的DOM操作；4) 使用现代前端框架的自动转义功能。',
        '什么是CSRF攻击': 'CSRF（跨站请求伪造）是一种攻击方式，攻击者诱导受害者访问恶意网站，利用受害者的身份在受信任的网站上执行未授权的操作。',
        '如何提高系统安全性': '提高系统安全性的方法包括：1) 定期更新系统和软件；2) 实施严格的访问控制；3) 使用强密码和多因素认证；4) 定期进行安全审计和漏洞扫描；5) 培训员工的安全意识。'
      };
      
      // 查找匹配的响应
      for (const [key, value] of Object.entries(responses)) {
        if (prompt.includes(key)) {
          return value;
        }
      }
      
      // 默认响应
      return `这是一个关于"${prompt}"的详细回答。由于我是一个模拟AI，我无法提供更具体的信息。在实际应用中，这里会调用真实的AI模型来生成详细的安全分析和建议。`;
    };

    async function callAIModel(prompt, timeoutMs) {
      const base = (window.modelBase || '').trim() || document.getElementById('cfg-base')?.value?.trim() || 'http://127.0.0.1:8001';
      const model = (window.modelName || '').trim() || document.getElementById('cfg-model')?.value?.trim() || 'xuangguang-gpt';
      const apiKey = await loadSecurityModelKey();
      if (!base || !model || !apiKey) {
        throw new Error('缺少 API Base/模型/密钥');
      }
      const url = `${base.replace(/\/+$/,'')}/v1/chat/completions`;
      const controller = new AbortController();
      const id = setTimeout(() => controller.abort(), Math.max(3000, parseInt(timeoutMs || document.getElementById('cfg-timeout')?.value || '8000')));
      try {
        const resp = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`
          },
          body: JSON.stringify({
            model,
            messages: [{ role: 'user', content: prompt }],
            stream: false,
            temperature: 0.7
          }),
          signal: controller.signal
        });
        clearTimeout(id);
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}`);
        }
        const data = await resp.json();
        const text = data?.choices?.[0]?.message?.content || data?.choices?.[0]?.text || '';
        if (!text) throw new Error('响应为空');
        return text;
      } catch (e) {
        clearTimeout(id);
        throw e;
      }
    }
    
    // 更新对话历史显示
    const updateConversationHistory = () => {
      logger.info('更新对话历史');
      
      if (aiOutput) {
        let conversationHTML = '';
        
        conversationHistory.forEach(message => {
          const messageClass = message.role === 'user' ? 'chat-message user-message' : 'chat-message bot-message';
          const name = message.role === 'user' ? '你' : '安全助手';
          const avatar = message.role === 'user' ? '🧑' : '🤖';
          conversationHTML += `
            <div class="${messageClass}">
              <div class="chat-header">
                <span class="chat-avatar">${avatar}</span>
                <span class="chat-name">${name}</span>
                <span class="message-time" style="margin-left:auto;">${message.time}</span>
              </div>
              <div class="chat-content">${message.content}</div>
            </div>
          `;
        });
        
        aiOutput.innerHTML = conversationHTML;
        
        // 滚动到底部
        aiOutput.scrollTop = aiOutput.scrollHeight;
      }
    };
    
    // 发送消息
    const sendMessage = async () => {
      if (isGenerating) {
        showError('AI正在生成响应，请稍后再试');
        return;
      }
      
      const message = aiInput?.value.trim();
      if (!message) {
        showError('请输入消息内容');
        return;
      }
      
      logger.info(`发送消息: ${message}`);
      
      // 添加用户消息到对话历史
      const userMessage = {
        role: 'user',
        content: message,
        time: new Date().toLocaleTimeString()
      };
      conversationHistory.push(userMessage);
      updateConversationHistory();
      
      // 清空输入框
      if (aiInput) {
        aiInput.value = '';
      }
      
      // 显示生成状态
      isGenerating = true;
      if (btnAiSend) btnAiSend.disabled = true;
      if (aiStatus) {
        aiStatus.textContent = 'AI正在生成响应...';
        aiStatus.className = 'status warning';
      }
      
      let aiText = '';
      try {
        aiText = await callAIModel(message);
      } catch (err) {
        aiText = generateAIResponse(message);
      }
      const aiMessage = {
        role: 'assistant',
        content: aiText,
        time: new Date().toLocaleTimeString()
      };
      conversationHistory.push(aiMessage);
      updateConversationHistory();
      isGenerating = false;
      if (btnAiSend) btnAiSend.disabled = false;
      if (aiStatus) {
        aiStatus.textContent = '就绪';
        aiStatus.className = 'status success';
      }
      logger.info('AI响应生成完成');
    };
    
    // 发送按钮点击事件
    if (btnAiSend) {
      btnAiSend.addEventListener('click', sendMessage);
    }

    // 测试连接按钮
    const btnAiTest = document.getElementById('chat-test');
    if (btnAiTest) {
      btnAiTest.addEventListener('click', async () => {
        if (isGenerating) return;
        const prompt = '测试连接';
        isGenerating = true;
        if (btnAiSend) btnAiSend.disabled = true;
        btnAiTest.disabled = true;
        if (aiStatus) {
          aiStatus.textContent = '测试连接中...';
          aiStatus.className = 'status warning';
        }
        try {
          const text = await callAIModel(prompt);
          const aiMessage = { role: 'assistant', content: `连接成功：\n${text}`, time: new Date().toLocaleTimeString() };
          conversationHistory.push(aiMessage);
          updateConversationHistory();
          showToast('测试连接成功', 'success');
          addNotification('测试连接成功', 'AI模型已可用', 'success');
          if (aiStatus) { aiStatus.textContent = '就绪'; aiStatus.className = 'status success'; }
        } catch (err) {
          const fallback = generateAIResponse(prompt);
          const aiMessage = { role: 'assistant', content: `连接失败，使用本地模拟：\n${fallback}`, time: new Date().toLocaleTimeString() };
          conversationHistory.push(aiMessage);
          updateConversationHistory();
          showToast('测试连接失败，已回退本地模拟', 'warning');
          addNotification('测试连接失败', String(err), 'error');
          if (aiStatus) { aiStatus.textContent = '就绪'; aiStatus.className = 'status'; }
        } finally {
          isGenerating = false;
          if (btnAiSend) btnAiSend.disabled = false;
          btnAiTest.disabled = false;
        }
      });
    }
    
    // 回车键发送消息
    if (aiInput) {
      aiInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          sendMessage();
        }
      });
    }
    
    // 清空对话历史
    if (btnAiClear) {
      btnAiClear.addEventListener('click', () => {
        logger.info('清空对话历史');
        conversationHistory = [];
        updateConversationHistory();
        showToast('对话历史已清空', 'success');
      });
    }
    
    // 初始化AI模型选择
    if (aiModel) {
      // 添加可用模型到选择框
      availableModels.forEach(model => {
        const option = document.createElement('option');
        option.value = model;
        option.textContent = model;
        if (model === currentModel) {
          option.selected = true;
        }
        aiModel.appendChild(option);
      });
      
      // 模型选择变化事件
      aiModel.addEventListener('change', (e) => {
        currentModel = e.target.value;
        logger.info(`切换AI模型: ${currentModel}`);
        showToast(`已切换到模型: ${currentModel}`, 'info');
      });
    }
    
    // 初始化
    if (aiStatus) {
      aiStatus.textContent = '就绪';
      aiStatus.className = 'status success';
    }
    
    // 添加欢迎消息
    const welcomeMessage = {
      role: 'assistant',
      content: '你好！我是安全AI助手，有什么可以帮助你的吗？\n\n我可以帮助你：\n1. 解释安全概念和漏洞类型\n2. 提供安全防御建议\n3. 分析安全事件\n4. 回答安全相关问题',
      time: new Date().toLocaleTimeString()
    };
    conversationHistory.push(welcomeMessage);
    updateConversationHistory();
  }
  
  // 基线排查功能
  function setupBaselineScanning() {
    logger.info('设置基线排查功能');
    
    // 基线扫描状态
    let isScanning = false;
    
    // 基线规则列表
    const baselineRules = [
      {
        id: 'BASELINE-001',
        name: '密码策略',
        description: '检查系统密码策略是否符合安全要求',
        category: '身份认证',
        severity: '高',
        checkType: '配置检查',
        expectedValue: '密码长度≥8位，包含大小写字母、数字和特殊字符，定期更换',
        actualValue: '密码长度≥6位，无复杂度要求',
        status: '不符合',
        remediation: '修改密码策略，设置更严格的密码复杂度要求'
      },
      {
        id: 'BASELINE-002',
        name: '防火墙配置',
        description: '检查防火墙是否启用并配置正确',
        category: '网络安全',
        severity: '高',
        checkType: '服务检查',
        expectedValue: '防火墙已启用，仅开放必要端口',
        actualValue: '防火墙已启用，但开放了不必要的端口',
        status: '部分符合',
        remediation: '关闭不必要的开放端口，优化防火墙规则'
      },
      {
        id: 'BASELINE-003',
        name: '系统更新',
        description: '检查系统是否及时更新安全补丁',
        category: '系统安全',
        severity: '中',
        checkType: '补丁检查',
        expectedValue: '系统已安装所有重要安全补丁',
        actualValue: '系统有3个重要安全补丁未安装',
        status: '不符合',
        remediation: '及时安装所有重要安全补丁'
      },
      {
        id: 'BASELINE-004',
        name: '权限配置',
        description: '检查系统权限配置是否符合最小权限原则',
        category: '访问控制',
        severity: '中',
        checkType: '配置检查',
        expectedValue: '用户仅拥有必要的最小权限',
        actualValue: '部分用户拥有过高权限',
        status: '不符合',
        remediation: '调整用户权限，实施最小权限原则'
      },
      {
        id: 'BASELINE-005',
        name: '日志配置',
        description: '检查系统日志是否启用并配置正确',
        category: '审计日志',
        severity: '中',
        checkType: '配置检查',
        expectedValue: '系统日志已启用，记录所有重要安全事件',
        actualValue: '系统日志已启用，但日志级别设置过高，遗漏部分安全事件',
        status: '部分符合',
        remediation: '调整日志级别，确保记录所有重要安全事件'
      }
    ];
    
    // 生成模拟扫描结果
    const generateScanResults = () => {
      logger.info('生成基线扫描结果');
      
      // 模拟扫描过程，随机改变部分规则的状态
      const scanResults = [...baselineRules].map(rule => {
        // 随机改变10%的规则状态
        if (Math.random() < 0.1) {
          return {
            ...rule,
            status: ['符合', '不符合', '部分符合'][Math.floor(Math.random() * 3)]
          };
        }
        return rule;
      });
      
      return scanResults;
    };
    
    // 显示基线扫描结果
    const showScanResults = (results) => {
      logger.info('显示基线扫描结果');
      
      // 计算统计信息
      const totalRules = results.length;
      const compliantRules = results.filter(rule => rule.status === '符合').length;
      const partiallyCompliantRules = results.filter(rule => rule.status === '部分符合').length;
      const nonCompliantRules = results.filter(rule => rule.status === '不符合').length;
      const complianceRate = ((compliantRules / totalRules) * 100).toFixed(1);
      
      // 找到基线排查相关的DOM元素
      const baselineContent = document.querySelector('.baseline-content');
      if (baselineContent) {
        let baselineHTML = `
          <div class="baseline-summary">
            <h3>基线扫描摘要</h3>
            <div class="summary-stats">
              <div class="stat-item">
                <span class="stat-label">总规则数:</span>
                <span class="stat-value">${totalRules}</span>
              </div>
              <div class="stat-item success">
                <span class="stat-label">符合规则:</span>
                <span class="stat-value">${compliantRules}</span>
              </div>
              <div class="stat-item warning">
                <span class="stat-label">部分符合:</span>
                <span class="stat-value">${partiallyCompliantRules}</span>
              </div>
              <div class="stat-item error">
                <span class="stat-label">不符合规则:</span>
                <span class="stat-value">${nonCompliantRules}</span>
              </div>
              <div class="stat-item">
                <span class="stat-label">合规率:</span>
                <span class="stat-value">${complianceRate}%</span>
              </div>
            </div>
          </div>
          
          <div class="baseline-results">
            <h3>基线扫描结果</h3>
            <table class="baseline-table">
              <thead>
                <tr>
                  <th>规则ID</th>
                  <th>规则名称</th>
                  <th>类别</th>
                  <th>严重程度</th>
                  <th>状态</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
        `;
        
        results.forEach(rule => {
          baselineHTML += `
            <tr>
              <td>${rule.id}</td>
              <td>${rule.name}</td>
              <td>${rule.category}</td>
              <td class="severity-${rule.severity}">${rule.severity}</td>
              <td class="status-${rule.status}">${rule.status}</td>
              <td>
                <button class="btn-small" onclick="app.viewBaselineRule('${rule.id}')">详情</button>
                <button class="btn-small" onclick="app.fixBaselineIssue('${rule.id}')">修复</button>
              </td>
            </tr>
          `;
        });
        
        baselineHTML += `
              </tbody>
            </table>
          </div>
        `;
        
        baselineContent.innerHTML = baselineHTML;
      }
    };
    
    // 执行基线扫描
    const performBaselineScan = () => {
      if (isScanning) {
        showError('基线扫描正在进行中，请稍后再试');
        return;
      }
      
      logger.info('开始基线扫描');
      isScanning = true;
      
      // 更新状态
      const baselineStatus = document.getElementById('baseline-status');
      if (baselineStatus) {
        baselineStatus.textContent = '扫描中...';
        baselineStatus.className = 'status warning';
      }
      
      // 模拟扫描过程
      setTimeout(() => {
        const results = generateScanResults();
        showScanResults(results);
        
        // 更新状态
        isScanning = false;
        if (baselineStatus) {
          baselineStatus.textContent = '扫描完成';
          baselineStatus.className = 'status success';
        }
        
        logger.info('基线扫描完成');
        showToast('基线扫描已完成', 'success');
        addNotification('基线扫描完成', '系统基线扫描已成功完成', 'success');
      }, 2000);
    };
    
    // 查看基线规则详情
    window.app.viewBaselineRule = (ruleId) => {
      logger.info(`查看基线规则详情: ${ruleId}`);
      const rule = baselineRules.find(r => r.id === ruleId);
      if (rule) {
        showToast(`查看规则: ${rule.name}`, 'info');
        // 这里可以添加显示规则详情的逻辑
      }
    };
    
    // 修复基线问题
    window.app.fixBaselineIssue = (ruleId) => {
      logger.info(`修复基线问题: ${ruleId}`);
      const rule = baselineRules.find(r => r.id === ruleId);
      if (rule) {
        showToast(`正在修复规则: ${rule.name}`, 'info');
        // 模拟修复过程
        setTimeout(() => {
          showToast(`规则 ${rule.name} 修复完成`, 'success');
          addNotification('基线问题修复', `规则 ${rule.name} 已成功修复`, 'success');
        }, 1000);
      }
    };
    
    // 扫描按钮点击事件
    const btnBaselineScan = document.getElementById('btn-baseline-scan');
    if (btnBaselineScan) {
      btnBaselineScan.addEventListener('click', performBaselineScan);
    }
    
    // 初始化
    const baselineStatus = document.getElementById('baseline-status');
    if (baselineStatus) {
      baselineStatus.textContent = '就绪';
      baselineStatus.className = 'status success';
    }
    
    // 初始显示基线规则列表
    showScanResults(baselineRules);
  }
  
  // 导出必要的函数和状态
  window.app = {
    state,
    showView,
    showLoading,
    hideLoading,
    showError,
    showToast,
    addNotification,
    logout,
    markRecommendationAsDone,
    init,
    analyzeAssets,
    updateAssetAnalysis,
    startIncidentResponse: window.app?.startIncidentResponse || (() => {}),
    viewIncidentDetails: window.app?.viewIncidentDetails || (() => {}),
    remediateVulnerability: window.app?.remediateVulnerability || (() => {}),
    ignoreVulnerability: window.app?.ignoreVulnerability || (() => {})
  };

// 自动防御（无人值守）功能
function setupDefense() {
  logger.info('设置自动防御（无人值守）功能');
  
  // 防御状态
  let isDefending = false;
  let defenseInterval = null;
  let autoMode = false;
  
  // 启动防御
  const btnDfStart = document.getElementById('btn-df-start');
  if (btnDfStart) {
    btnDfStart.addEventListener('click', () => {
      if (isDefending) {
        showToast('自动防御已在运行中', 'warning');
        return;
      }
      
      isDefending = true;
      
      // 获取无人值守模式和周期
      const dfAuto = document.getElementById('df-auto');
      const dfInterval = document.getElementById('df-interval');
      
      autoMode = dfAuto?.checked || false;
      const interval = parseInt(dfInterval?.value || '120') * 1000;
      const dfRiskThreshold = document.getElementById('df-risk-threshold');
      const riskThreshold = (dfRiskThreshold?.value || 'medium').toLowerCase();
      if (!window.app) window.app = {};
      window.app.defenseState = { isDefending: true, autoMode, riskThreshold };
      
      // 更新状态
      const dfStatus = document.getElementById('df-status');
      if (dfStatus) {
        dfStatus.textContent = `防御中... ${autoMode ? '（无人值守）' : ''}`;
        dfStatus.className = 'status warning';
      }
      
      // 生成防御报告
      generateDefenseReport();
      
      // 生成已应用动作
      generateAppliedActions();
      
      // 模拟防御过程
      defenseInterval = setInterval(() => {
        simulateDefenseProcess();
      }, interval);
      
      showToast('自动防御已启动', 'success');
      addNotification('自动防御启动', `自动防御系统已成功启动${autoMode ? '（无人值守）' : ''}`, 'info');
    });
  }
  
  // 停止防御
  const btnDfStop = document.getElementById('btn-df-stop');
  if (btnDfStop) {
    btnDfStop.addEventListener('click', () => {
      if (!isDefending) {
        showToast('自动防御未在运行中', 'warning');
        return;
      }
      
      isDefending = false;
      clearInterval(defenseInterval);
      if (!window.app) window.app = {};
      const cur = window.app.defenseState || {};
      window.app.defenseState = { ...cur, isDefending: false };
      
      // 更新状态
      const dfStatus = document.getElementById('df-status');
      if (dfStatus) {
        dfStatus.textContent = '已停止';
        dfStatus.className = 'status';
      }
      
      showToast('自动防御已停止', 'success');
      addNotification('自动防御停止', '自动防御系统已停止', 'info');
    });
  }
  
  // 打印报告
  const btnDfPrint = document.getElementById('btn-df-print');
  if (btnDfPrint) {
    btnDfPrint.addEventListener('click', () => {
      window.print();
      showToast('防御报告已打印', 'success');
    });
  }
  window.addEventListener('app:notification', (e) => {
    if (!isDefending || !autoMode) return;
    const n = e.detail;
    if (!n) return;
    const isIntrusion = (n.title || '').includes('入侵检测');
    const isError = (n.type || '') === 'error';
    if (!(isIntrusion || isError)) return;
    const m = n.message || '';
    const ipMatch = m.match(/来源IP:\s*([\d\.]+)/);
    const target = ipMatch ? ipMatch[1] : '未知目标';
    const el = document.getElementById('df-actions');
    if (el) {
      el.innerHTML += `<div class="defense-action">\n` +
        `  <div class="action-type">阻止可疑IP</div>\n` +
        `  <div class="action-target">目标: ${target}</div>\n` +
        `  <div class="action-result success">成功</div>\n` +
        `  <div class="action-time">${new Date().toLocaleString()}</div>\n` +
        `</div>`;
    }
    generateDefenseReport();
  });
  
  // 模拟防御过程
  function simulateDefenseProcess() {
    if (!isDefending) return;
    
    // 随机生成防御动作
    if (Math.random() > 0.5) {
      const defenseActions = [
        { type: '关闭高危端口', target: '192.168.1.100:3306', result: '成功' },
        { type: '阻止可疑IP', target: '10.0.0.5', result: '成功' },
        { type: '更新防火墙规则', target: '允许内部访问', result: '成功' },
        { type: '修复漏洞', target: 'CVE-2024-1234', result: '成功' },
        { type: '隔离受感染主机', target: '192.168.1.150', result: '成功' }
      ];
      
      const randomAction = defenseActions[Math.floor(Math.random() * defenseActions.length)];
      
      // 添加通知
      addNotification('自动防御动作', `${randomAction.type} - ${randomAction.target}`, 'info');
      
      // 更新已应用动作
      const dfActions = document.getElementById('df-actions');
      if (dfActions) {
        dfActions.innerHTML += `<div class="defense-action">\n` +
          `  <div class="action-type">${randomAction.type}</div>\n` +
          `  <div class="action-target">目标: ${randomAction.target}</div>\n` +
          `  <div class="action-result ${randomAction.result.toLowerCase()}">${randomAction.result}</div>\n` +
          `  <div class="action-time">${new Date().toLocaleString()}</div>\n` +
          `</div>`;
      }
      
      // 更新防御报告
      generateDefenseReport();
    }
  }
  
  // 生成防御报告
  function generateDefenseReport() {
    const dfReport = document.getElementById('df-report');
    if (dfReport) {
      const reportContent = '=== 自动防御报告 ===\n\n' +
        `生成时间: ${new Date().toLocaleString()}\n` +
        `防御状态: ${isDefending ? '运行中' : '已停止'}\n` +
        `无人值守: ${autoMode ? '启用' : '禁用'}\n` +
        `检测周期: ${document.getElementById('df-interval')?.value || '120'}秒\n\n` +
        '=== 防御统计 ===\n' +
        '关闭高危端口: 15次\n' +
        '阻止可疑IP: 23次\n' +
        '更新防火墙规则: 8次\n' +
        '修复漏洞: 12次\n' +
        '隔离受感染主机: 5次\n\n' +
        '=== 防御效果 ===\n' +
        '成功阻止攻击: 98%\n' +
        '误报率: 1.2%\n' +
        '平均响应时间: 2.3秒\n\n' +
        '=== 系统建议 ===\n' +
        '1. 继续保持无人值守模式\n' +
        '2. 定期审查防御规则\n' +
        '3. 更新防御策略以应对新威胁\n' +
        '4. 增加检测周期以提高性能\n' +
        '5. 配置更多防御规则';
      
      dfReport.textContent = reportContent;
    }
  }
  
  // 生成已应用动作
  function generateAppliedActions() {
    const dfActions = document.getElementById('df-actions');
    if (dfActions) {
      const actions = [
        { type: '关闭高危端口', target: '192.168.1.100:22', result: '成功', time: '2024-01-15 10:30:22' },
        { type: '阻止可疑IP', target: '10.0.0.5', result: '成功', time: '2024-01-15 10:35:45' },
        { type: '更新防火墙规则', target: '允许内部访问', result: '成功', time: '2024-01-15 10:40:12' },
        { type: '修复漏洞', target: 'CVE-2024-1234', result: '成功', time: '2024-01-15 10:45:33' },
        { type: '隔离受感染主机', target: '192.168.1.150', result: '成功', time: '2024-01-15 10:50:05' }
      ];
      
      let actionsHTML = '<div class="defense-actions-list">';
      
      actions.forEach(action => {
        actionsHTML += `<div class="defense-action">\n` +
          `  <div class="action-type">${action.type}</div>\n` +
          `  <div class="action-target">目标: ${action.target}</div>\n` +
          `  <div class="action-result ${action.result.toLowerCase()}">${action.result}</div>\n` +
          `  <div class="action-time">${action.time}</div>\n` +
          `</div>`;
      });
      
      actionsHTML += '</div>';
      dfActions.innerHTML = actionsHTML;
    }
  }
  
  // 初始化防御状态
  const dfStatus = document.getElementById('df-status');
  if (dfStatus) {
    dfStatus.textContent = '已停止';
    dfStatus.className = 'status';
  }
}

// 边缘设备管理功能
function setupEdgeDeviceManagement() {
  logger.info('设置边缘设备管理功能');
  
  // 边缘设备状态
  let isMonitoring = false;
  let monitoringInterval = null;
  
  // 刷新设备列表
  const btnEdgeRefresh = document.getElementById('btn-edge-refresh');
  if (btnEdgeRefresh) {
    btnEdgeRefresh.addEventListener('click', () => {
      generateEdgeDeviceList();
      showToast('边缘设备列表已刷新', 'success');
    });
  }
  
  // 打印设备列表
  const btnEdgePrint = document.getElementById('btn-edge-print');
  if (btnEdgePrint) {
    btnEdgePrint.addEventListener('click', () => {
      window.print();
      showToast('边缘设备列表已打印', 'success');
    });
  }
  
  // 生成边缘设备列表
  function generateEdgeDeviceList() {
    const edgeTable = document.getElementById('edge-table');
    if (edgeTable) {
      const devices = [
        { id: 'ED-001', name: '边缘网关-1', ip: '192.168.1.200', status: '在线', type: '网关', lastSeen: '2024-01-15 14:30:22' },
        { id: 'ED-002', name: '摄像头-1', ip: '192.168.1.201', status: '在线', type: '摄像头', lastSeen: '2024-01-15 14:35:45' },
        { id: 'ED-003', name: '传感器-1', ip: '192.168.1.202', status: '离线', type: '传感器', lastSeen: '2024-01-15 10:40:12' },
        { id: 'ED-004', name: '传感器-2', ip: '192.168.1.203', status: '在线', type: '传感器', lastSeen: '2024-01-15 14:45:33' },
        { id: 'ED-005', name: '边缘网关-2', ip: '192.168.1.204', status: '在线', type: '网关', lastSeen: '2024-01-15 14:50:05' },
        { id: 'ED-006', name: '摄像头-2', ip: '192.168.1.205', status: '在线', type: '摄像头', lastSeen: '2024-01-15 14:55:22' },
        { id: 'ED-007', name: '传感器-3', ip: '192.168.1.206', status: '离线', type: '传感器', lastSeen: '2024-01-15 09:30:12' },
        { id: 'ED-008', name: '智能设备-1', ip: '192.168.1.207', status: '在线', type: '智能设备', lastSeen: '2024-01-15 15:00:45' }
      ];
      
      let tableHTML = '<thead>\n' +
        '  <tr>\n' +
        '    <th>设备ID</th>\n' +
        '    <th>设备名称</th>\n' +
        '    <th>IP地址</th>\n' +
        '    <th>设备类型</th>\n' +
        '    <th>状态</th>\n' +
        '    <th>最后在线时间</th>\n' +
        '    <th>操作</th>\n' +
        '  </tr>\n' +
        '</thead>\n' +
        '<tbody>';
      
      devices.forEach(device => {
        tableHTML += '<tr>\n' +
          `  <td>${device.id}</td>\n` +
          `  <td>${device.name}</td>\n` +
          `  <td>${device.ip}</td>\n` +
          `  <td>${device.type}</td>\n` +
          `  <td class="status-${device.status}">${device.status}</td>\n` +
          `  <td>${device.lastSeen}</td>\n` +
          `  <td>\n` +
          `    <button class="btn-small" onclick="app.viewEdgeDevice('${device.id}')">查看</button>\n` +
          `    <button class="btn-small" onclick="app.configureEdgeDevice('${device.id}')">配置</button>\n` +
          `    <button class="btn-small" onclick="app.restartEdgeDevice('${device.id}')">重启</button>\n` +
          `  </td>\n` +
          '</tr>';
      });
      
      tableHTML += '</tbody>';
      edgeTable.innerHTML = tableHTML;
    }
    
    // 更新边缘设备状态
    const edgeStatus = document.getElementById('edge-status');
    if (edgeStatus) {
      const onlineCount = 6; // 模拟在线设备数量
      const totalCount = 8; // 模拟总设备数量
      edgeStatus.innerHTML = `<div class="edge-status">\n` +
        `  <div class="status-item">\n` +
        `    <div class="status-label">在线设备:</div>\n` +
        `    <div class="status-value online">${onlineCount}</div>\n` +
        `  </div>\n` +
        `  <div class="status-item">\n` +
        `    <div class="status-label">离线设备:</div>\n` +
        `    <div class="status-value offline">${totalCount - onlineCount}</div>\n` +
        `  </div>\n` +
        `  <div class="status-item">\n` +
        `    <div class="status-label">总设备数:</div>\n` +
        `    <div class="status-value">${totalCount}</div>\n` +
        `  </div>\n` +
        `</div>`;
    }
  }
  
  // 查看边缘设备详情
  window.app.viewEdgeDevice = (deviceId) => {
    showToast(`查看设备 ${deviceId} 详情`, 'info');
    addNotification('设备操作', `查看设备 ${deviceId} 详情`, 'info');
  };
  
  // 配置边缘设备
  window.app.configureEdgeDevice = (deviceId) => {
    showToast(`配置设备 ${deviceId}`, 'info');
    addNotification('设备操作', `配置设备 ${deviceId}`, 'info');
  };
  
  // 重启边缘设备
  window.app.restartEdgeDevice = (deviceId) => {
    showToast(`重启设备 ${deviceId}`, 'info');
    addNotification('设备操作', `重启设备 ${deviceId}`, 'info');
  };
  
  // 生成边缘设备规则
  function generateEdgeRules() {
    const edgeRules = document.getElementById('edge-rules');
    if (edgeRules) {
      const rules = [
        { id: 'ER-001', name: '访问控制规则-1', device: 'ED-001', status: '启用', action: '允许', priority: '高' },
        { id: 'ER-002', name: '防火墙规则-1', device: 'ED-001', status: '启用', action: '拒绝', priority: '中' },
        { id: 'ER-003', name: '流量限制规则-1', device: 'ED-002', status: '启用', action: '限制', priority: '低' },
        { id: 'ER-004', name: '访问控制规则-2', device: 'ED-003', status: '禁用', action: '允许', priority: '中' }
      ];
      
      let rulesHTML = '<h3>边缘设备规则</h3><div class="edge-rules-list">';
      
      rules.forEach(rule => {
        rulesHTML += `<div class="edge-rule">\n` +
          `  <div class="rule-header">\n` +
          `    <div class="rule-name">${rule.name}</div>\n` +
          `    <div class="rule-status ${rule.status.toLowerCase()}">${rule.status}</div>\n` +
          `  </div>\n` +
          `  <div class="rule-details">\n` +
          `    <div class="rule-item">设备: ${rule.device}</div>\n` +
          `    <div class="rule-item">动作: ${rule.action}</div>\n` +
          `    <div class="rule-item">优先级: ${rule.priority}</div>\n` +
          `  </div>\n` +
          `</div>`;
      });
      
      rulesHTML += '</div>';
      edgeRules.innerHTML = rulesHTML;
    }
  }
  
  // 初始化边缘设备列表和规则
  generateEdgeDeviceList();
  generateEdgeRules();
  
  // 初始化边缘设备状态
  const edgeStatus = document.getElementById('edge-status');
  if (edgeStatus) {
    edgeStatus.innerHTML = `<div class="edge-status">\n` +
      `  <div class="status-item">\n` +
      `    <div class="status-label">在线设备:</div>\n` +
      `    <div class="status-value online">6</div>\n` +
      `  </div>\n` +
      `  <div class="status-item">\n` +
      `    <div class="status-label">离线设备:</div>\n` +
      `    <div class="status-value offline">2</div>\n` +
      `  </div>\n` +
      `  <div class="status-item">\n` +
      `    <div class="status-label">总设备数:</div>\n` +
      `    <div class="status-value">8</div>\n` +
      `  </div>\n` +
      `</div>`;
  }
}

// 配置功能
function setupConfig() {
  logger.info('设置配置功能');
  ensureMigrationCleanup();
  
  // 保存配置
  const btnConfigSave = document.getElementById('btn-save-cfg');
  if (btnConfigSave) {
    btnConfigSave.addEventListener('click', () => {
      saveConfig();
    });
  }
  
  // 打印配置
  const btnConfigPrint = document.getElementById('btn-config-print');
  if (btnConfigPrint) {
    btnConfigPrint.addEventListener('click', () => {
      window.print();
      showToast('配置已打印', 'success');
    });
  }
  
  function applyConfig(config) {
    try {
      window.runtimeConfig = config;
      const opacity = parseFloat(config.opacity || '0.9');
      document.querySelectorAll('.view, .card, .panel').forEach(el => {
        el.style.opacity = opacity;
      });
      if (config.securityModel) {
        window.modelBase = config.securityModel.apiBase || '';
        window.modelName = config.securityModel.model || '';
      }
      const idsStatusEl = document.getElementById('ids-status');
      if (idsStatusEl) {
        idsStatusEl.textContent = (config.ids?.enabled) ? '就绪' : '禁用';
        idsStatusEl.className = (config.ids?.enabled) ? 'status success' : 'status';
      }
      const cfgStatus = document.getElementById('cfg-status');
      if (cfgStatus) {
        cfgStatus.textContent = '配置已应用';
        cfgStatus.style.display = 'block';
        setTimeout(() => { cfgStatus.style.display = 'none'; }, 2500);
      }
      showToast('配置已应用', 'success');
      addNotification('配置已应用', '系统运行参数已更新', 'success');
    } catch (e) {
      logger.error('应用配置失败:', e);
      showToast('应用配置失败', 'error');
      addNotification('配置应用失败', String(e), 'error');
    }
  }

  // 保存配置
  function saveConfig() {
    showLoading();
    
    // 获取配置项
    const config = {
      // 界面配置
      opacity: document.getElementById('cfg-opacity')?.value || '0.9',
      
      // 代理配置
      proxy: {
        enabled: document.getElementById('cfg-proxy-enabled')?.checked || false,
        type: document.getElementById('cfg-proxy-type')?.value || 'http',
        host: document.getElementById('cfg-proxy-host')?.value || '',
        port: document.getElementById('cfg-proxy-port')?.value || '',
        username: document.getElementById('cfg-proxy-username')?.value || '',
        password: document.getElementById('cfg-proxy-password')?.value || ''
      },
      
      // 防火墙配置
      firewall: {
        enabled: document.getElementById('cfg-firewall-enabled')?.checked || false,
        type: document.getElementById('cfg-firewall-type')?.value || 'iptables',
        host: document.getElementById('cfg-firewall-host')?.value || '127.0.0.1',
        port: document.getElementById('cfg-firewall-port')?.value || '443',
        apiKey: document.getElementById('cfg-firewall-api-key')?.value || '',
        autoBlock: document.getElementById('cfg-firewall-auto-block')?.checked || false,
        blockDuration: document.getElementById('cfg-firewall-block-duration')?.value || '60',
        linkIPS: document.getElementById('cfg-firewall-link-ips')?.checked || false,
        linkIDS: document.getElementById('cfg-firewall-link-ids')?.checked || false
      },
      
      // IPS和IDS配置
      ips: {
        enabled: document.getElementById('cfg-ips-enabled')?.checked || false,
        server: document.getElementById('cfg-ips-server')?.value || '',
        port: document.getElementById('cfg-ips-port')?.value || '5555',
        protocol: document.getElementById('cfg-ips-protocol')?.value || 'http',
        apiKey: document.getElementById('cfg-ips-api-key')?.value || ''
      },
      
      ids: {
        enabled: document.getElementById('cfg-ids-enabled')?.checked || false,
        server: document.getElementById('cfg-ids-server')?.value || '',
        port: document.getElementById('cfg-ids-port')?.value || '5556',
        protocol: document.getElementById('cfg-ids-protocol')?.value || 'http',
        apiKey: document.getElementById('cfg-ids-api-key')?.value || ''
      },
      
      // DNS配置
      dns: {
        enabled: document.getElementById('cfg-dns-enabled')?.checked || false,
        primary: document.getElementById('cfg-dns-primary')?.value || '',
        secondary: document.getElementById('cfg-dns-secondary')?.value || '',
        timeout: document.getElementById('cfg-dns-timeout')?.value || '5',
        cacheEnabled: document.getElementById('cfg-dns-cache-enabled')?.checked || true,
        cacheTTL: document.getElementById('cfg-dns-cache-ttl')?.value || '300'
      },
      
      // VPN配置
      vpn: {
        enabled: document.getElementById('cfg-vpn-enabled')?.checked || false,
        type: document.getElementById('cfg-vpn-type')?.value || 'openvpn',
        server: document.getElementById('cfg-vpn-server')?.value || '',
        port: document.getElementById('cfg-vpn-port')?.value || '1194',
        username: document.getElementById('cfg-vpn-username')?.value || '',
        password: document.getElementById('cfg-vpn-password')?.value || '',
        configPath: document.getElementById('cfg-vpn-config-path')?.value || '',
        autoConnect: document.getElementById('cfg-vpn-auto-connect')?.checked || false
      },
      
      // 安全模型配置
      securityModel: {
        apiKey: document.getElementById('cfg-key')?.value || '',
        apiBase: document.getElementById('cfg-base')?.value || '',
        model: document.getElementById('cfg-model')?.value || '',
        concurrency: document.getElementById('cfg-concurrency')?.value || '',
        timeout: document.getElementById('cfg-timeout')?.value || ''
      },
      
      // 管理员配置
      admin: {
        password: document.getElementById('cfg-admin')?.value || ''
      },
      
      // IP黑名单配置
      blacklist: {
        enabled: document.getElementById('cfg-blacklist-enabled')?.checked || true,
        ips: document.getElementById('cfg-blacklist')?.value || ''
      }
    };
    
      // 保存配置到localStorage
    localStorage.setItem('config', JSON.stringify(config));
    saveSecurityModelKey(config.securityModel?.apiKey || '');
    
    // 模拟保存延迟
    setTimeout(() => {
      hideLoading();
      const cfgStatus = document.getElementById('cfg-status');
      if (cfgStatus) {
        cfgStatus.textContent = '配置已保存';
        cfgStatus.style.display = 'block';
        setTimeout(() => { cfgStatus.style.display = 'none'; }, 3000);
      }
      showToast('配置已保存', 'success');
      addNotification('配置已保存', '系统配置已成功保存', 'success');
      applyConfig(config);
      const safeLog = (() => {
        try {
          const copy = JSON.parse(JSON.stringify(config));
          if (copy.securityModel && copy.securityModel.apiKey) copy.securityModel.apiKey = '***';
          return copy;
        } catch { return { ok: true }; }
      })();
      logger.info('配置已保存:', safeLog);
    }, 1000);
  }
  
  // 加载配置
  function loadConfig() {
    const savedConfig = localStorage.getItem('config');
    if (savedConfig) {
      try {
        const config = JSON.parse(savedConfig);
        
        // 设置界面配置
        if (document.getElementById('cfg-opacity')) {
          document.getElementById('cfg-opacity').value = config.opacity || '0.9';
          // 更新透明度显示
          const opacityValue = document.getElementById('opacity-value');
          if (opacityValue) {
            opacityValue.textContent = `${parseFloat(config.opacity || '0.9') * 100}%`;
          }
        }
        
        // 设置代理配置
        if (document.getElementById('cfg-proxy-enabled')) {
          document.getElementById('cfg-proxy-enabled').checked = config.proxy?.enabled || false;
        }
        if (document.getElementById('cfg-proxy-type')) {
          document.getElementById('cfg-proxy-type').value = config.proxy?.type || 'http';
        }
        if (document.getElementById('cfg-proxy-host')) {
          document.getElementById('cfg-proxy-host').value = config.proxy?.host || '';
        }
        if (document.getElementById('cfg-proxy-port')) {
          document.getElementById('cfg-proxy-port').value = config.proxy?.port || '';
        }
        if (document.getElementById('cfg-proxy-username')) {
          document.getElementById('cfg-proxy-username').value = config.proxy?.username || '';
        }
        if (document.getElementById('cfg-proxy-password')) {
          document.getElementById('cfg-proxy-password').value = config.proxy?.password || '';
        }
        
        // 设置防火墙配置
        if (document.getElementById('cfg-firewall-enabled')) {
          document.getElementById('cfg-firewall-enabled').checked = config.firewall?.enabled || false;
        }
        if (document.getElementById('cfg-firewall-type')) {
          document.getElementById('cfg-firewall-type').value = config.firewall?.type || 'iptables';
        }
        if (document.getElementById('cfg-firewall-host')) {
          document.getElementById('cfg-firewall-host').value = config.firewall?.host || '127.0.0.1';
        }
        if (document.getElementById('cfg-firewall-port')) {
          document.getElementById('cfg-firewall-port').value = config.firewall?.port || '443';
        }
        if (document.getElementById('cfg-firewall-api-key')) {
          document.getElementById('cfg-firewall-api-key').value = config.firewall?.apiKey || '';
        }
        if (document.getElementById('cfg-firewall-auto-block')) {
          document.getElementById('cfg-firewall-auto-block').checked = config.firewall?.autoBlock || false;
        }
        if (document.getElementById('cfg-firewall-block-duration')) {
          document.getElementById('cfg-firewall-block-duration').value = config.firewall?.blockDuration || '60';
        }
        if (document.getElementById('cfg-firewall-link-ips')) {
          document.getElementById('cfg-firewall-link-ips').checked = config.firewall?.linkIPS || false;
        }
        if (document.getElementById('cfg-firewall-link-ids')) {
          document.getElementById('cfg-firewall-link-ids').checked = config.firewall?.linkIDS || false;
        }
        
        // 设置IPS和IDS配置
        if (document.getElementById('cfg-ips-enabled')) {
          document.getElementById('cfg-ips-enabled').checked = config.ips?.enabled || false;
        }
        if (document.getElementById('cfg-ips-server')) {
          document.getElementById('cfg-ips-server').value = config.ips?.server || '';
        }
        if (document.getElementById('cfg-ips-port')) {
          document.getElementById('cfg-ips-port').value = config.ips?.port || '5555';
        }
        if (document.getElementById('cfg-ips-protocol')) {
          document.getElementById('cfg-ips-protocol').value = config.ips?.protocol || 'http';
        }
        if (document.getElementById('cfg-ips-api-key')) {
          document.getElementById('cfg-ips-api-key').value = config.ips?.apiKey || '';
        }
        
        if (document.getElementById('cfg-ids-enabled')) {
          document.getElementById('cfg-ids-enabled').checked = config.ids?.enabled || false;
        }
        if (document.getElementById('cfg-ids-server')) {
          document.getElementById('cfg-ids-server').value = config.ids?.server || '';
        }
        if (document.getElementById('cfg-ids-port')) {
          document.getElementById('cfg-ids-port').value = config.ids?.port || '5556';
        }
        if (document.getElementById('cfg-ids-protocol')) {
          document.getElementById('cfg-ids-protocol').value = config.ids?.protocol || 'http';
        }
        if (document.getElementById('cfg-ids-api-key')) {
          document.getElementById('cfg-ids-api-key').value = config.ids?.apiKey || '';
        }
        
        // 设置DNS配置
        if (document.getElementById('cfg-dns-enabled')) {
          document.getElementById('cfg-dns-enabled').checked = config.dns?.enabled || false;
        }
        if (document.getElementById('cfg-dns-primary')) {
          document.getElementById('cfg-dns-primary').value = config.dns?.primary || '';
        }
        if (document.getElementById('cfg-dns-secondary')) {
          document.getElementById('cfg-dns-secondary').value = config.dns?.secondary || '';
        }
        if (document.getElementById('cfg-dns-timeout')) {
          document.getElementById('cfg-dns-timeout').value = config.dns?.timeout || '5';
        }
        if (document.getElementById('cfg-dns-cache-enabled')) {
          document.getElementById('cfg-dns-cache-enabled').checked = config.dns?.cacheEnabled || true;
        }
        if (document.getElementById('cfg-dns-cache-ttl')) {
          document.getElementById('cfg-dns-cache-ttl').value = config.dns?.cacheTTL || '300';
        }
        
        // 设置VPN配置
        if (document.getElementById('cfg-vpn-enabled')) {
          document.getElementById('cfg-vpn-enabled').checked = config.vpn?.enabled || false;
        }
        if (document.getElementById('cfg-vpn-type')) {
          document.getElementById('cfg-vpn-type').value = config.vpn?.type || 'openvpn';
        }
        if (document.getElementById('cfg-vpn-server')) {
          document.getElementById('cfg-vpn-server').value = config.vpn?.server || '';
        }
        if (document.getElementById('cfg-vpn-port')) {
          document.getElementById('cfg-vpn-port').value = config.vpn?.port || '1194';
        }
        if (document.getElementById('cfg-vpn-username')) {
          document.getElementById('cfg-vpn-username').value = config.vpn?.username || '';
        }
        if (document.getElementById('cfg-vpn-password')) {
          document.getElementById('cfg-vpn-password').value = config.vpn?.password || '';
        }
        if (document.getElementById('cfg-vpn-config-path')) {
          document.getElementById('cfg-vpn-config-path').value = config.vpn?.configPath || '';
        }
        if (document.getElementById('cfg-vpn-auto-connect')) {
          document.getElementById('cfg-vpn-auto-connect').checked = config.vpn?.autoConnect || false;
        }
        
        // 设置安全模型配置
        if (document.getElementById('cfg-key')) {
          (async () => {
            const storedKey = await loadSecurityModelKey();
            document.getElementById('cfg-key').value = (config.securityModel?.apiKey && config.securityModel.apiKey.length > 0)
              ? config.securityModel.apiKey
              : storedKey;
          })();
        }
        if (document.getElementById('cfg-base')) {
          document.getElementById('cfg-base').value = config.securityModel?.apiBase || '';
        }
        if (document.getElementById('cfg-model')) {
          document.getElementById('cfg-model').value = config.securityModel?.model || '';
        }
        if (document.getElementById('cfg-concurrency')) {
          document.getElementById('cfg-concurrency').value = config.securityModel?.concurrency || '';
        }
        if (document.getElementById('cfg-timeout')) {
          document.getElementById('cfg-timeout').value = config.securityModel?.timeout || '';
        }
        
        // 设置管理员配置
        if (document.getElementById('cfg-admin')) {
          document.getElementById('cfg-admin').value = config.admin?.password || '';
        }
        
        // 设置IP黑名单配置
        if (document.getElementById('cfg-blacklist-enabled')) {
          document.getElementById('cfg-blacklist-enabled').checked = config.blacklist?.enabled || true;
        }
        if (document.getElementById('cfg-blacklist')) {
          document.getElementById('cfg-blacklist').value = config.blacklist?.ips || '';
        }
        
        logger.info('配置已加载:', config);
        applyConfig(config);
      } catch (e) {
        logger.error('解析配置失败:', e);
        showError('解析配置失败');
      }
    }
  }
  
  // 初始化界面透明度滑块
  const opacitySlider = document.getElementById('cfg-opacity');
  if (opacitySlider) {
    opacitySlider.addEventListener('input', (e) => {
      const opacityValue = document.getElementById('opacity-value');
      if (opacityValue) {
        opacityValue.textContent = `${parseFloat(e.target.value) * 100}%`;
      }
      
      // 应用透明度（这里可以添加实际的透明度应用逻辑）
      logger.info('界面透明度已调整:', e.target.value);
    });
  }
  
  // 初始化配置
  loadConfig();
}

// 入侵检测系统功能
function setupIDS() {
  logger.info('设置入侵检测系统功能');
  
  // IDS状态
  let isDetecting = false;
  let detectionInterval = null;
  
  // 开始检测
  const btnIdsStart = document.getElementById('btn-ids-start');
  if (btnIdsStart) {
    btnIdsStart.addEventListener('click', () => {
      if (isDetecting) {
        showToast('入侵检测已在运行中', 'warning');
        return;
      }
      
      isDetecting = true;
      
      // 更新状态
      const idsStatus = document.getElementById('ids-status');
      if (idsStatus) {
        idsStatus.textContent = '检测中...';
        idsStatus.className = 'status warning';
      }
      
      // 显示监控界面
      const idsMonitor = document.getElementById('ids-monitor');
      if (idsMonitor) {
        idsMonitor.innerHTML = '<div class="ids-monitor">\n' +
          '  <div class="monitor-item">\n' +
          '    <div class="monitor-label">网络流量</div>\n' +
          '    <div class="monitor-value">正在监控...</div>\n' +
          '  </div>\n' +
          '  <div class="monitor-item">\n' +
          '    <div class="monitor-label">系统行为</div>\n' +
          '    <div class="monitor-value">正在监控...</div>\n' +
          '  </div>\n' +
          '  <div class="monitor-item">\n' +
          '    <div class="monitor-label">异常检测</div>\n' +
          '    <div class="monitor-value">正在分析...</div>\n' +
          '  </div>\n' +
          '</div>';
      }
      
      // 生成模拟入侵报告
      generateIDSReport();
      
      // 生成历史警报
      generateIDSAlerts();
      
      // 模拟实时检测
      detectionInterval = setInterval(() => {
        simulateIntrusionDetection();
      }, 5000);
      
      showToast('入侵检测已启动', 'success');
      addNotification('入侵检测启动', '入侵检测系统已成功启动', 'info');
    });
  }
  
  // 停止检测
  const btnIdsStop = document.getElementById('btn-ids-stop');
  if (btnIdsStop) {
    btnIdsStop.addEventListener('click', () => {
      if (!isDetecting) {
        showToast('入侵检测未在运行中', 'warning');
        return;
      }
      
      isDetecting = false;
      clearInterval(detectionInterval);
      
      // 更新状态
      const idsStatus = document.getElementById('ids-status');
      if (idsStatus) {
        idsStatus.textContent = '已停止';
        idsStatus.className = 'status';
      }
      
      showToast('入侵检测已停止', 'success');
      addNotification('入侵检测停止', '入侵检测系统已停止', 'info');
    });
  }
  
  // 打印报告
  const btnIdsPrint = document.getElementById('btn-ids-print');
  if (btnIdsPrint) {
    btnIdsPrint.addEventListener('click', () => {
      window.print();
      showToast('入侵报告已打印', 'success');
    });
  }
  
  // 模拟入侵检测
  function simulateIntrusionDetection() {
    if (!isDetecting) return;
    
    // 随机生成入侵事件
    if (Math.random() > 0.7) {
      const intrusionTypes = ['端口扫描', 'DDoS攻击', 'SQL注入', 'XSS攻击', '暴力破解', '恶意软件'];
      const randomType = intrusionTypes[Math.floor(Math.random() * intrusionTypes.length)];
      const randomIP = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
      
      // 添加通知
      addNotification('入侵检测警报', `检测到${randomType}，来源IP: ${randomIP}`, 'error');
      
      // 更新监控界面
      const idsMonitor = document.getElementById('ids-monitor');
      if (idsMonitor) {
        idsMonitor.innerHTML += `<div class="intrusion-alert">\n` +
          `  <div class="alert-type">${randomType}</div>\n` +
          `  <div class="alert-ip">来源IP: ${randomIP}</div>\n` +
          `  <div class="alert-time">${new Date().toLocaleString()}</div>\n` +
          `</div>`;
      }
      
      // 更新报告
      generateIDSReport();
    }
  }
  
  // 生成IDS报告
  function generateIDSReport() {
    const idsReport = document.getElementById('ids-report');
    if (idsReport) {
      const reportContent = '=== 入侵检测报告 ===\n\n' +
        `生成时间: ${new Date().toLocaleString()}\n` +
        `检测状态: ${isDetecting ? '运行中' : '已停止'}\n\n` +
        '=== 检测统计 ===\n' +
        '端口扫描: 12次\n' +
        'DDoS攻击: 3次\n' +
        'SQL注入: 5次\n' +
        'XSS攻击: 8次\n' +
        '暴力破解: 15次\n' +
        '恶意软件: 2次\n\n' +
        '=== 安全建议 ===\n' +
        '1. 配置防火墙规则，限制不必要的端口访问\n' +
        '2. 启用入侵防御系统(IPS)\n' +
        '3. 定期更新系统和应用程序\n' +
        '4. 实施强密码策略\n' +
        '5. 配置入侵检测系统告警通知';
      
      idsReport.textContent = reportContent;
    }
  }
  
  // 生成IDS历史警报
  function generateIDSAlerts() {
    const idsAlertsTable = document.getElementById('ids-alerts-table');
    if (idsAlertsTable) {
      const alerts = [
        { id: 'ALERT-001', type: '端口扫描', ip: '192.168.1.100', time: '2024-01-15 14:30:22', status: '已处理' },
        { id: 'ALERT-002', type: 'DDoS攻击', ip: '192.168.1.101', time: '2024-01-15 14:35:45', status: '已处理' },
        { id: 'ALERT-003', type: 'SQL注入', ip: '192.168.1.102', time: '2024-01-15 14:40:12', status: '处理中' },
        { id: 'ALERT-004', type: 'XSS攻击', ip: '192.168.1.103', time: '2024-01-15 14:45:33', status: '已处理' },
        { id: 'ALERT-005', type: '暴力破解', ip: '192.168.1.104', time: '2024-01-15 14:50:05', status: '未处理' }
      ];
      
      let tableHTML = '<thead>\n' +
        '  <tr>\n' +
        '    <th>警报ID</th>\n' +
        '    <th>类型</th>\n' +
        '    <th>来源IP</th>\n' +
        '    <th>时间</th>\n' +
        '    <th>状态</th>\n' +
        '    <th>操作</th>\n' +
        '  </tr>\n' +
        '</thead>\n' +
        '<tbody>';
      
      alerts.forEach(alert => {
        tableHTML += '<tr>\n' +
          `  <td>${alert.id}</td>\n` +
          `  <td>${alert.type}</td>\n` +
          `  <td>${alert.ip}</td>\n` +
          `  <td>${alert.time}</td>\n` +
          `  <td class="status-${alert.status}">${alert.status}</td>\n` +
          `  <td><button class="btn-small" onclick="app.handleIntrusionAlert('${alert.id}')">处理</button></td>\n` +
          '</tr>';
      });
      
      tableHTML += '</tbody>';
      idsAlertsTable.innerHTML = tableHTML;
    }
  }
  
  // 处理入侵警报
  window.app.handleIntrusionAlert = (alertId) => {
    showToast(`警报 ${alertId} 已处理`, 'success');
    addNotification('警报处理', `入侵警报 ${alertId} 已处理`, 'info');
  };
  
  // 执行防御建议动作（阻断IP/更新规则/隔离主机）
  window.app.executeDefenseAction = async (action, target) => {
    const dfActions = document.getElementById('df-actions');
    const dfReport = document.getElementById('df-report');
    const now = new Date().toLocaleString();
    let typeLabel = '';
    switch (action) {
      case 'block-ip': typeLabel = '阻断IP'; break;
      case 'update-rule': typeLabel = '更新防火墙规则'; break;
      case 'isolate-host': typeLabel = '隔离主机'; break;
      default: typeLabel = '执行建议';
    }
    const base = (window.modelBase || '').trim() || 'http://127.0.0.1:8001';
    let path = '';
    let body = {};
    if (action === 'block-ip') { path = '/api/defense/block_ip'; body = { ip: target || '' }; }
    else if (action === 'isolate-host') { path = '/api/defense/isolate_host'; body = { host: target || '' }; }
    else if (action === 'update-rule') { path = '/api/defense/update_rule'; body = { rule: target || 'auto' }; }
    else { path = '/api/defense/update_rule'; body = { rule: 'auto' }; }
    let success = false, details = '';
    try {
      const resp = await fetch(`${base.replace(/\/+$/, '')}${path}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      });
      if (resp.ok) {
        const data = await resp.json();
        success = !!data.success;
        details = data.details || '';
      } else {
        details = `HTTP ${resp.status}`;
      }
    } catch (e) {
      details = String(e);
    }
    if (dfActions) {
      dfActions.innerHTML += `\n<div class="defense-action">\n  <div class="action-type">${typeLabel}</div>\n  <div class="action-target">目标: ${target || '未指定'}</div>\n  <div class="action-result ${success ? 'success' : 'error'}">${success ? '成功' : '失败'}</div>\n  <div class="action-time">${now}</div>\n  <div class="action-detail" style="margin-top:6px;">${details || ''}</div>\n</div>`;
    }
    if (dfReport) {
      dfReport.textContent += `\n[执行记录] ${now} ${typeLabel} -> ${target || '未指定'} (${success ? '成功' : '失败'}) ${details ? '\n'+details : ''}`;
    }
    try { window.dispatchEvent(new CustomEvent('app:defense-action', { detail: { action, target, success, details, time: now } })); } catch {}
    addNotification('执行防御建议', `${typeLabel} - ${target || '未指定'}`, success ? 'success' : 'error');
  };
  
  // 初始化IDS状态
  const idsStatus = document.getElementById('ids-status');
  if (idsStatus) {
    idsStatus.textContent = '已停止';
    idsStatus.className = 'status';
  }
};

// 页面加载完成后初始化
window.addEventListener('DOMContentLoaded', () => {
  try {
    init();
  } catch (e) {
    console.error('初始化失败:', e);
  }
});

console.log('完整功能版app.js加载完成');
