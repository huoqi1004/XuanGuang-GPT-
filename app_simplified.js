// 简化版app.js - 只包含DOM定义和基本功能
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
const aiInput = document.getElementById("ai-input");
const btnAiSend = document.getElementById("btn-ai-send");
const aiOutput = document.getElementById("ai-output");
const aiStatus = document.getElementById("ai-status");
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
const menuDashboard = document.getElementById("menu-dashboard");
const menuBaseline = document.getElementById("menu-baseline");
const menuSituation = document.getElementById("menu-situation");
const menuDefense = document.getElementById("menu-defense");
const menuAv = document.getElementById("menu-av");
const menuEdge = document.getElementById("menu-edge");
const menuAiChat = document.getElementById("menu-ai-chat");
const menuIds = document.getElementById("menu-ids");
const menuLogging = document.getElementById("menu-logging");
const menuIncidentResponse = document.getElementById("menu-incident-response");
const menuConfig = document.getElementById("menu-config");
const menuLogin = document.getElementById("menu-login");
const menuRegister = document.getElementById("menu-register");
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

// 基本功能 - 简化版
const state = {
  user: null,
  isLoading: false,
  notifications: []
};

// 简化的显示视图函数
function showView(viewName) {
  // 隐藏所有视图
  Object.values(views).forEach(view => {
    if (view) view.style.display = 'none';
  });
  
  // 显示指定视图
  if (views[viewName]) {
    views[viewName].style.display = 'block';
  }
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
  console.error(message);
  // 可以在这里添加toast通知逻辑
}

// 初始化
function init() {
  console.log('应用初始化');
  // 检查登录状态（简化版）
  const savedUser = localStorage.getItem('user');
  if (savedUser) {
    try {
      state.user = JSON.parse(savedUser);
      showView('dashboard');
    } catch (e) {
      showError('解析用户数据失败');
      showView('login');
    }
  } else {
    showView('login');
  }
}

// 导出必要的函数和状态
window.app = {
  state,
  showView,
  showLoading,
  hideLoading,
  showError,
  init
};

// 页面加载完成后初始化
window.addEventListener('DOMContentLoaded', () => {
  try {
    init();
  } catch (e) {
    console.error('初始化失败:', e);
  }
});

console.log('简化版app.js加载完成');