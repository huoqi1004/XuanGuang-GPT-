// 测试版本
console.log('测试版本启动');
const state = {
  token: localStorage.getItem("token") || "",
  lastScanId: "",
  lastResult: null,
  isLoading: false,
  // 会话管理相关属性
  user: JSON.parse(localStorage.getItem('userInfo')) || null,
  tokenExpireAt: localStorage.getItem('tokenExpireAt') ? parseInt(localStorage.getItem('tokenExpireAt')) : null,
  isLoggedIn: false,
  isCheckingExpiry: false,
  // 性能优化相关属性
  viewTransitionInProgress: false,
  cachedViews: {},
  performanceMode: localStorage.getItem('app_performance_mode') || 'auto'
};

function init() {
  console.log('初始化完成');
}

// 页面加载完成后初始化
window.addEventListener('load', init);