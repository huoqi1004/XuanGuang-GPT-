// 性能监控模块 - 简化版本
function PerformanceMonitor() {
  this.memoryMonitoringInterval = null;
}

PerformanceMonitor.prototype.startMonitoring = function() {
  console.log('性能监控已启动');
};

PerformanceMonitor.prototype.stopMonitoring = function() {
  if (this.memoryMonitoringInterval) {
    clearInterval(this.memoryMonitoringInterval);
    this.memoryMonitoringInterval = null;
  }
  console.log('性能监控已停止');
};

// 创建全局实例
const performanceMonitor = new PerformanceMonitor();