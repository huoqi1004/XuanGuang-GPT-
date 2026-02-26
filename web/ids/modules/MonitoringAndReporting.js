/**
 * 入侵检测系统 - 监控和报告模块
 * 负责系统活动日志记录、入侵事件跟踪、性能监控和报告生成
 */

class MonitoringAndReporting {
  constructor(config = {}) {
    this.config = {
      logLevel: 'info', // debug, info, warn, error, critical
      logRotation: {
        maxSize: 50 * 1024 * 1024, // 50MB
        maxFiles: 10
      },
      reportInterval: 24 * 60 * 60 * 1000, // 24小时
      alertThreshold: 5, // 5分钟内超过此阈值触发警报
      alertChannels: ['console', 'file'], // 告警渠道
      ...config
    };
    
    // 系统状态数据
    this.systemStatus = {
      uptime: Date.now(),
      modules: {},
      resourceUsage: {
        cpu: 0,
        memory: 0,
        disk: 0
      },
      lastScanTime: null,
      detectionStats: {
        totalScans: 0,
        threatsDetected: 0,
        falsePositives: 0,
        falseNegatives: 0
      }
    };
    
    // 事件日志存储
    this.eventLog = [];
    this.maxLogEntries = 10000;
    
    // 告警队列
    this.alertQueue = [];
    
    // 性能指标
    this.performanceMetrics = {
      scanTimes: [],
      detectionLatencies: [],
      modelResponseTimes: []
    };
    
    // 初始化报告生成器
    this.reportGenerator = new ReportGenerator(this.config.reportInterval);
    
    // 初始化告警管理器
    this.alertManager = new AlertManager(this.config.alertChannels, this.config.alertThreshold);
    
    console.log('监控与报告模块已初始化');
  }

  /**
   * 初始化模块
   */
  initialize() {
    this.startResourceMonitoring();
    this.scheduleRegularReports();
    this.log('info', '监控与报告模块已启动');
    return this;
  }

  /**
   * 记录日志
   */
  log(level, message, metadata = {}) {
    // 检查日志级别是否应该被记录
    const levels = ['debug', 'info', 'warn', 'error', 'critical'];
    if (levels.indexOf(level) < levels.indexOf(this.config.logLevel)) {
      return;
    }
    
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      message,
      metadata
    };
    
    // 添加到内存日志
    this.eventLog.push(logEntry);
    
    // 限制日志大小
    if (this.eventLog.length > this.maxLogEntries) {
      this.eventLog.shift();
    }
    
    // 在控制台输出
    if (level === 'error' || level === 'critical') {
      console.error(`[${timestamp}] [${level.toUpperCase()}] ${message}`, metadata);
    } else if (level === 'warn') {
      console.warn(`[${timestamp}] [${level.toUpperCase()}] ${message}`, metadata);
    } else if (this.config.logLevel === 'debug') {
      console.log(`[${timestamp}] [${level.toUpperCase()}] ${message}`, metadata);
    }
    
    // 如果是严重级别，触发告警
    if (level === 'error' || level === 'critical') {
      this.alertManager.triggerAlert(level, message, metadata);
    }
    
    return logEntry;
  }

  /**
   * 记录入侵检测事件
   */
  logDetectionEvent(event) {
    const detectionEvent = {
      timestamp: new Date().toISOString(),
      type: event.type || 'unknown',
      severity: event.severity || 'medium',
      source: event.source || 'unknown',
      target: event.target || 'unknown',
      description: event.description || 'No description provided',
      confidence: event.confidence || 0.7,
      actionTaken: event.actionTaken || 'none',
      rawData: event.rawData || {}
    };
    
    // 记录事件
    this.log('warn', `检测到潜在入侵: ${detectionEvent.description}`, detectionEvent);
    
    // 更新统计信息
    this.systemStatus.detectionStats.threatsDetected++;
    
    // 触发告警
    this.alertManager.triggerAlert(
      'warning',
      `检测到${detectionEvent.severity}级别威胁: ${detectionEvent.description}`,
      detectionEvent
    );
    
    // 通知报告生成器
    this.reportGenerator.addDetectionEvent(detectionEvent);
    
    return detectionEvent;
  }

  /**
   * 记录误报
   */
  logFalsePositive(event) {
    this.systemStatus.detectionStats.falsePositives++;
    this.log('info', '记录误报', event);
  }

  /**
   * 记录漏报
   */
  logFalseNegative(event) {
    this.systemStatus.detectionStats.falseNegatives++;
    this.log('error', '记录漏报', event);
  }

  /**
   * 记录模块状态
   */
  updateModuleStatus(moduleName, status) {
    this.systemStatus.modules[moduleName] = {
      status,
      lastUpdate: new Date().toISOString()
    };
    
    if (status === 'error' || status === 'stopped') {
      this.log('error', `${moduleName} 模块状态变为: ${status}`);
    }
  }

  /**
   * 更新资源使用情况
   */
  updateResourceUsage(usage) {
    this.systemStatus.resourceUsage = {
      ...this.systemStatus.resourceUsage,
      ...usage,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * 开始资源监控
   */
  startResourceMonitoring() {
    if (typeof window !== 'undefined') {
      // 浏览器环境下的模拟监控
      setInterval(() => {
        this.updateResourceUsage({
          cpu: Math.random() * 20 + 5, // 5-25% CPU使用率
          memory: Math.random() * 30 + 10, // 10-40% 内存使用率
          disk: Math.random() * 10 + 5 // 5-15% 磁盘使用增长率
        });
      }, 5000);
    } else {
      // Node.js环境下的实际监控
      try {
        const os = require('os');
        setInterval(() => {
          const cpus = os.cpus();
          const totalMemory = os.totalmem();
          const freeMemory = os.freemem();
          
          this.updateResourceUsage({
            cpu: Math.random() * 20 + 5, // 模拟CPU使用率
            memory: ((totalMemory - freeMemory) / totalMemory) * 100,
            disk: Math.random() * 10 + 5 // 模拟磁盘使用增长率
          });
        }, 5000);
      } catch (error) {
        this.log('error', '资源监控初始化失败', { error: error.message });
      }
    }
  }

  /**
   * 记录性能指标
   */
  recordPerformanceMetric(metricType, value) {
    if (this.performanceMetrics[metricType]) {
      this.performanceMetrics[metricType].push({
        timestamp: new Date().toISOString(),
        value
      });
      
      // 限制指标数组大小
      if (this.performanceMetrics[metricType].length > 1000) {
        this.performanceMetrics[metricType].shift();
      }
    }
  }

  /**
   * 安排定期报告生成
   */
  scheduleRegularReports() {
    setInterval(() => {
      this.generateReport('daily');
    }, this.config.reportInterval);
  }

  /**
   * 生成报告
   */
  generateReport(type = 'summary') {
    const report = this.reportGenerator.generateReport(type);
    this.log('info', `生成${type}报告`);
    
    // 保存报告
    this.saveReport(report);
    
    return report;
  }

  /**
   * 保存报告
   */
  saveReport(report) {
    try {
      // 在实际环境中，这里会将报告保存到文件系统或数据库
      // 目前只是在内存中保存最近的报告
      this.lastReport = report;
      
      // 如果是严重报告，发送告警
      if (report.threatSummary && report.threatSummary.highSeverity > 0) {
        this.alertManager.triggerAlert(
          'critical',
          `报告显示存在${report.threatSummary.highSeverity}个高危威胁`,
          report
        );
      }
    } catch (error) {
      this.log('error', '保存报告失败', { error: error.message });
    }
  }

  /**
   * 获取系统状态
   */
  getSystemStatus() {
    return {
      ...this.systemStatus,
      uptime: Math.floor((Date.now() - this.systemStatus.uptime) / 1000) // 转换为秒
    };
  }

  /**
   * 获取事件日志
   */
  getEventLog(options = {}) {
    const { limit = 100, level, startDate, endDate } = options;
    let filteredLog = [...this.eventLog];
    
    // 按级别过滤
    if (level) {
      filteredLog = filteredLog.filter(entry => entry.level === level);
    }
    
    // 按日期范围过滤
    if (startDate) {
      filteredLog = filteredLog.filter(entry => new Date(entry.timestamp) >= new Date(startDate));
    }
    
    if (endDate) {
      filteredLog = filteredLog.filter(entry => new Date(entry.timestamp) <= new Date(endDate));
    }
    
    // 限制返回数量
    return filteredLog.slice(-limit);
  }

  /**
   * 导出日志
   */
  exportLog(format = 'json') {
    if (format === 'json') {
      return JSON.stringify(this.eventLog, null, 2);
    } else if (format === 'csv') {
      // 生成CSV格式日志
      const headers = ['timestamp', 'level', 'message'];
      const rows = this.eventLog.map(entry => [
        entry.timestamp,
        entry.level,
        `"${entry.message}"`
      ]);
      
      return [headers, ...rows].map(row => row.join(',')).join('\n');
    }
    
    return '';
  }

  /**
   * 清除日志
   */
  clearLog() {
    this.eventLog = [];
    this.log('info', '日志已清除');
  }

  /**
   * 停止监控
   */
  stop() {
    // 清除定时器和资源
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }
    
    if (this.reportIntervalId) {
      clearInterval(this.reportIntervalId);
    }
    
    this.log('info', '监控与报告模块已停止');
  }
}

/**
 * 报告生成器类
 */
class ReportGenerator {
  constructor(reportInterval) {
    this.reportInterval = reportInterval;
    this.detectionEvents = [];
    this.performanceData = [];
    this.lastReportTime = Date.now();
  }

  /**
   * 添加检测事件
   */
  addDetectionEvent(event) {
    this.detectionEvents.push(event);
  }

  /**
   * 添加性能数据
   */
  addPerformanceData(data) {
    this.performanceData.push(data);
  }

  /**
   * 生成报告
   */
  generateReport(type) {
    const now = new Date();
    const report = {
      reportId: `report-${now.getTime()}`,
      timestamp: now.toISOString(),
      type,
      generatedBy: '入侵检测系统',
      period: this.calculateReportPeriod(type),
      systemInfo: this.getSystemInfo(),
      threatSummary: this.summarizeThreats(),
      performanceSummary: this.summarizePerformance(),
      recommendations: this.generateRecommendations()
    };
    
    // 更新最后报告时间
    this.lastReportTime = Date.now();
    
    return report;
  }

  /**
   * 计算报告周期
   */
  calculateReportPeriod(type) {
    const now = new Date();
    let startDate;
    
    if (type === 'daily') {
      startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    } else if (type === 'weekly') {
      startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    } else if (type === 'monthly') {
      startDate = new Date(now.getFullYear(), now.getMonth() - 1, now.getDate());
    } else {
      startDate = new Date(now.getTime() - 1 * 60 * 60 * 1000); // 默认小时报告
    }
    
    return {
      start: startDate.toISOString(),
      end: now.toISOString()
    };
  }

  /**
   * 获取系统信息
   */
  getSystemInfo() {
    if (typeof window !== 'undefined') {
      // 浏览器环境
      return {
        platform: navigator.platform,
        userAgent: navigator.userAgent,
        language: navigator.language,
        screenResolution: `${window.screen.width}x${window.screen.height}`
      };
    } else {
      // Node.js环境
      try {
        const os = require('os');
        return {
          platform: os.platform(),
          arch: os.arch(),
          release: os.release(),
          hostname: os.hostname(),
          cpus: os.cpus().length
        };
      } catch (error) {
        return { platform: 'unknown' };
      }
    }
  }

  /**
   * 总结威胁情况
   */
  summarizeThreats() {
    const periodStart = new Date(this.period.start);
    const periodEvents = this.detectionEvents.filter(event => 
      new Date(event.timestamp) >= periodStart
    );
    
    const severityCounts = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0
    };
    
    const typeCounts = {};
    
    periodEvents.forEach(event => {
      // 计算严重级别
      if (severityCounts[event.severity]) {
        severityCounts[event.severity]++;
      } else {
        severityCounts.medium++; // 默认中等
      }
      
      // 计算类型
      if (typeCounts[event.type]) {
        typeCounts[event.type]++;
      } else {
        typeCounts[event.type] = 1;
      }
    });
    
    // 找出最常见的威胁类型
    let mostCommonType = 'unknown';
    let maxCount = 0;
    for (const [type, count] of Object.entries(typeCounts)) {
      if (count > maxCount) {
        maxCount = count;
        mostCommonType = type;
      }
    }
    
    return {
      total: periodEvents.length,
      ...severityCounts,
      mostCommonType,
      typeBreakdown: typeCounts,
      topSources: this.findTopSources(periodEvents)
    };
  }

  /**
   * 找出最常见的攻击源
   */
  findTopSources(events, limit = 5) {
    const sourceCounts = {};
    
    events.forEach(event => {
      if (event.source) {
        sourceCounts[event.source] = (sourceCounts[event.source] || 0) + 1;
      }
    });
    
    // 排序并返回前N个
    return Object.entries(sourceCounts)
      .sort(([,a], [,b]) => b - a)
      .slice(0, limit)
      .map(([source, count]) => ({ source, count }));
  }

  /**
   * 总结性能情况
   */
  summarizePerformance() {
    // 生成模拟性能数据
    return {
      averageScanTime: Math.random() * 10 + 5, // 5-15秒
      detectionLatency: Math.random() * 2 + 0.5, // 0.5-2.5秒
      systemResourceUsage: {
        cpu: Math.random() * 15 + 5, // 5-20%
        memory: Math.random() * 20 + 10, // 10-30%
        disk: Math.random() * 5 + 2 // 2-7%
      },
      falsePositiveRate: Math.random() * 3, // 0-3%
      detectionRate: 95 + Math.random() * 4 // 95-99%
    };
  }

  /**
   * 生成建议
   */
  generateRecommendations() {
    const recommendations = [];
    
    // 根据检测到的威胁生成建议
    const threatSummary = this.summarizeThreats();
    
    if (threatSummary.high > 5) {
      recommendations.push('检测到大量高危威胁，建议立即审查系统安全配置');
    }
    
    if (threatSummary.mostCommonType === 'brute_force') {
      recommendations.push('发现多次暴力破解尝试，建议加强密码策略和启用账户锁定机制');
    }
    
    if (threatSummary.total > 50) {
      recommendations.push('单位时间内检测到大量威胁，可能存在针对性攻击');
    }
    
    // 根据性能生成建议
    const performance = this.summarizePerformance();
    
    if (performance.systemResourceUsage.cpu > 15) {
      recommendations.push('CPU使用率较高，建议优化系统配置或增加硬件资源');
    }
    
    if (performance.falsePositiveRate > 2) {
      recommendations.push('误报率较高，建议调整检测规则阈值');
    }
    
    // 默认建议
    if (recommendations.length === 0) {
      recommendations.push('系统运行正常，建议定期检查更新');
      recommendations.push('保持定期安全审计和渗透测试');
    }
    
    return recommendations;
  }
}

/**
 * 告警管理器类
 */
class AlertManager {
  constructor(alertChannels, threshold) {
    this.alertChannels = alertChannels;
    this.threshold = threshold;
    this.alertCount = 0;
    this.alertWindowStart = Date.now();
    this.alertQueue = [];
    this.sentAlerts = new Set();
  }

  /**
   * 触发告警
   */
  triggerAlert(level, message, metadata) {
    // 检查告警窗口
    const now = Date.now();
    if (now - this.alertWindowStart > 5 * 60 * 1000) { // 5分钟窗口
      this.alertCount = 0;
      this.alertWindowStart = now;
    }
    
    this.alertCount++;
    
    // 生成唯一告警ID
    const alertId = `${level}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const alert = {
      id: alertId,
      timestamp: new Date().toISOString(),
      level,
      message,
      metadata,
      repeatCount: 1
    };
    
    // 检查是否超过阈值
    if (this.alertCount > this.threshold) {
      alert.thresholdExceeded = true;
    }
    
    // 发送告警到各个渠道
    this.sendAlert(alert);
    
    return alert;
  }

  /**
   * 发送告警
   */
  sendAlert(alert) {
    // 检查是否已经发送过相同的告警（防止告警风暴）
    const alertKey = `${alert.level}-${alert.message.substring(0, 100)}`;
    if (this.sentAlerts.has(alertKey)) {
      return;
    }
    
    this.sentAlerts.add(alertKey);
    
    // 30秒后允许相同告警再次发送
    setTimeout(() => {
      this.sentAlerts.delete(alertKey);
    }, 30000);
    
    // 发送到各个配置的渠道
    this.alertChannels.forEach(channel => {
      switch (channel) {
        case 'console':
          this.sendToConsole(alert);
          break;
        case 'file':
          this.sendToFile(alert);
          break;
        case 'email':
          this.sendToEmail(alert);
          break;
        case 'webhook':
          this.sendToWebhook(alert);
          break;
      }
    });
    
    // 添加到队列
    this.alertQueue.push(alert);
    
    // 限制队列大小
    if (this.alertQueue.length > 1000) {
      this.alertQueue.shift();
    }
  }

  /**
   * 发送到控制台
   */
  sendToConsole(alert) {
    const prefix = `[告警 - ${alert.level.toUpperCase()}]`;
    console.log(`${prefix} ${alert.message}`);
    if (alert.metadata) {
      console.log(JSON.stringify(alert.metadata, null, 2));
    }
  }

  /**
   * 发送到文件
   */
  sendToFile(alert) {
    try {
      if (typeof window === 'undefined') {
        const fs = require('fs');
        const path = require('path');
        const logDir = path.join(process.cwd(), 'logs');
        
        if (!fs.existsSync(logDir)) {
          fs.mkdirSync(logDir, { recursive: true });
        }
        
        const logFile = path.join(logDir, 'alerts.log');
        const logEntry = JSON.stringify(alert) + '\n';
        
        fs.appendFileSync(logFile, logEntry);
      }
    } catch (error) {
      console.error('保存告警到文件失败:', error.message);
    }
  }

  /**
   * 发送到邮件
   */
  sendToEmail(alert) {
    // 模拟邮件发送
    console.log(`[邮件告警] 发送告警邮件: ${alert.message}`);
    // 实际环境中会调用邮件发送API
  }

  /**
   * 发送到Webhook
   */
  sendToWebhook(alert) {
    // 模拟Webhook发送
    console.log(`[Webhook告警] 发送到告警系统: ${alert.message}`);
    // 实际环境中会发送HTTP请求到配置的webhook URL
  }

  /**
   * 获取告警历史
   */
  getAlertHistory(options = {}) {
    const { limit = 100, level } = options;
    let alerts = [...this.alertQueue];
    
    // 按级别过滤
    if (level) {
      alerts = alerts.filter(alert => alert.level === level);
    }
    
    // 限制返回数量
    return alerts.slice(-limit).reverse(); // 最新的在前
  }

  /**
   * 清除告警历史
   */
  clearAlertHistory() {
    this.alertQueue = [];
  }
}

// 导出MonitoringAndReporting类
if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
  module.exports = MonitoringAndReporting;
} else if (typeof window !== 'undefined') {
  window.MonitoringAndReporting = MonitoringAndReporting;
}

// 如果是直接在浏览器中加载，创建一个全局实例
if (typeof window !== 'undefined' && !window.monitoringAndReporting) {
  window.monitoringAndReporting = new MonitoringAndReporting();
}
