/**
 * 入侵检测系统 - 测试套件
 * 包含功能测试、性能测试和集成测试
 */

class IDS_TestSuite {
  constructor(config = {}) {
    this.config = {
      testMode: 'full', // full, unit, integration, performance
      timeout: 30000, // 测试超时时间（毫秒）
      verbose: true, // 是否显示详细日志
      mockData: true, // 是否使用模拟数据
      ...config
    };
    
    // 测试结果
    this.results = {
      total: 0,
      passed: 0,
      failed: 0,
      skipped: 0,
      startTime: null,
      endTime: null,
      duration: 0,
      testCases: []
    };
    
    // 性能指标
    this.performanceMetrics = {
      moduleLoadTime: {},
      functionExecutionTime: {},
      memoryUsage: [],
      detectionAccuracy: {
        truePositives: 0,
        falsePositives: 0,
        trueNegatives: 0,
        falseNegatives: 0
      }
    };
    
    // 测试日志
    this.testLogs = [];
    
    // 导入模块（尝试动态导入）
    this.modules = {};
    
    console.log('入侵检测系统测试套件已初始化');
  }

  /**
   * 初始化测试环境
   */
  async initialize() {
    this.log('info', '开始初始化测试环境');
    
    try {
      // 尝试导入各个模块
      await this.loadModules();
      
      // 初始化模拟数据生成器
      this.mockDataGenerator = new MockDataGenerator();
      
      this.log('info', '测试环境初始化完成');
      return true;
    } catch (error) {
      this.log('error', '测试环境初始化失败', { error: error.message });
      return false;
    }
  }

  /**
   * 加载测试所需的模块
   */
  async loadModules() {
    // 在Node.js环境下使用require
    if (typeof require !== 'undefined') {
      try {
        // 记录加载时间
        const startTime = Date.now();
        
        this.modules = {
          InvasionDetector: require('../InvasionDetector.js'),
          DataCollector: require('../modules/DataCollector.js'),
          InvasionAnalyzer: require('../modules/InvasionAnalyzer.js'),
          InvasionResponder: require('../modules/InvasionResponder.js'),
          InvasionInterceptionManager: require('../modules/InvasionInterceptionManager.js'),
          NetworkTrafficMonitor: require('../modules/NetworkTrafficMonitor.js'),
          SystemBehaviorMonitor: require('../modules/SystemBehaviorMonitor.js'),
          MonitoringAndReporting: require('../modules/MonitoringAndReporting.js'),
          Logger: require('../modules/Logger.js').default
        };
        
        this.performanceMetrics.moduleLoadTime.total = Date.now() - startTime;
        this.log('info', '成功加载所有模块');
      } catch (error) {
        this.log('warn', '部分模块加载失败，将使用模拟对象', { error: error.message });
        // 创建模拟对象
        this.createMockModules();
      }
    } else {
      // 浏览器环境下使用全局对象
      this.modules = {
        InvasionDetector: window.InvasionDetector,
        DataCollector: window.DataCollector,
        InvasionAnalyzer: window.InvasionAnalyzer,
        InvasionResponder: window.InvasionResponder,
        InvasionInterceptionManager: window.InvasionInterceptionManager,
        NetworkTrafficMonitor: window.NetworkTrafficMonitor,
        SystemBehaviorMonitor: window.SystemBehaviorMonitor,
        MonitoringAndReporting: window.MonitoringAndReporting,
        Logger: window.logger
      };
      
      this.log('info', '使用全局模块');
    }
  }

  /**
   * 创建模拟模块对象
   */
  createMockModules() {
    // 创建简化的模拟对象，用于测试
    this.modules = {
      InvasionDetector: class MockInvasionDetector {
        constructor() { this.initialized = false; }
        initialize() { this.initialized = true; return true; }
        startDetection() { return true; }
        stopDetection() { return true; }
      },
      DataCollector: class MockDataCollector {
        collect() { return { data: 'mock data' }; }
        startMonitoring() { return true; }
        stopMonitoring() { return true; }
      },
      // 其他模块的模拟实现...
    };
  }

  /**
   * 运行测试套件
   */
  async runTests() {
    this.results.startTime = new Date();
    this.log('info', '开始运行测试套件');
    
    try {
      // 根据测试模式运行不同的测试
      if (this.config.testMode === 'full' || this.config.testMode === 'unit') {
        await this.runUnitTests();
      }
      
      if (this.config.testMode === 'full' || this.config.testMode === 'integration') {
        await this.runIntegrationTests();
      }
      
      if (this.config.testMode === 'full' || this.config.testMode === 'performance') {
        await this.runPerformanceTests();
      }
      
      this.results.endTime = new Date();
      this.results.duration = this.results.endTime - this.results.startTime;
      
      this.generateTestReport();
      return this.results;
    } catch (error) {
      this.log('error', '测试套件运行失败', { error: error.message });
      return this.results;
    }
  }

  /**
   * 运行单元测试
   */
  async runUnitTests() {
    this.log('info', '开始运行单元测试');
    
    const unitTests = [
      { name: '测试InvasionDetector初始化', testFn: this.testInvasionDetectorInit },
      { name: '测试DataCollector数据收集', testFn: this.testDataCollector },
      { name: '测试InvasionAnalyzer分析', testFn: this.testInvasionAnalyzer },
      { name: '测试InvasionResponder响应', testFn: this.testInvasionResponder },
      { name: '测试NetworkTrafficMonitor', testFn: this.testNetworkTrafficMonitor },
      { name: '测试SystemBehaviorMonitor', testFn: this.testSystemBehaviorMonitor },
      { name: '测试MonitoringAndReporting', testFn: this.testMonitoringAndReporting },
      { name: '测试Logger功能', testFn: this.testLogger }
    ];
    
    for (const test of unitTests) {
      await this.runTestCase(test.name, test.testFn.bind(this));
    }
  }

  /**
   * 运行集成测试
   */
  async runIntegrationTests() {
    this.log('info', '开始运行集成测试');
    
    const integrationTests = [
      { name: '测试完整检测流程', testFn: this.testFullDetectionFlow },
      { name: '测试无人值守模式集成', testFn: this.testUnattendedMode },
      { name: '测试告警和报告生成', testFn: this.testAlertAndReporting }
    ];
    
    for (const test of integrationTests) {
      await this.runTestCase(test.name, testFn.bind(this));
    }
  }

  /**
   * 运行性能测试
   */
  async runPerformanceTests() {
    this.log('info', '开始运行性能测试');
    
    const performanceTests = [
      { name: '测试数据收集性能', testFn: this.testDataCollectionPerformance },
      { name: '测试分析引擎性能', testFn: this.testAnalysisEnginePerformance },
      { name: '测试内存使用情况', testFn: this.testMemoryUsage },
      { name: '测试并发检测能力', testFn: this.testConcurrentDetection }
    ];
    
    for (const test of performanceTests) {
      await this.runTestCase(test.name, testFn.bind(this));
    }
  }

  /**
   * 运行单个测试用例
   */
  async runTestCase(name, testFn) {
    this.results.total++;
    const startTime = Date.now();
    
    try {
      this.log('info', `开始测试: ${name}`);
      
      // 设置超时
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('测试超时')), this.config.timeout);
      });
      
      await Promise.race([testFn(), timeoutPromise]);
      
      const duration = Date.now() - startTime;
      this.results.passed++;
      
      const testResult = {
        name,
        status: 'passed',
        duration,
        timestamp: new Date().toISOString()
      };
      
      this.results.testCases.push(testResult);
      this.log('info', `测试通过: ${name} (${duration}ms)`);
      
      return testResult;
    } catch (error) {
      const duration = Date.now() - startTime;
      this.results.failed++;
      
      const testResult = {
        name,
        status: 'failed',
        duration,
        error: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString()
      };
      
      this.results.testCases.push(testResult);
      this.log('error', `测试失败: ${name} - ${error.message}`);
      
      return testResult;
    }
  }

  /**
   * 单元测试：测试InvasionDetector初始化
   */
  async testInvasionDetectorInit() {
    if (!this.modules.InvasionDetector) {
      throw new Error('InvasionDetector模块不可用');
    }
    
    const detector = new this.modules.InvasionDetector({
      testMode: true
    });
    
    if (!detector || typeof detector.initialize !== 'function') {
      throw new Error('InvasionDetector实例创建失败');
    }
    
    const result = detector.initialize();
    if (!result) {
      throw new Error('InvasionDetector初始化失败');
    }
  }

  /**
   * 单元测试：测试DataCollector数据收集
   */
  async testDataCollector() {
    if (!this.modules.DataCollector) {
      throw new Error('DataCollector模块不可用');
    }
    
    const collector = new this.modules.DataCollector({
      mockMode: true
    });
    
    if (!collector || typeof collector.collect !== 'function') {
      throw new Error('DataCollector实例创建失败');
    }
    
    const data = collector.collect();
    if (!data) {
      throw new Error('数据收集失败');
    }
  }

  /**
   * 单元测试：测试InvasionAnalyzer分析
   */
  async testInvasionAnalyzer() {
    if (!this.modules.InvasionAnalyzer) {
      throw new Error('InvasionAnalyzer模块不可用');
    }
    
    const analyzer = new this.modules.InvasionAnalyzer({
      mockModel: true
    });
    
    const mockData = this.mockDataGenerator.generateInvasionData('port_scan');
    const result = analyzer.analyze(mockData);
    
    if (!result || !result.detection) {
      throw new Error('分析结果无效');
    }
  }

  /**
   * 单元测试：测试InvasionResponder响应
   */
  async testInvasionResponder() {
    if (!this.modules.InvasionResponder) {
      throw new Error('InvasionResponder模块不可用');
    }
    
    const responder = new this.modules.InvasionResponder({
      testMode: true
    });
    
    const mockAlert = this.mockDataGenerator.generateAlert('port_scan', 'high');
    const result = responder.respond(mockAlert);
    
    if (!result) {
      throw new Error('响应操作失败');
    }
  }

  /**
   * 单元测试：测试NetworkTrafficMonitor
   */
  async testNetworkTrafficMonitor() {
    if (!this.modules.NetworkTrafficMonitor) {
      throw new Error('NetworkTrafficMonitor模块不可用');
    }
    
    const monitor = new this.modules.NetworkTrafficMonitor({
      mockMode: true
    });
    
    const result = monitor.startMonitoring();
    if (!result) {
      throw new Error('网络监控启动失败');
    }
    
    monitor.stopMonitoring();
  }

  /**
   * 单元测试：测试SystemBehaviorMonitor
   */
  async testSystemBehaviorMonitor() {
    if (!this.modules.SystemBehaviorMonitor) {
      throw new Error('SystemBehaviorMonitor模块不可用');
    }
    
    const monitor = new this.modules.SystemBehaviorMonitor({
      mockMode: true
    });
    
    const result = monitor.initialize();
    if (!result) {
      throw new Error('系统行为监控初始化失败');
    }
  }

  /**
   * 单元测试：测试MonitoringAndReporting
   */
  async testMonitoringAndReporting() {
    if (!this.modules.MonitoringAndReporting) {
      throw new Error('MonitoringAndReporting模块不可用');
    }
    
    const reporter = new this.modules.MonitoringAndReporting({
      logLevel: 'debug'
    });
    
    reporter.initialize();
    reporter.log('info', '测试日志');
    
    const status = reporter.getSystemStatus();
    if (!status) {
      throw new Error('获取系统状态失败');
    }
  }

  /**
   * 单元测试：测试Logger功能
   */
  async testLogger() {
    if (!this.modules.Logger) {
      throw new Error('Logger模块不可用');
    }
    
    const logger = this.modules.Logger;
    
    logger.info('测试日志信息');
    logger.warn('测试警告日志');
    logger.error('测试错误日志');
    
    const stats = logger.getStats();
    if (stats.total === 0) {
      throw new Error('日志统计信息无效');
    }
  }

  /**
   * 集成测试：测试完整检测流程
   */
  async testFullDetectionFlow() {
    // 模拟完整的检测流程
    const detector = new this.modules.InvasionDetector({
      testMode: true,
      mockMode: true
    });
    
    await detector.initialize();
    await detector.startDetection();
    
    // 模拟触发检测
    const mockData = this.mockDataGenerator.generateInvasionData('brute_force');
    await detector.processDetection(mockData);
    
    await detector.stopDetection();
  }

  /**
   * 集成测试：测试无人值守模式集成
   */
  async testUnattendedMode() {
    const detector = new this.modules.InvasionDetector({
      unattendedMode: true,
      mockMode: true
    });
    
    const result = await detector.enableUnattendedMode();
    if (!result) {
      throw new Error('无人值守模式启用失败');
    }
  }

  /**
   * 集成测试：测试告警和报告生成
   */
  async testAlertAndReporting() {
    const reporter = new this.modules.MonitoringAndReporting({
      alertChannels: ['console']
    });
    
    reporter.initialize();
    
    // 模拟检测事件
    const event = {
      type: 'sql_injection',
      severity: 'high',
      source: '192.168.1.100',
      description: 'SQL注入攻击尝试'
    };
    
    reporter.logDetectionEvent(event);
    
    const report = reporter.generateReport('summary');
    if (!report) {
      throw new Error('报告生成失败');
    }
  }

  /**
   * 性能测试：测试数据收集性能
   */
  async testDataCollectionPerformance() {
    const collector = new this.modules.DataCollector({
      performanceTest: true
    });
    
    const iterations = 100;
    const startTime = Date.now();
    
    for (let i = 0; i < iterations; i++) {
      collector.collect();
    }
    
    const endTime = Date.now();
    const avgTime = (endTime - startTime) / iterations;
    
    this.performanceMetrics.functionExecutionTime.dataCollection = avgTime;
    this.log('info', `数据收集性能: 平均${avgTime.toFixed(2)}ms/次`);
    
    // 性能阈值检查
    if (avgTime > 10) { // 10ms阈值
      throw new Error(`数据收集性能不达标: ${avgTime}ms > 10ms`);
    }
  }

  /**
   * 性能测试：测试分析引擎性能
   */
  async testAnalysisEnginePerformance() {
    const analyzer = new this.modules.InvasionAnalyzer({
      mockModel: true,
      performanceTest: true
    });
    
    const iterations = 50;
    const startTime = Date.now();
    
    for (let i = 0; i < iterations; i++) {
      const mockData = this.mockDataGenerator.generateInvasionData('random');
      analyzer.analyze(mockData);
    }
    
    const endTime = Date.now();
    const avgTime = (endTime - startTime) / iterations;
    
    this.performanceMetrics.functionExecutionTime.analysis = avgTime;
    this.log('info', `分析引擎性能: 平均${avgTime.toFixed(2)}ms/次`);
    
    // 性能阈值检查
    if (avgTime > 50) { // 50ms阈值
      throw new Error(`分析引擎性能不达标: ${avgTime}ms > 50ms`);
    }
  }

  /**
   * 性能测试：测试内存使用情况
   */
  async testMemoryUsage() {
    // 在Node.js环境下测试内存使用
    if (typeof process !== 'undefined' && process.memoryUsage) {
      const startMemory = process.memoryUsage();
      
      // 创建大量对象模拟内存压力
      const objects = [];
      for (let i = 0; i < 100000; i++) {
        objects.push(this.mockDataGenerator.generateInvasionData('random'));
      }
      
      const endMemory = process.memoryUsage();
      const usedMemory = (endMemory.heapUsed - startMemory.heapUsed) / (1024 * 1024); // MB
      
      this.performanceMetrics.memoryUsage.push({
        timestamp: new Date().toISOString(),
        usedMemoryMB: usedMemory
      });
      
      this.log('info', `内存使用测试: 新增使用${usedMemory.toFixed(2)}MB`);
      
      // 内存阈值检查
      if (usedMemory > 100) { // 100MB阈值
        throw new Error(`内存使用过高: ${usedMemory}MB > 100MB`);
      }
    }
  }

  /**
   * 性能测试：测试并发检测能力
   */
  async testConcurrentDetection() {
    const detector = new this.modules.InvasionDetector({
      mockMode: true,
      concurrentMode: true
    });
    
    await detector.initialize();
    
    const concurrentTasks = 10;
    const promises = [];
    
    const startTime = Date.now();
    
    for (let i = 0; i < concurrentTasks; i++) {
      promises.push(new Promise(async (resolve) => {
        const mockData = this.mockDataGenerator.generateInvasionData('random');
        await detector.processDetection(mockData);
        resolve();
      }));
    }
    
    await Promise.all(promises);
    
    const endTime = Date.now();
    const totalTime = endTime - startTime;
    
    this.log('info', `并发检测测试: ${concurrentTasks}个任务耗时${totalTime}ms`);
  }

  /**
   * 生成测试报告
   */
  generateTestReport() {
    const report = {
      summary: {
        totalTests: this.results.total,
        passed: this.results.passed,
        failed: this.results.failed,
        passRate: ((this.results.passed / this.results.total) * 100).toFixed(2) + '%',
        duration: this.results.duration + 'ms',
        startTime: this.results.startTime,
        endTime: this.results.endTime
      },
      performanceMetrics: this.performanceMetrics,
      testDetails: this.results.testCases,
      recommendations: this.generateRecommendations()
    };
    
    this.lastReport = report;
    
    if (this.config.verbose) {
      console.log('\n========== 测试报告 ==========');
      console.log(`总测试数: ${report.summary.totalTests}`);
      console.log(`通过: ${report.summary.passed}`);
      console.log(`失败: ${report.summary.failed}`);
      console.log(`通过率: ${report.summary.passRate}`);
      console.log(`总耗时: ${report.summary.duration}`);
      
      if (report.summary.failed > 0) {
        console.log('\n失败的测试:');
        this.results.testCases
          .filter(test => test.status === 'failed')
          .forEach(test => {
            console.log(`  - ${test.name}: ${test.error}`);
          });
      }
      
      console.log('==============================\n');
    }
    
    return report;
  }

  /**
   * 生成改进建议
   */
  generateRecommendations() {
    const recommendations = [];
    
    // 基于测试结果生成建议
    if (this.results.failed > 0) {
      recommendations.push(`修复失败的测试用例 (${this.results.failed}个)`);
    }
    
    // 基于性能指标生成建议
    const dataCollectionTime = this.performanceMetrics.functionExecutionTime.dataCollection;
    if (dataCollectionTime > 5) {
      recommendations.push('优化数据收集性能');
    }
    
    const analysisTime = this.performanceMetrics.functionExecutionTime.analysis;
    if (analysisTime > 30) {
      recommendations.push('优化分析引擎性能');
    }
    
    const memoryUsage = this.performanceMetrics.memoryUsage;
    if (memoryUsage.length > 0) {
      const maxMemory = Math.max(...memoryUsage.map(m => m.usedMemoryMB));
      if (maxMemory > 50) {
        recommendations.push('优化内存使用');
      }
    }
    
    // 总体健康状态
    const passRate = (this.results.passed / this.results.total) * 100;
    if (passRate >= 95) {
      recommendations.push('系统测试状态良好，建议进行实际环境测试');
    } else if (passRate >= 80) {
      recommendations.push('系统基本可用，但需要进一步优化');
    } else {
      recommendations.push('系统存在严重问题，需要全面审查和修复');
    }
    
    return recommendations;
  }

  /**
   * 记录测试日志
   */
  log(level, message, meta = {}) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      meta
    };
    
    this.testLogs.push(logEntry);
    
    if (this.config.verbose) {
      console.log(`[TEST] [${level.toUpperCase()}] ${message}`, meta);
    }
  }

  /**
   * 导出测试结果
   */
  exportResults(format = 'json') {
    if (format === 'json') {
      return JSON.stringify(this.results, null, 2);
    }
    
    // 其他格式的导出...
    return '';
  }

  /**
   * 清理测试环境
   */
  cleanup() {
    // 清理测试资源
    this.modules = {};
    this.log('info', '测试环境已清理');
  }
}

/**
 * 模拟数据生成器
 */
class MockDataGenerator {
  constructor() {
    this.invasionTypes = ['port_scan', 'brute_force', 'sql_injection', 'xss', 'malware', 'ddos'];
    this.severityLevels = ['low', 'medium', 'high', 'critical'];
    this.ipAddresses = [
      '192.168.1.100', '10.0.0.5', '172.16.0.25', '8.8.8.8', '1.1.1.1',
      '203.0.113.1', '198.51.100.10', '2001:db8::1'
    ];
  }

  /**
   * 生成入侵数据
   */
  generateInvasionData(type = 'random') {
    const invasionType = type === 'random' 
      ? this.invasionTypes[Math.floor(Math.random() * this.invasionTypes.length)]
      : type;
    
    const baseData = {
      timestamp: new Date().toISOString(),
      type: invasionType,
      source: this.getRandomIp(),
      target: this.getRandomIp(),
      protocol: this.getRandomProtocol(),
      severity: this.getRandomSeverity(),
      confidence: Math.random() * 0.4 + 0.6, // 0.6-1.0
      rawData: this.generateRawData(invasionType)
    };
    
    return baseData;
  }

  /**
   * 生成告警数据
   */
  generateAlert(type, severity = 'medium') {
    return {
      id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      type,
      severity,
      source: this.getRandomIp(),
      target: this.getRandomIp(),
      description: this.getAlertDescription(type),
      actionRequired: severity === 'high' || severity === 'critical',
      metadata: {
        detectionMethod: this.getDetectionMethod(type),
        correlationId: `corr-${Date.now()}`
      }
    };
  }

  /**
   * 获取随机IP地址
   */
  getRandomIp() {
    return this.ipAddresses[Math.floor(Math.random() * this.ipAddresses.length)];
  }

  /**
   * 获取随机协议
   */
  getRandomProtocol() {
    const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'SSH', 'FTP'];
    return protocols[Math.floor(Math.random() * protocols.length)];
  }

  /**
   * 获取随机严重级别
   */
  getRandomSeverity() {
    return this.severityLevels[Math.floor(Math.random() * this.severityLevels.length)];
  }

  /**
   * 生成原始数据
   */
  generateRawData(type) {
    switch (type) {
      case 'port_scan':
        return {
          scannedPorts: Array.from({length: Math.floor(Math.random() * 50) + 10}, (_, i) => 1024 + i),
          scanDuration: Math.random() * 60 + 10, // 10-70秒
          scanType: ['SYN', 'TCP', 'UDP'][Math.floor(Math.random() * 3)]
        };
        
      case 'brute_force':
        return {
          attempts: Math.floor(Math.random() * 100) + 10,
          username: 'admin',
          service: ['SSH', 'FTP', 'HTTP', 'RDP'][Math.floor(Math.random() * 4)],
          failRate: 0.95
        };
        
      case 'sql_injection':
        return {
          query: `SELECT * FROM users WHERE username = 'admin' OR '1'='1' --`,
          endpoint: '/login',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        };
        
      case 'xss':
        return {
          payload: `<script>alert('XSS')</script>`,
          endpoint: '/search',
          parameter: 'q'
        };
        
      case 'malware':
        return {
          hash: this.generateRandomHash(),
          filename: 'suspicious.exe',
          signature: 'Win32.Trojan.Generic',
          fileSize: Math.floor(Math.random() * 1024 * 1024) + 1024
        };
        
      case 'ddos':
        return {
          sourceIps: Array.from({length: Math.floor(Math.random() * 20) + 5}, () => this.getRandomIp()),
          packetsPerSecond: Math.floor(Math.random() * 10000) + 1000,
          targetPort: 80
        };
        
      default:
        return { type, randomData: Math.random().toString(36) };
    }
  }

  /**
   * 生成随机哈希值
   */
  generateRandomHash() {
    return Array.from({length: 32}, () => Math.random().toString(16)[2]).join('');
  }

  /**
   * 获取告警描述
   */
  getAlertDescription(type) {
    const descriptions = {
      port_scan: '检测到端口扫描活动',
      brute_force: '检测到暴力破解攻击',
      sql_injection: '检测到SQL注入尝试',
      xss: '检测到跨站脚本攻击',
      malware: '检测到恶意软件',
      ddos: '检测到DDoS攻击'
    };
    
    return descriptions[type] || '检测到可疑活动';
  }

  /**
   * 获取检测方法
   */
  getDetectionMethod(type) {
    const methods = {
      port_scan: '异常流量分析',
      brute_force: '频率限制检测',
      sql_injection: '模式匹配',
      xss: '输入验证',
      malware: '特征匹配',
      ddos: '流量异常检测'
    };
    
    return methods[type] || '行为分析';
  }

  /**
   * 生成正常流量数据
   */
  generateNormalTrafficData() {
    return {
      timestamp: new Date().toISOString(),
      source: this.getRandomIp(),
      target: this.getRandomIp(),
      protocol: ['TCP', 'UDP'][Math.floor(Math.random() * 2)],
      sourcePort: Math.floor(Math.random() * 65535) + 1,
      targetPort: [80, 443, 22, 3306, 5432][Math.floor(Math.random() * 5)],
      bytesSent: Math.floor(Math.random() * 1024 * 1024),
      bytesReceived: Math.floor(Math.random() * 1024 * 1024),
      connectionDuration: Math.random() * 30 + 5 // 5-35秒
    };
  }

  /**
   * 生成系统行为数据
   */
  generateSystemBehaviorData() {
    return {
      timestamp: new Date().toISOString(),
      processName: ['chrome.exe', 'firefox.exe', 'explorer.exe', 'svchost.exe', 'winlogon.exe'][Math.floor(Math.random() * 5)],
      processId: Math.floor(Math.random() * 65535),
      parentProcessId: Math.floor(Math.random() * 65535),
      userId: Math.floor(Math.random() * 1000),
      cpuUsage: Math.random() * 10,
      memoryUsage: Math.random() * 100,
      fileOperations: Math.floor(Math.random() * 10),
      networkConnections: Math.floor(Math.random() * 5)
    };
  }
}

// 导出测试套件
if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
  module.exports = {
    IDS_TestSuite,
    MockDataGenerator
  };
} else if (typeof window !== 'undefined') {
  window.IDS_TestSuite = IDS_TestSuite;
  window.MockDataGenerator = MockDataGenerator;
}

// 提供一个简单的运行测试函数
async function runIDSTests() {
  const testSuite = new IDS_TestSuite();
  await testSuite.initialize();
  const results = await testSuite.runTests();
  return results;
}

if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
  module.exports.runTests = runIDSTests;
} else if (typeof window !== 'undefined') {
  window.runIDSTests = runIDSTests;
}
