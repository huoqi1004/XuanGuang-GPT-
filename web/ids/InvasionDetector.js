// 入侵检测系统主控制类
class InvasionDetector {
  constructor() {
    // 获取全局实例
    this.logger = window.globalLogger || console;
    this.monitoringManager = window.monitoringManager;
    this.modelEngine = window.modelEngine;
    this.autonomousModeManager = window.autonomousModeManager;
    
    // 初始化各模块
    this.dataCollector = null;
    this.analyzer = null;
    this.responseManager = null;
    
    // 系统状态
    this.isActive = false;
    this.detectionInterval = null;
    this.lastDetectionTime = null;
    this.detectionResults = [];
    
    // 配置
    this.config = this.loadConfig();
    
    // 初始化系统
    this.initialize();
    
    // 注册到全局
    window.invasionDetector = this;
  }
  
  // 初始化系统
  initialize() {
    try {
      // 动态加载依赖模块，避免循环引用
      setTimeout(() => {
        this.loadModules();
        this.logger.info('入侵检测系统已初始化');
      }, 0);
    } catch (error) {
      this.logger.error('入侵检测系统初始化失败:', error);
    }
  }
  
  // 加载系统模块
  async loadModules() {
    try {
      // 动态导入模块
      const modules = await import('./modules/index.js');
      
      // 初始化各模块
      this.dataCollector = new modules.DataCollector();
      this.analyzer = new modules.InvasionAnalyzer();
      this.responseManager = new modules.ResponseManager();
      
      // 注册到监控系统
      this.registerToMonitoring();
      
      // 集成到无人值守模式
      if (this.config.integrateWithAutonomousMode) {
        this.integrateWithAutonomousMode();
      }
      
    } catch (error) {
      this.logger.error('加载入侵检测模块失败:', error);
    }
  }
  
  // 加载配置
  loadConfig() {
    try {
      // 从配置管理器获取配置或使用默认配置
      const configManager = window.ConfigManager;
      const savedConfig = configManager ? configManager.getInvasionDetectorConfig() : null;
      
      return {
        enabled: true,
        detectionInterval: 60000, // 默认检测间隔（毫秒）
        integrateWithAutonomousMode: true,
        dataCollection: {
          network: true,
          system: true,
          logs: true,
          securityEvents: true
        },
        analysis: {
          useLLM: true,
          confidenceThreshold: 0.7
        },
        response: {
          autoBlock: true,
          autoNotify: true,
          severityLevels: {
            LOW: { notify: true, block: false },
            MEDIUM: { notify: true, block: true },
            HIGH: { notify: true, block: true },
            CRITICAL: { notify: true, block: true, emergencyResponse: true }
          }
        },
        ...savedConfig
      };
    } catch (error) {
      this.logger.error('加载入侵检测配置失败:', error);
      return this.getDefaultConfig();
    }
  }
  
  // 获取默认配置
  getDefaultConfig() {
    return {
      enabled: true,
      detectionInterval: 60000,
      integrateWithAutonomousMode: true,
      dataCollection: {
        network: true,
        system: true,
        logs: true,
        securityEvents: true
      },
      analysis: {
        useLLM: true,
        confidenceThreshold: 0.7
      },
      response: {
        autoBlock: true,
        autoNotify: true,
        severityLevels: {
          LOW: { notify: true, block: false },
          MEDIUM: { notify: true, block: true },
          HIGH: { notify: true, block: true },
          CRITICAL: { notify: true, block: true, emergencyResponse: true }
        }
      }
    };
  }
  
  // 保存配置
  saveConfig(config) {
    try {
      this.config = { ...this.config, ...config };
      const configManager = window.ConfigManager;
      if (configManager) {
        configManager.saveInvasionDetectorConfig(this.config);
      }
      this.logger.info('入侵检测配置已保存');
      return true;
    } catch (error) {
      this.logger.error('保存入侵检测配置失败:', error);
      return false;
    }
  }
  
  // 启动检测服务
  start() {
    try {
      if (this.isActive) {
        this.logger.warn('入侵检测系统已经在运行');
        return true;
      }
      
      this.isActive = true;
      
      // 立即执行一次检测
      this.performDetection();
      
      // 设置定时检测
      this.detectionInterval = setInterval(() => {
        this.performDetection();
      }, this.config.detectionInterval);
      
      this.logger.info('入侵检测系统已启动，检测间隔:', this.config.detectionInterval, 'ms');
      
      // 更新监控面板
      if (this.monitoringManager) {
        this.monitoringManager.updateAlertPanel('入侵检测系统已启动');
      }
      
      return true;
    } catch (error) {
      this.logger.error('启动入侵检测系统失败:', error);
      this.isActive = false;
      return false;
    }
  }
  
  // 停止检测服务
  stop() {
    try {
      if (!this.isActive) {
        this.logger.warn('入侵检测系统未在运行');
        return true;
      }
      
      this.isActive = false;
      
      // 清除定时检测
      if (this.detectionInterval) {
        clearInterval(this.detectionInterval);
        this.detectionInterval = null;
      }
      
      this.logger.info('入侵检测系统已停止');
      
      // 更新监控面板
      if (this.monitoringManager) {
        this.monitoringManager.updateAlertPanel('入侵检测系统已停止');
      }
      
      return true;
    } catch (error) {
      this.logger.error('停止入侵检测系统失败:', error);
      return false;
    }
  }
  
  // 执行检测流程
  async performDetection() {
    try {
      const startTime = Date.now();
      this.logger.info('开始执行入侵检测...');
      
      // 1. 收集数据
      const data = await this.collectData();
      if (!data || (Object.keys(data).length === 0)) {
        this.logger.warn('未收集到检测数据');
        return;
      }
      
      // 2. 分析数据
      const analysisResults = await this.analyzeData(data);
      if (!analysisResults) {
        this.logger.warn('数据分析失败');
        return;
      }
      
      // 3. 处理结果
      await this.handleResults(analysisResults);
      
      // 4. 记录检测时间
      this.lastDetectionTime = new Date();
      
      // 5. 更新检测结果历史
      this.detectionResults.push({
        timestamp: this.lastDetectionTime,
        results: analysisResults,
        duration: Date.now() - startTime
      });
      
      // 限制历史记录数量
      if (this.detectionResults.length > 100) {
        this.detectionResults.shift();
      }
      
      this.logger.info('入侵检测完成，耗时:', Date.now() - startTime, 'ms');
    } catch (error) {
      this.logger.error('执行入侵检测失败:', error);
    }
  }
  
  // 收集检测数据
  async collectData() {
    try {
      if (!this.dataCollector) {
        this.logger.error('数据收集器未初始化');
        return null;
      }
      
      // 根据配置收集相应类型的数据
      const data = {
        timestamp: new Date(),
        network: this.config.dataCollection.network ? await this.dataCollector.collectNetworkData() : null,
        system: this.config.dataCollection.system ? await this.dataCollector.collectSystemData() : null,
        logs: this.config.dataCollection.logs ? await this.dataCollector.collectLogData() : null,
        securityEvents: this.config.dataCollection.securityEvents ? await this.dataCollector.collectSecurityEvents() : null
      };
      
      return data;
    } catch (error) {
      this.logger.error('收集检测数据失败:', error);
      return null;
    }
  }
  
  // 分析检测数据
  async analyzeData(data) {
    try {
      if (!this.analyzer) {
        this.logger.error('数据分析器未初始化');
        return null;
      }
      
      // 执行分析
      const results = await this.analyzer.analyze(data);
      
      // 只返回高于置信度阈值的结果
      if (results && results.confidence >= this.config.analysis.confidenceThreshold) {
        return results;
      }
      
      return null;
    } catch (error) {
      this.logger.error('分析检测数据失败:', error);
      return null;
    }
  }
  
  // 处理分析结果
  async handleResults(results) {
    try {
      if (!this.responseManager) {
        this.logger.error('响应管理器未初始化');
        return;
      }
      
      if (!results || !results.isInvasion) {
        return;
      }
      
      // 交给响应管理器处理
      await this.responseManager.handleDetectionResult(results);
      
      // 记录到日志
      this.logger.warn('检测到潜在入侵行为:', {
        type: results.invasionType,
        riskLevel: results.riskLevel,
        confidence: results.confidence,
        details: results.details
      });
      
    } catch (error) {
      this.logger.error('处理分析结果失败:', error);
    }
  }
  
  // 集成到无人值守模式
  integrateWithAutonomousMode() {
    try {
      if (!this.autonomousModeManager) {
        this.logger.error('无人值守模式管理器未找到');
        return false;
      }
      
      // 向无人值守模式注册入侵检测任务
      this.autonomousModeManager.registerTask({
        id: 'invasionDetection',
        name: '入侵检测',
        description: '检测系统中的潜在入侵行为',
        execute: async () => {
          return await this.performDetection();
        },
        frequency: 'interval', // 基于时间间隔执行
        interval: this.config.detectionInterval // 使用配置的检测间隔
      });
      
      // 注册入侵响应为可执行动作
      this.autonomousModeManager.registerActionType('blockInvasion', {
        name: '拦截入侵',
        description: '拦截检测到的入侵行为',
        execute: async (params) => {
          if (this.responseManager) {
            return await this.responseManager.blockInvasion(params);
          }
          return { success: false, message: '响应管理器未初始化' };
        }
      });
      
      // 注册入侵分析为系统分析的一部分
      if (typeof this.autonomousModeManager.addSystemAnalysisTask === 'function') {
        this.autonomousModeManager.addSystemAnalysisTask('invasionAnalysis', async () => {
          const data = await this.collectData();
          if (data) {
            return await this.analyzeData(data);
          }
          return null;
        });
      }
      
      this.logger.info('入侵检测系统已集成到无人值守模式');
      return true;
    } catch (error) {
      this.logger.error('集成到无人值守模式失败:', error);
      return false;
    }
  }
  
  // 注册到监控系统
  registerToMonitoring() {
    try {
      if (!this.monitoringManager) {
        this.logger.error('监控管理器未找到');
        return false;
      }
      
      // 注册入侵检测相关的监控指标
      this.monitoringManager.registerMetric('invasion_detection_active', () => this.isActive);
      this.monitoringManager.registerMetric('invasion_detection_last_run', () => this.lastDetectionTime);
      this.monitoringManager.registerMetric('invasion_detection_total', () => {
        return this.detectionResults.filter(r => r.results && r.results.isInvasion).length;
      });
      
      // 设置告警阈值
      this.monitoringManager.setAlertThreshold('invasion_detection_active', {
        type: 'boolean',
        condition: 'false',
        message: '入侵检测系统未运行'
      });
      
      this.logger.info('入侵检测系统已注册到监控系统');
      return true;
    } catch (error) {
      this.logger.error('注册到监控系统失败:', error);
      return false;
    }
  }
  
  // 获取系统状态
  getStatus() {
    return {
      isActive: this.isActive,
      lastDetectionTime: this.lastDetectionTime,
      detectionCount: this.detectionResults.length,
      invasionCount: this.detectionResults.filter(r => r.results && r.results.isInvasion).length,
      config: this.config
    };
  }
  
  // 获取最近的检测结果
  getRecentResults(limit = 10) {
    return this.detectionResults.slice(-limit).reverse();
  }
  
  // 手动触发检测
  async triggerDetection() {
    return await this.performDetection();
  }
  
  // 更新配置
  updateConfig(newConfig) {
    const oldEnabled = this.config.enabled;
    const oldInterval = this.config.detectionInterval;
    
    // 保存新配置
    this.saveConfig(newConfig);
    
    // 如果启用状态或间隔时间改变，重新启动检测
    if (oldEnabled !== this.config.enabled || oldInterval !== this.config.detectionInterval) {
      this.restartDetection();
    }
    
    return true;
  }
  
  // 重启检测
  restartDetection() {
    this.stop();
    if (this.config.enabled) {
      this.start();
    }
  }
}

// 导出类
export default InvasionDetector;

// 如果在浏览器环境中，自动创建实例
if (typeof window !== 'undefined' && !window.invasionDetector) {
  window.addEventListener('load', () => {
    new InvasionDetector();
  });
}