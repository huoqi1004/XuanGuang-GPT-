// 模型集成适配器 - 负责将入侵检测系统与现有ModelIntegrationEngine无缝集成
class ModelIntegrationAdapter {
  constructor(config = {}) {
    this.logger = window.globalLogger || console;
    this.modelEngine = null;
    
    this.config = {
      // 模型配置
      modelName: 'security-analyzer',
      fallbackModel: 'default',
      timeout: 30000,
      maxRetries: 2,
      retryDelay: 1000,
      
      // 缓存配置
      enableCaching: true,
      cacheTTL: 300, // 缓存有效期（秒）
      maxCacheSize: 100,
      
      // 性能配置
      batchSize: 10,
      maxConcurrentRequests: 5,
      queueTimeout: 60000,
      
      // 安全配置
      requestValidation: true,
      inputSanitization: true,
      sensitiveDataMasking: true,
      
      // 监控配置
      enableMetrics: true,
      enableTracing: true,
      logLevel: 'INFO',
      
      ...config
    };
    
    // 缓存系统
    this.cache = new Map();
    this.cacheLastCleanup = Date.now();
    
    // 请求队列和限流控制
    this.requestQueue = [];
    this.activeRequests = 0;
    this.queueProcessing = false;
    
    // 监控和指标
    this.metrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      cachedResponses: 0,
      averageResponseTime: 0,
      totalResponseTime: 0,
      rateLimitRejections: 0
    };
    
    // 初始化
    this.initialize();
  }

  // 初始化适配器
  initialize() {
    try {
      // 尝试获取全局的模型引擎实例
      if (window.modelEngine && typeof window.modelEngine.analyzeSituation === 'function') {
        this.modelEngine = window.modelEngine;
        this.logger.info('成功连接到现有ModelIntegrationEngine');
      } else {
        this.logger.warn('未找到ModelIntegrationEngine，将在运行时尝试连接');
      }
      
      // 设置定期缓存清理
      if (this.config.enableCaching) {
        setInterval(() => this.cleanupCache(), 60000); // 每分钟清理一次
      }
      
      // 注册到全局对象
      if (typeof window !== 'undefined' && !window.modelIntegrationAdapter) {
        window.modelIntegrationAdapter = this;
      }
      
      return true;
    } catch (error) {
      this.logger.error('初始化模型集成适配器失败:', error);
      return false;
    }
  }

  // 连接到模型引擎
  async connectModelEngine(engineInstance = null) {
    try {
      if (engineInstance) {
        this.modelEngine = engineInstance;
        this.logger.info('成功连接到提供的模型引擎实例');
        return true;
      }
      
      // 尝试获取全局模型引擎
      if (window.modelEngine) {
        this.modelEngine = window.modelEngine;
        this.logger.info('成功连接到全局模型引擎');
        return true;
      }
      
      // 尝试通过其他方式获取模型引擎
      this.modelEngine = await this.locateModelEngine();
      
      if (!this.modelEngine) {
        throw new Error('无法找到或初始化模型引擎');
      }
      
      return true;
    } catch (error) {
      this.logger.error('连接模型引擎失败:', error);
      return false;
    }
  }

  // 查找模型引擎
  async locateModelEngine() {
    // 这里可以实现更多查找模型引擎的策略
    // 1. 查找特定命名空间
    if (window.securitySystem?.modelEngine) {
      return window.securitySystem.modelEngine;
    }
    
    // 2. 查找应用实例
    if (window.app?.modelEngine) {
      return window.app.modelEngine;
    }
    
    // 3. 优先使用HTTP模型引擎（玄光GPT），失败则降级模拟
    try {
      if (typeof this.createFetchModelEngine === 'function') {
        return this.createFetchModelEngine();
      }
    } catch {}
    return this.createMockModelEngine();
  }

  // 创建模拟模型引擎（用于测试和紧急情况）
  createMockModelEngine() {
    const mockEngine = {
      analyzeSituation: async (prompt, options) => {
        this.logger.warn('使用模拟模型引擎进行分析');
        
        // 简单的基于规则的响应生成
        const response = this.generateMockResponse(prompt);
        
        return {
          success: true,
          data: JSON.stringify(response),
          model: 'mock-security-analyzer',
          timestamp: new Date()
        };
      },
      healthCheck: async () => ({
        status: 'operational',
        model: 'mock-security-analyzer',
        version: '1.0.0'
      })
    };
    
    return mockEngine;
  }

  // 生成模拟响应
  generateMockResponse(prompt) {
    // 基于提示内容生成不同的模拟响应
    const promptText = JSON.stringify(prompt);
    
    // 检测暴力破解模式
    if (promptText.includes('failedLogins') && promptText.includes('authentication')) {
      return {
        analysis: {
          isInvasion: true,
          confidence: 0.92,
          riskLevel: 'HIGH',
          invasionType: '暴力破解攻击',
          attackStage: '初始访问',
          tactics: ['初始访问'],
          techniques: ['暴力破解'],
          evidence: ['多次失败登录尝试', '来自同一IP的反复认证请求'],
          falsePositiveAnalysis: '误报可能性低，模式符合典型暴力破解特征'
        },
        impact: {
          affectedSystems: ['认证服务'],
          potentialDamage: '未授权系统访问',
          dataExposureRisk: '中等',
          persistenceRisk: '低',
          lateralMovementRisk: '低'
        },
        recommendations: {
          immediate: ['阻止可疑IP地址', '锁定受攻击账户'],
          shortTerm: ['实施账户锁定策略', '启用多因素认证'],
          longTerm: ['部署入侵防御系统', '定期进行安全审计']
        },
        chainOfThought: '基于多次失败登录尝试和认证模式，判断为暴力破解攻击'
      };
    }
    
    // 检测恶意软件模式
    if (promptText.includes('suspiciousProcesses') && promptText.includes('registryChanges')) {
      return {
        analysis: {
          isInvasion: true,
          confidence: 0.95,
          riskLevel: 'CRITICAL',
          invasionType: '恶意软件感染',
          attackStage: '持久化',
          tactics: ['持久化', '命令与控制'],
          techniques: ['注册表持久化', '可疑进程执行'],
          evidence: ['检测到可疑进程', '发现注册表运行项变更'],
          falsePositiveAnalysis: '误报可能性低，观察到典型恶意软件行为模式'
        },
        impact: {
          affectedSystems: ['操作系统', '文件系统'],
          potentialDamage: '数据泄露，系统损坏，勒索软件风险',
          dataExposureRisk: '高',
          persistenceRisk: '高',
          lateralMovementRisk: '高'
        },
        recommendations: {
          immediate: ['隔离受感染系统', '终止可疑进程'],
          shortTerm: ['清除恶意软件', '恢复系统备份'],
          longTerm: ['增强端点防护', '实施应用白名单']
        },
        chainOfThought: '基于可疑进程和注册表变更，判断为恶意软件感染'
      };
    }
    
    // 默认响应 - 未检测到入侵
    return {
      analysis: {
        isInvasion: false,
        confidence: 0.85,
        riskLevel: 'LOW',
        invasionType: '正常行为',
        attackStage: 'N/A',
        tactics: [],
        techniques: [],
        evidence: ['无异常连接模式', '正常的系统活动', '无高危安全事件'],
        falsePositiveAnalysis: '当前数据未显示入侵迹象'
      },
      impact: {
        affectedSystems: [],
        potentialDamage: '无',
        dataExposureRisk: '低',
        persistenceRisk: '低',
        lateralMovementRisk: '低'
      },
      recommendations: {
        immediate: ['继续监控'],
        shortTerm: ['定期安全扫描'],
        longTerm: ['保持系统更新']
      },
      chainOfThought: '基于可用数据，未发现明显入侵行为模式'
    };
  }

  // 发送分析请求到模型引擎
  async sendAnalysisRequest(prompt, options = {}) {
    try {
      // 验证输入
      if (this.config.requestValidation) {
        this.validateRequest(prompt, options);
      }
      
      // 敏感数据脱敏
      if (this.config.sensitiveDataMasking) {
        prompt = this.maskSensitiveData(prompt);
      }
      
      // 检查缓存
      if (this.config.enableCaching) {
        const cachedResponse = this.getFromCache(prompt, options);
        if (cachedResponse) {
          this.incrementMetric('cachedResponses');
          return cachedResponse;
        }
      }
      
      // 限流控制
      if (this.activeRequests >= this.config.maxConcurrentRequests) {
        // 将请求放入队列
        return this.enqueueRequest(prompt, options);
      }
      
      // 执行请求
      return await this.executeRequest(prompt, options);
    } catch (error) {
      this.handleRequestError(error, prompt, options);
      return this.getFallbackResponse(error, prompt);
    }
  }

  // 执行请求
  async executeRequest(prompt, options) {
    const startTime = Date.now();
    let result = null;
    
    try {
      // 确保模型引擎已连接
      if (!this.modelEngine) {
        await this.connectModelEngine();
        if (!this.modelEngine) {
          throw new Error('模型引擎不可用');
        }
      }
      
      // 增加活跃请求计数
      this.activeRequests++;
      this.incrementMetric('totalRequests');
      
      // 准备请求参数
      const requestParams = this.prepareRequestParams(prompt, options);
      
      // 执行请求
      if (this.config.enableTracing) {
        this.logger.debug('执行模型请求:', { prompt, params: requestParams });
      }
      
      result = await this.modelEngine.analyzeSituation(requestParams.prompt, requestParams.options);
      
      // 验证响应
      if (!result || !result.success) {
        throw new Error('模型返回无效响应: ' + JSON.stringify(result));
      }
      
      // 处理成功响应
      const processedResult = this.processResponse(result);
      
      // 缓存结果
      if (this.config.enableCaching && processedResult) {
        this.cacheResponse(prompt, options, processedResult);
      }
      
      // 更新指标
      this.incrementMetric('successfulRequests');
      
      return processedResult;
    } finally {
      // 计算响应时间
      const responseTime = Date.now() - startTime;
      this.updateResponseTimeMetric(responseTime);
      
      // 减少活跃请求计数
      this.activeRequests--;
      
      // 处理队列中的下一个请求
      this.processQueue();
    }
  }

  // 准备请求参数
  prepareRequestParams(prompt, options) {
    return {
      prompt: {
        system: prompt.system || '',
        user: this.config.inputSanitization ? this.sanitizeInput(prompt.user || '') : (prompt.user || '')
      },
      options: {
        taskType: options.taskType || 'security_analysis',
        timeout: options.timeout || this.config.timeout,
        maxRetries: options.maxRetries || this.config.maxRetries,
        modelName: options.modelName || this.config.modelName,
        fallbackModel: options.fallbackModel || this.config.fallbackModel,
        ...options
      }
    };
  }

  // 处理响应
  processResponse(rawResponse) {
    try {
      let result = rawResponse.data;
      
      // 如果响应是字符串，尝试解析为JSON
      if (typeof result === 'string') {
        try {
          result = JSON.parse(result);
        } catch (e) {
          // 如果解析失败，保留原始字符串
          this.logger.warn('无法将模型响应解析为JSON，保留原始格式');
        }
      }
      
      // 添加元数据
      return {
        ...result,
        metadata: {
          timestamp: new Date(),
          model: rawResponse.model || 'unknown',
          responseTime: rawResponse.responseTime || 0,
          cached: false
        }
      };
    } catch (error) {
      this.logger.error('处理模型响应失败:', error);
      throw error;
    }
  }

  // 验证请求
  validateRequest(prompt, options) {
    if (!prompt || (!prompt.system && !prompt.user)) {
      throw new Error('无效的提示：缺少必要的提示内容');
    }
    
    // 检查提示长度
    const promptLength = (prompt.system?.length || 0) + (prompt.user?.length || 0);
    if (promptLength > 100000) { // 100KB限制
      throw new Error('提示内容过长，超过了系统限制');
    }
    
    // 检查选项
    if (options && options.timeout && options.timeout > 60000) {
      throw new Error('超时设置过大，不允许超过60秒');
    }
    
    return true;
  }

  // 输入净化
  sanitizeInput(input) {
    if (!input) return input;
    
    // 移除潜在危险字符和格式
    let sanitized = input
      .replace(/<script[^>]*>.*?<\/script>/gi, '') // 移除脚本标签
      .replace(/<iframe[^>]*>.*?<\/iframe>/gi, '') // 移除iframe标签
      .replace(/javascript:[^\s]*/gi, '') // 移除javascript协议
      .replace(/on\w+\s*=\s*"[^"]*"/gi, '') // 移除事件处理器
      .replace(/on\w+\s*=\s*'[^']*'/gi, '') // 移除事件处理器
      .replace(/on\w+\s*=\s*[^\s>]*/gi, '') // 移除事件处理器
      .trim();
    
    return sanitized;
  }

  // 敏感数据脱敏
  maskSensitiveData(prompt) {
    const maskedPrompt = { ...prompt };
    
    // 脱敏用户提示中的敏感信息
    if (maskedPrompt.user) {
      // 脱敏IP地址
      maskedPrompt.user = maskedPrompt.user.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '***.***.***.***');
      
      // 脱敏电子邮件
      maskedPrompt.user = maskedPrompt.user.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '***@***.***');
      
      // 脱敏用户名
      maskedPrompt.user = maskedPrompt.user.replace(/\b(username|user|login):\s*["']?([\w.-]+)["']?/gi, '$1: ***');
      
      // 脱敏密码
      maskedPrompt.user = maskedPrompt.user.replace(/\b(password|pwd|pass):\s*["']?([^"\']+)["']?/gi, '$1: ***');
      
      // 脱敏API密钥
      maskedPrompt.user = maskedPrompt.user.replace(/\b(api[_-]?key|token|secret):\s*["']?([\w\d]{8,})["']?/gi, '$1: ***');
      
      // 脱敏文件路径中的用户名
      maskedPrompt.user = maskedPrompt.user.replace(/(C:\\Users\\)([^\\]+)/g, '$1***');
    }
    
    return maskedPrompt;
  }

  // 缓存管理
  cacheResponse(prompt, options, response) {
    const key = this.generateCacheKey(prompt, options);
    const cacheEntry = {
      response,
      timestamp: Date.now(),
      expiration: Date.now() + (this.config.cacheTTL * 1000)
    };
    
    // 添加到缓存
    this.cache.set(key, cacheEntry);
    
    // 检查缓存大小
    if (this.cache.size > this.config.maxCacheSize) {
      this.evictOldestCacheEntry();
    }
    
    return true;
  }

  // 从缓存获取
  getFromCache(prompt, options) {
    const key = this.generateCacheKey(prompt, options);
    const entry = this.cache.get(key);
    
    if (!entry) return null;
    
    // 检查是否过期
    if (Date.now() > entry.expiration) {
      this.cache.delete(key);
      return null;
    }
    
    // 返回缓存的响应并添加元数据
    return {
      ...entry.response,
      metadata: {
        ...entry.response.metadata,
        cached: true,
        cachedAt: new Date(entry.timestamp)
      }
    };
  }

  // 生成缓存键
  generateCacheKey(prompt, options) {
    // 创建提示的指纹
    const promptFingerprint = JSON.stringify({
      system: prompt.system?.substring(0, 100) || '',
      user: prompt.user?.substring(0, 200) || ''
    });
    
    // 创建选项的指纹
    const optionsFingerprint = JSON.stringify({
      modelName: options.modelName || '',
      taskType: options.taskType || ''
    });
    
    // 简单的缓存键生成
    return `cache_${promptFingerprint.substring(0, 50)}_${optionsFingerprint}`;
  }

  // 缓存清理
  cleanupCache() {
    const now = Date.now();
    let evictedCount = 0;
    
    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiration) {
        this.cache.delete(key);
        evictedCount++;
      }
    }
    
    if (evictedCount > 0 && this.config.logLevel === 'DEBUG') {
      this.logger.debug(`清理了 ${evictedCount} 个过期缓存项`);
    }
    
    // 更新最后清理时间
    this.cacheLastCleanup = now;
  }

  // 驱逐最旧的缓存项
  evictOldestCacheEntry() {
    let oldestKey = null;
    let oldestTime = Infinity;
    
    for (const [key, entry] of this.cache.entries()) {
      if (entry.timestamp < oldestTime) {
        oldestTime = entry.timestamp;
        oldestKey = key;
      }
    }
    
    if (oldestKey) {
      this.cache.delete(oldestKey);
    }
  }

  // 请求队列管理
  enqueueRequest(prompt, options) {
    return new Promise((resolve, reject) => {
      const queueItem = {
        prompt,
        options,
        resolve,
        reject,
        timestamp: Date.now()
      };
      
      this.requestQueue.push(queueItem);
      
      // 开始处理队列（如果尚未开始）
      if (!this.queueProcessing) {
        this.processQueue();
      }
      
      // 设置队列项超时
      setTimeout(() => {
        const index = this.requestQueue.findIndex(item => item === queueItem);
        if (index !== -1) {
          this.requestQueue.splice(index, 1);
          reject(new Error('请求在队列中等待超时'));
        }
      }, this.config.queueTimeout);
    });
  }

  // 处理队列
  async processQueue() {
    if (this.queueProcessing || this.requestQueue.length === 0 || this.activeRequests >= this.config.maxConcurrentRequests) {
      this.queueProcessing = false;
      return;
    }
    
    this.queueProcessing = true;
    
    try {
      // 获取下一个请求
      const queueItem = this.requestQueue.shift();
      if (!queueItem) {
        this.queueProcessing = false;
        return;
      }
      
      // 检查请求是否已超时
      if (Date.now() - queueItem.timestamp > this.config.queueTimeout) {
        queueItem.reject(new Error('请求在队列中等待超时'));
        return this.processQueue();
      }
      
      // 执行请求
      const result = await this.executeRequest(queueItem.prompt, queueItem.options);
      queueItem.resolve(result);
    } catch (error) {
      // 如果有当前正在处理的队列项，拒绝它
      if (this.currentQueueItem) {
        this.currentQueueItem.reject(error);
      }
    } finally {
      this.processQueue(); // 递归处理下一个请求
    }
  }

  // 处理请求错误
  handleRequestError(error, prompt, options) {
    this.incrementMetric('failedRequests');
    
    // 记录错误
    this.logger.error('模型请求失败:', {
      error: error.message,
      promptLength: (prompt.system?.length || 0) + (prompt.user?.length || 0),
      modelName: options.modelName || this.config.modelName
    });
    
    // 可以在这里添加错误恢复逻辑
    // 例如：切换到备用模型、重试策略等
  }

  // 获取备用响应
  getFallbackResponse(error, prompt) {
    // 生成一个安全的备用响应
    return {
      analysis: {
        isInvasion: false,
        confidence: 0.5, // 低置信度
        riskLevel: 'UNKNOWN',
        invasionType: '无法确定',
        attackStage: 'UNKNOWN',
        tactics: [],
        techniques: [],
        evidence: ['模型分析服务暂时不可用'],
        falsePositiveAnalysis: '由于服务不可用，无法进行完整分析'
      },
      impact: {
        affectedSystems: [],
        potentialDamage: '未知',
        dataExposureRisk: '未知',
        persistenceRisk: '未知',
        lateralMovementRisk: '未知'
      },
      recommendations: {
        immediate: ['重启分析服务', '检查系统日志'],
        shortTerm: ['使用备用分析方法', '手动审查可疑活动'],
        longTerm: ['增加系统弹性', '实施多模型策略']
      },
      metadata: {
        timestamp: new Date(),
        fallback: true,
        error: error.message,
        model: 'fallback'
      }
    };
  }

  // 批量分析
  async batchAnalyze(requests, batchOptions = {}) {
    const batchSize = batchOptions.batchSize || this.config.batchSize;
    const results = [];
    
    // 将请求分成批次
    for (let i = 0; i < requests.length; i += batchSize) {
      const batch = requests.slice(i, i + batchSize);
      const batchResults = await Promise.allSettled(
        batch.map(req => this.sendAnalysisRequest(req.prompt, req.options))
      );
      
      // 处理批次结果
      batchResults.forEach((result, index) => {
        if (result.status === 'fulfilled') {
          results.push(result.value);
        } else {
          // 使用备用响应
          results.push(this.getFallbackResponse(result.reason, batch[index].prompt));
        }
      });
    }
    
    return results;
  }

  // 健康检查
  async healthCheck() {
    try {
      // 检查模型引擎是否可用
      if (!this.modelEngine) {
        await this.connectModelEngine();
      }
      
      // 执行引擎健康检查
      if (this.modelEngine && typeof this.modelEngine.healthCheck === 'function') {
        const engineHealth = await this.modelEngine.healthCheck();
        
        return {
          status: engineHealth.status || 'unknown',
          model: engineHealth.model || 'unknown',
          version: engineHealth.version || 'unknown',
          timestamp: new Date(),
          cacheSize: this.cache.size,
          queueSize: this.requestQueue.length,
          activeRequests: this.activeRequests
        };
      }
      
      // 如果引擎没有健康检查方法，尝试简单请求
      const testResult = await this.sendAnalysisRequest(
        { user: '执行健康检查' },
        { timeout: 5000, taskType: 'health_check' }
      );
      
      return {
        status: testResult ? 'operational' : 'degraded',
        model: this.config.modelName,
        timestamp: new Date(),
        cacheSize: this.cache.size,
        queueSize: this.requestQueue.length,
        activeRequests: this.activeRequests
      };
    } catch (error) {
      this.logger.error('健康检查失败:', error);
      return {
        status: 'unhealthy',
        error: error.message,
        timestamp: new Date(),
        cacheSize: this.cache.size,
        queueSize: this.requestQueue.length,
        activeRequests: this.activeRequests
      };
    }
  }

  // 指标管理
  incrementMetric(metricName) {
    if (this.metrics[metricName] !== undefined) {
      this.metrics[metricName]++;
    }
  }

  updateResponseTimeMetric(responseTime) {
    this.metrics.totalResponseTime += responseTime;
    this.metrics.averageResponseTime = this.metrics.totalResponseTime / this.metrics.totalRequests;
  }

  // 获取指标
  getMetrics() {
    return { ...this.metrics };
  }

  // 重置指标
  resetMetrics() {
    this.metrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      cachedResponses: 0,
      averageResponseTime: 0,
      totalResponseTime: 0,
      rateLimitRejections: 0
    };
    return this.metrics;
  }

  // 更新配置
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    return this.config;
  }

  // 清除缓存
  clearCache() {
    const size = this.cache.size;
    this.cache.clear();
    return size;
  }

  // 清空队列
  clearQueue() {
    const size = this.requestQueue.length;
    
    // 拒绝队列中的所有请求
    this.requestQueue.forEach(item => {
      item.reject(new Error('请求队列已被清空'));
    });
    
    this.requestQueue = [];
    this.queueProcessing = false;
    
    return size;
  }

  // 关闭适配器
  shutdown() {
    // 清空队列
    this.clearQueue();
    
    // 清除缓存
    this.clearCache();
    
    // 清理全局引用
    if (window.modelIntegrationAdapter === this) {
      delete window.modelIntegrationAdapter;
    }
    
    return true;
  }
}

// 导出适配器类
export default ModelIntegrationAdapter;

// 创建默认实例
let defaultAdapter = null;

export function getModelIntegrationAdapter() {
  if (!defaultAdapter) {
    defaultAdapter = new ModelIntegrationAdapter();
  }
  return defaultAdapter;
}

// 扩展：创建HTTP模型引擎（玄光GPT本地服务）
ModelIntegrationAdapter.prototype.createFetchModelEngine = function() {
  const engine = {
    analyzeSituation: async (prompt, options = {}) => {
      const base = (window.modelBase || '').trim() || 'http://127.0.0.1:8001';
      const model = (options.modelName || window.modelName || 'xuangguang-gpt');
      const url = `${base.replace(/\/+$/, '')}/v1/chat/completions`;
      const body = {
        model,
        messages: [
          { role: 'system', content: prompt.system || '' },
          { role: 'user', content: prompt.user || '' }
        ],
        stream: false
      };
      const controller = new AbortController();
      const to = Math.max(3000, parseInt(options.timeout || this.config?.timeout || 10000));
      const timer = setTimeout(() => controller.abort(), to);
      try {
        const resp = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          signal: controller.signal
        });
        clearTimeout(timer);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        const content = data?.choices?.[0]?.message?.content || data?.choices?.[0]?.text || '';
        return { success: true, data: content ? JSON.stringify({ advice: content }) : '{}', model: model, timestamp: new Date() };
      } catch (e) {
        clearTimeout(timer);
        throw e;
      }
    },
    healthCheck: async () => ({ status: 'operational', model: 'xuangguang-gpt' })
  };
  return engine;
};

// 扩展：分析并记录到自动防御面板
  ModelIntegrationAdapter.prototype.analyzeAndRecord = async function(context) {
    try {
      const prompt = { system: '玄光GPT安全分析', user: JSON.stringify(context) };
      const res = await this.sendAnalysisRequest(prompt, { taskType: 'defense_advice', modelName: 'xuangguang-gpt', timeout: 10000 });
      let adviceText = '';
      if (typeof res === 'string') adviceText = res;
      else if (res?.advice) adviceText = res.advice;
      else if (res?.recommendations) {
        const r = res.recommendations;
        adviceText = [ ...(r.immediate || []), ...(r.shortTerm || []), ...(r.longTerm || []) ].join('\n');
      } else if (res?.analysis) {
        adviceText = `风险: ${res.analysis.riskLevel || 'UNKNOWN'} 入侵: ${res.analysis.isInvasion ? '是' : '否'} 置信度: ${res.analysis.confidence ?? ''}`;
      }
      const ipMatch = String(context.message || '').match(/(?:来源IP|IP|源地址)[^\d]*(\b(?:\d{1,3}\.){3}\d{1,3}\b)/);
      const targetIp = ipMatch ? ipMatch[1] : '';
      const dfActions = document.getElementById('df-actions');
      if (dfActions) {
        const html = `<div class=\"defense-action\">\n  <div class=\"action-type\">模型意见</div>\n  <div class=\"action-target\">来源: ${context.title}</div>\n  <div class=\"action-result info\">建议</div>\n  <div class=\"action-time\">${new Date().toLocaleString()}</div>\n  <div class=\"action-detail\" style=\"margin-top:6px; white-space:pre-wrap;\">${(adviceText || '未提供建议')}</div>\n  <div class=\"action-controls\" style=\"margin-top:8px; display:flex; gap:8px;\">\n    <button class=\"df-exec-btn\" data-action=\"block-ip\" data-target=\"${targetIp}\">阻断IP</button>\n    <button class=\"df-exec-btn\" data-action=\"update-rule\" data-target=\"\">更新规则</button>\n    <button class=\"df-exec-btn\" data-action=\"isolate-host\" data-target=\"${targetIp}\">隔离主机</button>\n  </div>\n</div>`;
        dfActions.innerHTML += html;
      }
      const dfReport = document.getElementById('df-report');
      if (dfReport) {
        dfReport.textContent += `\n\n[模型意见] ${new Date().toLocaleString()}\n${(adviceText || '未提供建议')}\n`;
      }
      // 自动执行策略：无人值守启用且风险达到门限
      const state = (window.app && window.app.defenseState) ? window.app.defenseState : { isDefending: false, autoMode: false, riskThreshold: 'medium' };
      const threshold = String(state.riskThreshold || 'medium').toLowerCase();
      const rank = { low: 1, medium: 2, high: 3, critical: 4 };
      const detectRisk = (txt) => {
        const t = String(txt || '').toLowerCase();
        if (/critical|严重|紧急/.test(t)) return 'critical';
        if (/high|高/.test(t)) return 'high';
        if (/medium|中/.test(t)) return 'medium';
        if (/low|低/.test(t)) return 'low';
        return 'medium';
      };
      const risk = detectRisk(adviceText);
      if (state.isDefending && state.autoMode && rank[risk] >= rank[threshold]) {
        let action = 'update-rule';
        const txt = adviceText.toLowerCase();
        if (/阻断|block/.test(txt) && targetIp) action = 'block-ip';
        else if (/隔离|isolate/.test(txt) && targetIp) action = 'isolate-host';
        else if (/规则|更新|rule/.test(txt)) action = 'update-rule';
        try {
          if (window.app && typeof window.app.executeDefenseAction === 'function') {
            window.app.executeDefenseAction(action, targetIp);
          }
        } catch {}
      }
    } catch (e) {
      (this.logger || console).error('模型分析与记录失败:', e);
    }
  };

// 全局事件监听：入侵与防御通知触发模型分析
if (typeof window !== 'undefined') {
  window.addEventListener('app:notification', (e) => {
    const n = e?.detail;
    if (!n) return;
    const title = String(n.title || '');
    const message = String(n.message || '');
    const relate = title.includes('入侵检测') || title.includes('自动防御') || title.includes('警报');
    if (!relate) return;
    const ctx = { title, message, time: n.time || new Date().toLocaleString() };
    try {
      getModelIntegrationAdapter().analyzeAndRecord(ctx);
    } catch {}
  });
  window.addEventListener('click', (ev) => {
    const t = ev.target;
    if (t && t.classList && t.classList.contains('df-exec-btn')) {
      const action = t.getAttribute('data-action') || '';
      const target = t.getAttribute('data-target') || '';
      try {
        if (window.app && typeof window.app.executeDefenseAction === 'function') {
          window.app.executeDefenseAction(action, target);
        }
        window.dispatchEvent(new CustomEvent('app:defense-action', { detail: { action, target, time: new Date().toLocaleString() } }));
      } catch {}
    }
  });
}
