// 入侵拦截管理器 - 负责根据检测结果自动执行拦截操作，保护系统安全
class InvasionInterceptionManager {
  constructor(config = {}) {
    this.logger = window.globalLogger || console;
    this.invasionDetector = null;
    
    // 配置项
    this.config = {
      // 拦截策略配置
      autoIntercept: true, // 是否自动拦截
      minimumRiskLevel: 'MEDIUM', // 最低拦截风险等级
      confidenceThreshold: 0.7, // 拦截置信度阈值
      
      // 拦截动作配置
      blockIpAddresses: true, // 是否阻止IP
      terminateProcesses: true, // 是否终止进程
      disconnectNetwork: true, // 是否断开网络连接
      isolateSystem: false, // 是否隔离系统（默认关闭，高风险操作）
      quarantineFiles: true, // 是否隔离文件
      
      // 安全机制配置
      requireConfirmation: false, // 是否需要确认
      emergencyOverride: true, // 是否允许紧急覆盖
      whitelistEnabled: true, // 是否启用白名单
      
      // 监控配置
      logInterceptions: true, // 是否记录拦截操作
      alertOnInterception: true, // 是否在拦截时告警
      notifyAdmin: true, // 是否通知管理员
      
      // 恢复配置
      enableAutoRecovery: true, // 是否启用自动恢复
      recoveryTimeframe: 3600000, // 自动恢复时间范围（毫秒）
      maxRecoveryOperations: 100, // 最大恢复操作数
      
      // 并发控制
      maxConcurrentOperations: 5, // 最大并发操作数
      operationTimeout: 10000, // 操作超时时间（毫秒）
      
      ...config
    };
    
    // 白名单管理
    this.whitelists = {
      ipAddresses: new Set(config.ipWhitelist || []),
      processes: new Set(config.processWhitelist || []),
      users: new Set(config.userWhitelist || []),
      applications: new Set(config.applicationWhitelist || [])
    };
    
    // 操作历史和状态
    this.interceptionHistory = [];
    this.activeInterceptions = new Map();
    this.pendingInterceptions = [];
    
    // 恢复队列
    this.recoveryQueue = [];
    this.activeOperations = 0;
    
    // 操作状态码
    this.operationStatus = {
      PENDING: 'pending',
      EXECUTING: 'executing',
      COMPLETED: 'completed',
      FAILED: 'failed',
      PARTIAL: 'partial',
      REVERSED: 'reversed'
    };
    
    // 初始化
    this.initialize();
  }

  // 初始化拦截管理器
  initialize() {
    try {
      // 尝试获取入侵检测器实例
      if (window.invasionDetector) {
        this.invasionDetector = window.invasionDetector;
        this.setupEventListeners();
      }
      
      // 设置定期清理
      setInterval(() => this.cleanupOldRecords(), 3600000); // 每小时清理一次
      
      // 设置定期检查恢复任务
      if (this.config.enableAutoRecovery) {
        setInterval(() => this.checkRecoveryQueue(), 60000); // 每分钟检查一次
      }
      
      // 注册到全局对象
      if (typeof window !== 'undefined' && !window.invasionInterceptionManager) {
        window.invasionInterceptionManager = this;
      }
      
      this.logger.info('入侵拦截管理器初始化完成');
      return true;
    } catch (error) {
      this.logger.error('初始化入侵拦截管理器失败:', error);
      return false;
    }
  }

  // 设置事件监听器
  setupEventListeners() {
    if (!this.invasionDetector) return;
    
    // 监听入侵检测事件
    this.invasionDetector.on('invasionDetected', (detectionResult) => {
      this.handleInvasionDetection(detectionResult);
    });
    
    // 监听分析完成事件
    this.invasionDetector.on('analysisComplete', (analysisResult) => {
      if (analysisResult.analysis?.isInvasion) {
        this.evaluateForInterception(analysisResult);
      }
    });
    
    // 监听告警事件
    this.invasionDetector.on('securityAlert', (alert) => {
      if (alert.severity === 'CRITICAL') {
        this.handleCriticalAlert(alert);
      }
    });
  }

  // 处理入侵检测结果
  async handleInvasionDetection(detectionResult) {
    try {
      this.logger.info('收到入侵检测结果，评估是否执行拦截');
      
      // 记录检测结果
      this.logDetection(detectionResult);
      
      // 评估是否需要拦截
      const shouldIntercept = this.shouldPerformInterception(detectionResult);
      
      if (shouldIntercept) {
        // 如果需要确认，则等待确认
        if (this.config.requireConfirmation) {
          this.pendingInterceptions.push(detectionResult);
          this.notifyInterceptionPending(detectionResult);
        } else {
          // 直接执行拦截
          await this.executeInterception(detectionResult);
        }
      }
    } catch (error) {
      this.logger.error('处理入侵检测结果失败:', error);
    }
  }

  // 评估是否执行拦截
  evaluateForInterception(analysisResult) {
    if (this.shouldPerformInterception(analysisResult)) {
      this.handleInvasionDetection(analysisResult);
    }
  }

  // 处理严重告警
  async handleCriticalAlert(alert) {
    try {
      this.logger.warn(`收到严重告警: ${alert.message}`);
      
      // 对于严重告警，可以执行紧急响应
      if (alert.requiresImmediateAction) {
        // 创建一个临时的检测结果对象用于拦截
        const emergencyDetection = {
          analysis: {
            isInvasion: true,
            riskLevel: 'CRITICAL',
            confidence: 0.85,
            invasionType: alert.alertType || '未知入侵',
            evidence: [alert.message]
          },
          detectedAt: new Date(),
          affectedSystems: alert.affectedSystems || [],
          emergencyAlert: true
        };
        
        // 紧急情况下可以覆盖正常拦截规则
        if (this.config.emergencyOverride || this.shouldPerformInterception(emergencyDetection)) {
          await this.executeInterception(emergencyDetection);
        }
      }
    } catch (error) {
      this.logger.error('处理严重告警失败:', error);
    }
  }

  // 判断是否应该执行拦截
  shouldPerformInterception(detectionResult) {
    // 检查自动拦截是否启用
    if (!this.config.autoIntercept && !detectionResult.emergencyAlert) {
      return false;
    }
    
    const { analysis } = detectionResult;
    
    // 检查是否确实检测到入侵
    if (!analysis?.isInvasion) {
      return false;
    }
    
    // 检查风险等级
    const riskLevelValue = this.getRiskLevelValue(analysis.riskLevel);
    const minRiskLevelValue = this.getRiskLevelValue(this.config.minimumRiskLevel);
    
    if (riskLevelValue < minRiskLevelValue) {
      return false;
    }
    
    // 检查置信度
    if (analysis.confidence < this.config.confidenceThreshold) {
      return false;
    }
    
    // 检查白名单
    if (this.isWhitelisted(detectionResult)) {
      return false;
    }
    
    return true;
  }

  // 获取风险等级数值
  getRiskLevelValue(riskLevel) {
    const levels = {
      'LOW': 1,
      'MEDIUM': 2,
      'HIGH': 3,
      'CRITICAL': 4
    };
    
    return levels[riskLevel?.toUpperCase()] || 0;
  }

  // 检查是否在白名单中
  isWhitelisted(detectionResult) {
    if (!this.config.whitelistEnabled) {
      return false;
    }
    
    // 检查IP地址白名单
    if (detectionResult.sourceIp && this.whitelists.ipAddresses.has(detectionResult.sourceIp)) {
      return true;
    }
    
    // 检查进程白名单
    if (detectionResult.affectedProcess && this.whitelists.processes.has(detectionResult.affectedProcess)) {
      return true;
    }
    
    // 检查用户白名单
    if (detectionResult.affectedUser && this.whitelists.users.has(detectionResult.affectedUser)) {
      return true;
    }
    
    // 检查应用程序白名单
    if (detectionResult.affectedApplication && this.whitelists.applications.has(detectionResult.affectedApplication)) {
      return true;
    }
    
    return false;
  }

  // 执行拦截操作
  async executeInterception(detectionResult) {
    try {
      // 检查并发操作限制
      if (this.activeOperations >= this.config.maxConcurrentOperations) {
        this.pendingInterceptions.push(detectionResult);
        this.logger.info('拦截操作已加入队列，等待执行');
        return { success: false, queued: true };
      }
      
      // 创建拦截操作ID
      const operationId = this.generateOperationId();
      
      // 记录开始执行
      this.activeOperations++;
      
      // 创建拦截操作记录
      const interceptionRecord = {
        id: operationId,
        timestamp: new Date(),
        detectionResult,
        status: this.operationStatus.EXECUTING,
        actions: [],
        results: {},
        recoveryInfo: null
      };
      
      // 添加到活动拦截列表
      this.activeInterceptions.set(operationId, interceptionRecord);
      
      try {
        // 执行各种拦截动作
        const actions = await this.performInterceptionActions(detectionResult, operationId);
        
        // 更新记录
        interceptionRecord.actions = actions;
        
        // 检查是否所有操作都成功
        const allSuccessful = actions.every(action => action.success);
        const anySuccessful = actions.some(action => action.success);
        
        if (allSuccessful) {
          interceptionRecord.status = this.operationStatus.COMPLETED;
        } else if (anySuccessful) {
          interceptionRecord.status = this.operationStatus.PARTIAL;
        } else {
          interceptionRecord.status = this.operationStatus.FAILED;
        }
        
        // 添加到历史记录
        this.interceptionHistory.push(interceptionRecord);
        
        // 如果配置了自动恢复，设置恢复任务
        if (this.config.enableAutoRecovery && anySuccessful) {
          this.scheduleRecovery(interceptionRecord);
        }
        
        // 发送通知
        this.notifyInterceptionComplete(interceptionRecord);
        
        return {
          success: anySuccessful,
          operationId,
          status: interceptionRecord.status,
          actions: interceptionRecord.actions
        };
      } finally {
        // 移除活动记录
        this.activeInterceptions.delete(operationId);
        this.activeOperations--;
        
        // 处理队列中的下一个拦截请求
        this.processPendingInterceptions();
      }
    } catch (error) {
      this.logger.error('执行拦截操作失败:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // 执行具体的拦截动作
  async performInterceptionActions(detectionResult, operationId) {
    const actions = [];
    const recoveryActions = [];
    
    try {
      const { analysis, affectedSystems, sourceIp, affectedProcess, affectedFiles } = detectionResult;
      
      // 1. 阻止IP地址
      if (this.config.blockIpAddresses && sourceIp && !this.whitelists.ipAddresses.has(sourceIp)) {
        const blockResult = await this.blockIpAddress(sourceIp, analysis);
        actions.push({ type: 'blockIp', target: sourceIp, success: blockResult.success });
        
        if (blockResult.success) {
          recoveryActions.push({ type: 'unblockIp', target: sourceIp, params: blockResult.recoveryInfo });
        }
      }
      
      // 2. 终止可疑进程
      if (this.config.terminateProcesses && affectedProcess) {
        const terminateResult = await this.terminateProcess(affectedProcess, analysis);
        actions.push({ type: 'terminateProcess', target: affectedProcess, success: terminateResult.success });
        
        if (terminateResult.success) {
          recoveryActions.push({ type: 'restartProcess', target: affectedProcess, params: terminateResult.recoveryInfo });
        }
      }
      
      // 3. 断开网络连接
      if (this.config.disconnectNetwork && analysis.riskLevel === 'CRITICAL') {
        const disconnectResult = await this.disconnectNetworkConnection(affectedSystems || []);
        actions.push({ type: 'disconnectNetwork', success: disconnectResult.success });
        
        if (disconnectResult.success) {
          recoveryActions.push({ type: 'restoreNetwork', params: disconnectResult.recoveryInfo });
        }
      }
      
      // 4. 隔离系统（仅在极高风险情况下）
      if (this.config.isolateSystem && analysis.riskLevel === 'CRITICAL' && analysis.confidence > 0.9) {
        const isolateResult = await this.isolateSystemFromNetwork();
        actions.push({ type: 'isolateSystem', success: isolateResult.success });
        
        if (isolateResult.success) {
          recoveryActions.push({ type: 'reintegrateSystem', params: isolateResult.recoveryInfo });
        }
      }
      
      // 5. 隔离可疑文件
      if (this.config.quarantineFiles && affectedFiles && affectedFiles.length > 0) {
        for (const file of affectedFiles) {
          const quarantineResult = await this.quarantineFile(file, analysis);
          actions.push({ type: 'quarantineFile', target: file, success: quarantineResult.success });
          
          if (quarantineResult.success) {
            recoveryActions.push({ type: 'restoreFile', target: file, params: quarantineResult.recoveryInfo });
          }
        }
      }
      
      // 保存恢复信息
      if (recoveryActions.length > 0 && this.config.enableAutoRecovery) {
        const record = this.activeInterceptions.get(operationId);
        if (record) {
          record.recoveryInfo = {
            actions: recoveryActions,
            scheduledTime: Date.now() + this.config.recoveryTimeframe
          };
        }
      }
      
      return actions;
    } catch (error) {
      this.logger.error('执行拦截动作失败:', error);
      return actions;
    }
  }

  // 阻止IP地址
  async blockIpAddress(ipAddress, analysis) {
    try {
      this.logger.info(`正在阻止恶意IP地址: ${ipAddress}`);
      
      // 在真实环境中，这里应该调用操作系统或防火墙API来阻止IP
      // 示例实现
      const blockId = `block_${ipAddress}_${Date.now()}`;
      
      // 模拟API调用
      await this.simulateOperation(100);
      
      // 记录到防火墙规则或安全策略
      this.logInterceptionAction('blockIp', ipAddress, analysis);
      
      return {
        success: true,
        recoveryInfo: { ipAddress, blockId }
      };
    } catch (error) {
      this.logger.error(`阻止IP地址 ${ipAddress} 失败:`, error);
      return { success: false, error: error.message };
    }
  }

  // 终止可疑进程
  async terminateProcess(processInfo, analysis) {
    try {
      const processName = processInfo.name || processInfo;
      const processId = processInfo.pid || null;
      
      this.logger.info(`正在终止可疑进程: ${processName}${processId ? ` (PID: ${processId})` : ''}`);
      
      // 在真实环境中，这里应该调用操作系统API终止进程
      // 示例实现
      const terminationId = `term_${processName}_${Date.now()}`;
      
      // 模拟API调用
      await this.simulateOperation(200);
      
      // 记录操作
      this.logInterceptionAction('terminateProcess', processName, analysis);
      
      return {
        success: true,
        recoveryInfo: { processName, processId, terminationId }
      };
    } catch (error) {
      this.logger.error(`终止进程失败:`, error);
      return { success: false, error: error.message };
    }
  }

  // 断开网络连接
  async disconnectNetworkConnection(affectedSystems = []) {
    try {
      this.logger.info(`正在断开受影响系统的网络连接: ${affectedSystems.join(', ') || '所有连接'}`);
      
      // 在真实环境中，这里应该调用网络管理API断开连接
      // 示例实现
      const disconnectId = `disconnect_${Date.now()}`;
      
      // 模拟API调用
      await this.simulateOperation(500);
      
      // 记录操作
      this.logInterceptionAction('disconnectNetwork', affectedSystems.join(', ') || 'all', {});
      
      return {
        success: true,
        recoveryInfo: { affectedSystems, disconnectId }
      };
    } catch (error) {
      this.logger.error(`断开网络连接失败:`, error);
      return { success: false, error: error.message };
    }
  }

  // 隔离系统
  async isolateSystemFromNetwork() {
    try {
      this.logger.warn(`正在执行系统隔离操作!`);
      
      // 在真实环境中，这里应该调用系统管理API进行网络隔离
      // 示例实现
      const isolateId = `isolate_${Date.now()}`;
      
      // 模拟API调用
      await this.simulateOperation(1000);
      
      // 记录操作
      this.logInterceptionAction('isolateSystem', 'entire system', {}, true);
      
      return {
        success: true,
        recoveryInfo: { isolateId }
      };
    } catch (error) {
      this.logger.error(`系统隔离失败:`, error);
      return { success: false, error: error.message };
    }
  }

  // 隔离可疑文件
  async quarantineFile(filePath, analysis) {
    try {
      this.logger.info(`正在隔离可疑文件: ${filePath}`);
      
      // 在真实环境中，这里应该调用文件系统API移动文件到隔离区
      // 示例实现
      const quarantinePath = `quarantine/${Date.now()}_${path.basename(filePath)}`;
      const quarantineId = `quarantine_${Date.now()}`;
      
      // 模拟API调用
      await this.simulateOperation(300);
      
      // 记录操作
      this.logInterceptionAction('quarantineFile', filePath, analysis);
      
      return {
        success: true,
        recoveryInfo: { originalPath: filePath, quarantinePath, quarantineId }
      };
    } catch (error) {
      this.logger.error(`隔离文件失败:`, error);
      return { success: false, error: error.message };
    }
  }

  // 恢复被拦截的操作
  async reverseInterception(operationId) {
    try {
      // 查找拦截记录
      const interceptionRecord = this.interceptionHistory.find(record => record.id === operationId);
      
      if (!interceptionRecord) {
        throw new Error(`找不到操作ID: ${operationId}`);
      }
      
      // 检查是否已经恢复
      if (interceptionRecord.status === this.operationStatus.REVERSED) {
        throw new Error(`操作 ${operationId} 已经被恢复`);
      }
      
      // 检查是否有恢复信息
      if (!interceptionRecord.recoveryInfo) {
        throw new Error(`操作 ${operationId} 没有可用的恢复信息`);
      }
      
      this.logger.info(`正在恢复拦截操作: ${operationId}`);
      
      // 执行恢复动作
      const recoveryResults = [];
      
      for (const recoveryAction of interceptionRecord.recoveryInfo.actions) {
        let result = { success: false };
        
        switch (recoveryAction.type) {
          case 'unblockIp':
            result = await this.unblockIpAddress(recoveryAction.target, recoveryAction.params);
            break;
          case 'restartProcess':
            result = await this.restartProcess(recoveryAction.target, recoveryAction.params);
            break;
          case 'restoreNetwork':
            result = await this.restoreNetworkConnection(recoveryAction.params);
            break;
          case 'reintegrateSystem':
            result = await this.reintegrateSystemToNetwork(recoveryAction.params);
            break;
          case 'restoreFile':
            result = await this.restoreFile(recoveryAction.target, recoveryAction.params);
            break;
        }
        
        recoveryResults.push({
          type: recoveryAction.type,
          target: recoveryAction.target,
          success: result.success
        });
      }
      
      // 更新记录状态
      const allSuccessful = recoveryResults.every(r => r.success);
      const anySuccessful = recoveryResults.some(r => r.success);
      
      if (allSuccessful) {
        interceptionRecord.status = this.operationStatus.REVERSED;
      } else {
        interceptionRecord.status = this.operationStatus.PARTIAL;
      }
      
      interceptionRecord.recoveryResults = recoveryResults;
      interceptionRecord.reversedAt = new Date();
      
      // 从恢复队列中移除
      this.recoveryQueue = this.recoveryQueue.filter(item => item.operationId !== operationId);
      
      // 发送通知
      this.notifyInterceptionReversed(interceptionRecord);
      
      return {
        success: anySuccessful,
        operationId,
        status: interceptionRecord.status,
        results: recoveryResults
      };
    } catch (error) {
      this.logger.error(`恢复拦截操作失败:`, error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // 解除IP阻止
  async unblockIpAddress(ipAddress, params) {
    try {
      this.logger.info(`正在解除IP地址阻止: ${ipAddress}`);
      
      // 在真实环境中，这里应该调用操作系统或防火墙API解除IP阻止
      // 模拟API调用
      await this.simulateOperation(100);
      
      return { success: true };
    } catch (error) {
      this.logger.error(`解除IP阻止失败:`, error);
      return { success: false, error: error.message };
    }
  }

  // 重启进程
  async restartProcess(processInfo, params) {
    try {
      const processName = processInfo.name || processInfo;
      this.logger.info(`正在重启进程: ${processName}`);
      
      // 在真实环境中，这里应该调用操作系统API重启进程
      // 模拟API调用
      await this.simulateOperation(300);
      
      return { success: true };
    } catch (error) {
      this.logger.error(`重启进程失败:`, error);
      return { success: false, error: error.message };
    }
  }

  // 恢复网络连接
  async restoreNetworkConnection(params) {
    try {
      this.logger.info(`正在恢复网络连接`);
      
      // 在真实环境中，这里应该调用网络管理API恢复连接
      // 模拟API调用
      await this.simulateOperation(500);
      
      return { success: true };
    } catch (error) {
      this.logger.error(`恢复网络连接失败:`, error);
      return { success: false, error: error.message };
    }
  }

  // 将系统重新集成到网络
  async reintegrateSystemToNetwork(params) {
    try {
      this.logger.info(`正在将系统重新集成到网络`);
      
      // 在真实环境中，这里应该调用系统管理API恢复网络连接
      // 模拟API调用
      await this.simulateOperation(1000);
      
      return { success: true };
    } catch (error) {
      this.logger.error(`系统重新集成到网络失败:`, error);
      return { success: false, error: error.message };
    }
  }

  // 恢复被隔离的文件
  async restoreFile(filePath, params) {
    try {
      this.logger.info(`正在恢复被隔离的文件: ${filePath}`);
      
      // 在真实环境中，这里应该调用文件系统API将文件从隔离区移回
      // 模拟API调用
      await this.simulateOperation(300);
      
      return { success: true };
    } catch (error) {
      this.logger.error(`恢复文件失败:`, error);
      return { success: false, error: error.message };
    }
  }

  // 安排自动恢复
  scheduleRecovery(interceptionRecord) {
    if (!interceptionRecord.recoveryInfo) return;
    
    const recoveryItem = {
      operationId: interceptionRecord.id,
      scheduledTime: interceptionRecord.recoveryInfo.scheduledTime,
      timestamp: new Date()
    };
    
    this.recoveryQueue.push(recoveryItem);
    
    // 限制恢复队列大小
    if (this.recoveryQueue.length > this.config.maxRecoveryOperations) {
      this.recoveryQueue.shift();
    }
  }

  // 检查恢复队列
  async checkRecoveryQueue() {
    const now = Date.now();
    const itemsToRecover = this.recoveryQueue.filter(item => item.scheduledTime <= now);
    
    for (const item of itemsToRecover) {
      try {
        await this.reverseInterception(item.operationId);
      } catch (error) {
        this.logger.error(`自动恢复操作失败:`, error);
      }
    }
  }

  // 处理待处理的拦截请求
  async processPendingInterceptions() {
    if (this.pendingInterceptions.length === 0 || this.activeOperations >= this.config.maxConcurrentOperations) {
      return;
    }
    
    const nextInterception = this.pendingInterceptions.shift();
    if (nextInterception) {
      await this.executeInterception(nextInterception);
    }
  }

  // 确认待处理的拦截请求
  async confirmInterception(operationId) {
    const pendingIndex = this.pendingInterceptions.findIndex(item => 
      item.operationId === operationId || item.id === operationId
    );
    
    if (pendingIndex === -1) {
      return { success: false, error: '未找到待确认的拦截请求' };
    }
    
    const interception = this.pendingInterceptions[pendingIndex];
    this.pendingInterceptions.splice(pendingIndex, 1);
    
    return await this.executeInterception(interception);
  }

  // 取消待处理的拦截请求
  cancelInterception(operationId) {
    const pendingIndex = this.pendingInterceptions.findIndex(item => 
      item.operationId === operationId || item.id === operationId
    );
    
    if (pendingIndex === -1) {
      return { success: false, error: '未找到待取消的拦截请求' };
    }
    
    this.pendingInterceptions.splice(pendingIndex, 1);
    
    return { success: true };
  }

  // 日志记录函数
  logDetection(detectionResult) {
    if (!this.config.logInterceptions) return;
    
    this.logger.info('检测到潜在入侵:', {
      riskLevel: detectionResult.analysis?.riskLevel,
      confidence: detectionResult.analysis?.confidence,
      type: detectionResult.analysis?.invasionType,
      sourceIp: detectionResult.sourceIp,
      affectedSystems: detectionResult.affectedSystems
    });
  }

  // 记录拦截动作
  logInterceptionAction(actionType, target, analysis, isCritical = false) {
    if (!this.config.logInterceptions) return;
    
    const logLevel = isCritical ? 'warn' : 'info';
    
    this.logger[logLevel]('执行拦截动作:', {
      actionType,
      target,
      riskLevel: analysis?.riskLevel,
      invasionType: analysis?.invasionType,
      timestamp: new Date()
    });
  }

  // 通知函数
  notifyInterceptionPending(detectionResult) {
    // 在真实环境中，这里应该发送通知到UI或管理员
    if (this.config.alertOnInterception) {
      this.logger.info('拦截请求等待确认:', {
        riskLevel: detectionResult.analysis?.riskLevel,
        type: detectionResult.analysis?.invasionType
      });
    }
  }

  notifyInterceptionComplete(interceptionRecord) {
    // 在真实环境中，这里应该发送通知到UI或管理员
    if (this.config.alertOnInterception) {
      this.logger.info('拦截操作完成:', {
        operationId: interceptionRecord.id,
        status: interceptionRecord.status,
        actions: interceptionRecord.actions.filter(a => a.success).length
      });
    }
    
    // 如果配置了管理员通知
    if (this.config.notifyAdmin && interceptionRecord.status === this.operationStatus.COMPLETED) {
      this.notifyAdministrator(interceptionRecord);
    }
  }

  notifyInterceptionReversed(interceptionRecord) {
    // 在真实环境中，这里应该发送通知到UI或管理员
    this.logger.info('拦截操作已恢复:', {
      operationId: interceptionRecord.id,
      originalActions: interceptionRecord.actions.length,
      reversedActions: interceptionRecord.recoveryResults?.filter(r => r.success).length || 0
    });
  }

  // 通知管理员
  notifyAdministrator(interceptionRecord) {
    // 在真实环境中，这里应该通过邮件、短信或其他渠道通知管理员
    this.logger.warn('发送管理员通知:', {
      operationId: interceptionRecord.id,
      riskLevel: interceptionRecord.detectionResult.analysis?.riskLevel,
      actions: interceptionRecord.actions.map(a => `${a.type}:${a.success ? '成功' : '失败'}`).join(', ')
    });
  }

  // 生成操作ID
  generateOperationId() {
    return `intercept_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // 模拟操作延迟
  simulateOperation(delayMs) {
    return new Promise(resolve => setTimeout(resolve, delayMs));
  }

  // 白名单管理
  addToWhitelist(type, item) {
    if (!this.whitelists[type]) {
      throw new Error(`无效的白名单类型: ${type}`);
    }
    
    this.whitelists[type].add(item);
    return true;
  }

  removeFromWhitelist(type, item) {
    if (!this.whitelists[type]) {
      throw new Error(`无效的白名单类型: ${type}`);
    }
    
    return this.whitelists[type].delete(item);
  }

  isInWhitelist(type, item) {
    if (!this.whitelists[type]) {
      throw new Error(`无效的白名单类型: ${type}`);
    }
    
    return this.whitelists[type].has(item);
  }

  getWhitelist(type) {
    if (!this.whitelists[type]) {
      throw new Error(`无效的白名单类型: ${type}`);
    }
    
    return Array.from(this.whitelists[type]);
  }

  clearWhitelist(type) {
    if (!this.whitelists[type]) {
      throw new Error(`无效的白名单类型: ${type}`);
    }
    
    this.whitelists[type].clear();
    return true;
  }

  // 配置管理
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    return this.config;
  }

  getConfig() {
    return { ...this.config };
  }

  // 状态和历史管理
  getInterceptionHistory(limit = 50) {
    return this.interceptionHistory.slice(-limit).reverse();
  }

  getActiveInterceptions() {
    return Array.from(this.activeInterceptions.values());
  }

  getPendingInterceptions() {
    return [...this.pendingInterceptions];
  }

  getRecoveryQueue() {
    return [...this.recoveryQueue];
  }

  getStatistics() {
    const totalInterceptions = this.interceptionHistory.length;
    const completed = this.interceptionHistory.filter(r => r.status === this.operationStatus.COMPLETED).length;
    const failed = this.interceptionHistory.filter(r => r.status === this.operationStatus.FAILED).length;
    const partial = this.interceptionHistory.filter(r => r.status === this.operationStatus.PARTIAL).length;
    const reversed = this.interceptionHistory.filter(r => r.status === this.operationStatus.REVERSED).length;
    
    return {
      totalInterceptions,
      completed,
      failed,
      partial,
      reversed,
      activeInterceptions: this.activeInterceptions.size,
      pendingInterceptions: this.pendingInterceptions.length,
      recoveryQueueSize: this.recoveryQueue.length
    };
  }

  // 清理旧记录
  cleanupOldRecords() {
    const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000); // 7天前
    
    // 清理历史记录
    const oldLength = this.interceptionHistory.length;
    this.interceptionHistory = this.interceptionHistory.filter(
      record => record.timestamp.getTime() > oneWeekAgo
    );
    
    const cleanedCount = oldLength - this.interceptionHistory.length;
    if (cleanedCount > 0) {
      this.logger.info(`清理了 ${cleanedCount} 条旧拦截记录`);
    }
  }

  // 重置状态
  resetState() {
    this.interceptionHistory = [];
    this.activeInterceptions.clear();
    this.pendingInterceptions = [];
    this.recoveryQueue = [];
    
    return true;
  }

  // 关闭管理器
  shutdown() {
    // 清空队列
    this.pendingInterceptions = [];
    this.recoveryQueue = [];
    
    // 清理全局引用
    if (window.invasionInterceptionManager === this) {
      delete window.invasionInterceptionManager;
    }
    
    this.logger.info('入侵拦截管理器已关闭');
    return true;
  }

  // 连接到入侵检测器
  connectToInvasionDetector(detectorInstance) {
    this.invasionDetector = detectorInstance;
    this.setupEventListeners();
    
    return true;
  }

  // 紧急禁用所有拦截
  emergencyDisableInterception() {
    this.config.autoIntercept = false;
    this.pendingInterceptions = [];
    
    this.logger.warn('紧急禁用所有拦截操作');
    return true;
  }

  // 紧急启用所有拦截
  emergencyEnableInterception() {
    this.config.autoIntercept = true;
    
    // 立即处理所有待处理的拦截请求
    const pending = [...this.pendingInterceptions];
    this.pendingInterceptions = [];
    
    pending.forEach(async (interception) => {
      await this.executeInterception(interception);
    });
    
    this.logger.warn('紧急启用所有拦截操作');
    return true;
  }
}

export default InvasionInterceptionManager;

// 创建默认实例
let defaultManager = null;

export function getInvasionInterceptionManager() {
  if (!defaultManager) {
    defaultManager = new InvasionInterceptionManager();
  }
  return defaultManager;
}