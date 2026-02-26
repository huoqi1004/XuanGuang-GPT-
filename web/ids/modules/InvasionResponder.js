// 入侵响应器模块 - 负责根据分析结果执行响应措施
class InvasionResponder {
  constructor(config = {}) {
    this.logger = window.globalLogger || console;
    this.config = {
      automaticResponse: true,
      responseRules: [],
      quarantineEnabled: true,
      maxBlockEntries: 1000,
      blockDuration: 86400000, // 默认阻止24小时
      notificationEnabled: true,
      ...config
    };
    
    // 阻止列表存储
    this.blockedIps = new Map();
    this.blockedProcesses = new Map();
    this.blockedUsers = new Map();
    
    // 响应历史
    this.responseHistory = [];
    
    // 加载配置的响应规则
    this.loadResponseRules();
    
    // 初始化系统资源访问
    this.system = this.initSystemAccess();
  }

  // 初始化系统访问接口
  initSystemAccess() {
    // 这里提供与系统交互的API抽象层
    // 在实际实现中，这将与系统级API或底层库交互
    return {
      // 网络操作
      network: {
        blockIp: this._blockIp.bind(this),
        blockPort: this._blockPort.bind(this),
        disconnectConnection: this._disconnectConnection.bind(this),
        getActiveConnections: this._getActiveConnections.bind(this)
      },
      
      // 进程操作
      process: {
        terminate: this._terminateProcess.bind(this),
        suspend: this._suspendProcess.bind(this),
        monitor: this._monitorProcess.bind(this),
        getDetails: this._getProcessDetails.bind(this)
      },
      
      // 文件操作
      file: {
        quarantine: this._quarantineFile.bind(this),
        delete: this._deleteFile.bind(this),
        getDetails: this._getFileDetails.bind(this)
      },
      
      // 用户操作
      user: {
        disable: this._disableUser.bind(this),
        lockAccount: this._lockUserAccount.bind(this),
        logoff: this._logoffUser.bind(this)
      },
      
      // 系统操作
      system: {
        isolate: this._isolateSystem.bind(this),
        restore: this._restoreSystem.bind(this),
        createBackup: this._createBackup.bind(this),
        updateSecuritySettings: this._updateSecuritySettings.bind(this)
      }
    };
  }

  // 主响应方法
  async respond(analysisResult) {
    try {
      if (!analysisResult || !analysisResult.isInvasion) {
        this.logger.info('未检测到入侵行为，无需响应');
        return { success: true, actions: [] };
      }

      this.logger.info(`检测到入侵行为，风险等级: ${analysisResult.riskLevel}, 入侵类型: ${analysisResult.invasionType}`);
      
      // 根据风险等级和入侵类型选择响应策略
      const responseActions = await this.determineResponseActions(analysisResult);
      
      // 执行响应措施
      const executedActions = [];
      for (const action of responseActions) {
        if (this.config.automaticResponse || action.force) {
          const result = await this.executeAction(action, analysisResult);
          if (result.success) {
            executedActions.push(result);
          }
        }
      }

      // 记录响应历史
      this.recordResponse(analysisResult, executedActions);
      
      // 发送通知
      if (this.config.notificationEnabled) {
        await this.sendNotification(analysisResult, executedActions);
      }

      return {
        success: true,
        actions: executedActions,
        summary: this.generateResponseSummary(analysisResult, executedActions)
      };
    } catch (error) {
      this.logger.error('执行入侵响应失败:', error);
      return { success: false, error: error.message };
    }
  }

  // 确定响应措施
  async determineResponseActions(analysisResult) {
    const actions = [];
    const riskLevel = analysisResult.riskLevel;
    const invasionType = analysisResult.invasionType;
    const details = analysisResult.details || {};

    // 根据风险等级应用默认响应
    switch (riskLevel) {
      case 'CRITICAL':
        // 严重风险响应
        actions.push(
          { type: 'ISOLATE_SYSTEM', priority: 1, force: true },
          { type: 'CREATE_BACKUP', priority: 2 },
          { type: 'BLOCK_SUSPICIOUS_IPS', priority: 3 },
          { type: 'TERMINATE_MALICIOUS_PROCESSES', priority: 4 },
          { type: 'QUARANTINE_FILES', priority: 5 },
          { type: 'LOCK_COMPROMISED_USERS', priority: 6 }
        );
        break;
        
      case 'HIGH':
        // 高风险响应
        actions.push(
          { type: 'BLOCK_SUSPICIOUS_IPS', priority: 1 },
          { type: 'TERMINATE_MALICIOUS_PROCESSES', priority: 2 },
          { type: 'QUARANTINE_FILES', priority: 3 },
          { type: 'MONITOR_SYSTEM', priority: 4 }
        );
        break;
        
      case 'MEDIUM':
        // 中等风险响应
        actions.push(
          { type: 'BLOCK_SUSPICIOUS_IPS', priority: 1 },
          { type: 'TERMINATE_SUSPICIOUS_PROCESSES', priority: 2 },
          { type: 'MONITOR_SYSTEM', priority: 3 }
        );
        break;
        
      case 'LOW':
        // 低风险响应
        actions.push(
          { type: 'MONITOR_SUSPICIOUS_IPS', priority: 1 },
          { type: 'MONITOR_SUSPICIOUS_PROCESSES', priority: 2 },
          { type: 'UPDATE_LOG_LEVEL', priority: 3 }
        );
        break;
    }

    // 根据入侵类型添加特定响应
    this.addTypeSpecificResponses(actions, invasionType, details);

    // 应用自定义规则响应
    this.applyCustomRules(actions, analysisResult);

    // 根据分析结果中的具体细节添加更多响应
    if (details.llmAnalysis?.recommendations) {
      this.addLlmRecommendedActions(actions, details.llmAnalysis.recommendations);
    }

    // 按优先级排序
    return actions.sort((a, b) => a.priority - b.priority);
  }

  // 添加基于入侵类型的特定响应
  addTypeSpecificResponses(actions, invasionType, details) {
    const typeLower = invasionType.toLowerCase();
    
    // SSH暴力破解
    if (typeLower.includes('ssh') && typeLower.includes('brute')) {
      actions.push(
        { type: 'BLOCK_SUSPICIOUS_IPS', priority: 1, force: true },
        { type: 'TEMPORARILY_DISABLE_SSH', priority: 2 }
      );
    }
    
    // 权限提升
    else if (typeLower.includes('privilege') || typeLower.includes('elevation')) {
      actions.push(
        { type: 'TERMINATE_COMPROMISED_PROCESSES', priority: 1 },
        { type: 'REVOKE_EXCESSIVE_PRIVILEGES', priority: 2 },
        { type: 'AUDIT_USER_PERMISSIONS', priority: 3 }
      );
    }
    
    // 数据泄露
    else if (typeLower.includes('data') || typeLower.includes('exfiltration')) {
      actions.push(
        { type: 'BLOCK_DATA_TRANSFER', priority: 1, force: true },
        { type: 'ISOLATE_SYSTEM', priority: 2 },
        { type: 'PRESERVE_EVIDENCE', priority: 3 }
      );
    }
    
    // 恶意软件
    else if (typeLower.includes('malware') || typeLower.includes('virus')) {
      actions.push(
        { type: 'SCAN_ALL_FILES', priority: 1 },
        { type: 'REMOVE_MALWARE', priority: 2 },
        { type: 'RESTORE_SYSTEM_FILES', priority: 3 }
      );
    }
    
    // 横向移动
    else if (typeLower.includes('lateral') || typeLower.includes('movement')) {
      actions.push(
        { type: 'ISOLATE_SYSTEM', priority: 1, force: true },
        { type: 'BLOCK_INTERNAL_COMMUNICATION', priority: 2 },
        { type: 'AUDIT_AUTHENTICATION_LOGS', priority: 3 }
      );
    }
  }

  // 应用自定义响应规则
  applyCustomRules(actions, analysisResult) {
    for (const rule of this.config.responseRules) {
      try {
        if (this.evaluateRule(rule, analysisResult)) {
          // 添加规则指定的操作
          rule.actions.forEach(action => {
            // 确保不添加重复的高优先级操作
            const existingActionIndex = actions.findIndex(a => a.type === action.type);
            if (existingActionIndex === -1 || 
                (action.priority !== undefined && 
                 actions[existingActionIndex].priority > action.priority)) {
              
              if (existingActionIndex !== -1) {
                actions.splice(existingActionIndex, 1);
              }
              actions.push(action);
            }
          });
        }
      } catch (error) {
        this.logger.error(`评估响应规则失败: ${rule.name}`, error);
      }
    }
  }

  // 评估响应规则
  evaluateRule(rule, analysisResult) {
    if (rule.condition) {
      // 支持风险等级条件
      if (rule.condition.riskLevel && 
          !Array.isArray(rule.condition.riskLevel) && 
          rule.condition.riskLevel !== analysisResult.riskLevel) {
        return false;
      }
      
      // 支持风险等级数组条件
      if (Array.isArray(rule.condition.riskLevel) && 
          !rule.condition.riskLevel.includes(analysisResult.riskLevel)) {
        return false;
      }
      
      // 支持入侵类型条件
      if (rule.condition.invasionType && 
          !analysisResult.invasionType.toLowerCase().includes(
            rule.condition.invasionType.toLowerCase()
          )) {
        return false;
      }
      
      // 支持置信度条件
      if (rule.condition.minConfidence !== undefined && 
          analysisResult.confidence < rule.condition.minConfidence) {
        return false;
      }
      
      // 支持特征匹配条件
      if (rule.condition.requiredFeatures && 
          Array.isArray(rule.condition.requiredFeatures)) {
        const hasAllFeatures = rule.condition.requiredFeatures.every(feature => {
          return analysisResult.details.keyFeatures?.some(kf => 
            kf.type.toLowerCase().includes(feature.toLowerCase())
          );
        });
        
        if (!hasAllFeatures) return false;
      }
    }
    
    return true;
  }

  // 添加大模型推荐的操作
  addLlmRecommendedActions(actions, recommendations) {
    // 将自然语言推荐转换为具体操作
    const recommendationMap = {
      '隔离': 'ISOLATE_SYSTEM',
      '阻止': 'BLOCK_SUSPICIOUS_IPS',
      '终止': 'TERMINATE_MALICIOUS_PROCESSES',
      '监控': 'MONITOR_SYSTEM',
      '检查': 'AUDIT_SYSTEM_ACTIVITY',
      '锁定': 'LOCK_COMPROMISED_USERS',
      '备份': 'CREATE_BACKUP'
    };
    
    recommendations.forEach(rec => {
      for (const [keyword, actionType] of Object.entries(recommendationMap)) {
        if (rec.includes(keyword) && !actions.some(a => a.type === actionType)) {
          actions.push({
            type: actionType,
            priority: 5, // 默认中等优先级
            source: 'llm_recommendation',
            details: rec
          });
          break;
        }
      }
    });
  }

  // 执行单个响应操作
  async executeAction(action, analysisResult) {
    try {
      this.logger.info(`执行响应操作: ${action.type}`);
      
      let result;
      switch (action.type) {
        case 'ISOLATE_SYSTEM':
          result = await this.system.system.isolate(action);
          break;
        case 'CREATE_BACKUP':
          result = await this.system.system.createBackup(action);
          break;
        case 'BLOCK_SUSPICIOUS_IPS':
          result = await this.blockSuspiciousIps(action, analysisResult);
          break;
        case 'TERMINATE_MALICIOUS_PROCESSES':
          result = await this.terminateMaliciousProcesses(action, analysisResult);
          break;
        case 'TERMINATE_SUSPICIOUS_PROCESSES':
          result = await this.terminateSuspiciousProcesses(action, analysisResult);
          break;
        case 'QUARANTINE_FILES':
          result = await this.quarantineSuspiciousFiles(action, analysisResult);
          break;
        case 'LOCK_COMPROMISED_USERS':
          result = await this.lockCompromisedUsers(action, analysisResult);
          break;
        case 'MONITOR_SYSTEM':
          result = await this.startSystemMonitoring(action);
          break;
        case 'UPDATE_LOG_LEVEL':
          result = await this.updateLogLevel(action);
          break;
        case 'TEMPORARILY_DISABLE_SSH':
          result = await this.temporarilyDisableService(action, 'ssh');
          break;
        case 'BLOCK_DATA_TRANSFER':
          result = await this.blockDataTransfer(action);
          break;
        case 'PRESERVE_EVIDENCE':
          result = await this.preserveEvidence(action);
          break;
        case 'SCAN_ALL_FILES':
          result = await this.scanAllFiles(action);
          break;
        default:
          this.logger.warn(`未知的响应操作类型: ${action.type}`);
          result = { success: false, error: 'Unknown action type' };
      }
      
      return {
        actionType: action.type,
        success: result.success,
        details: result.details || {},
        timestamp: new Date(),
        source: action.source || 'system'
      };
    } catch (error) {
      this.logger.error(`执行操作 ${action.type} 失败:`, error);
      return {
        actionType: action.type,
        success: false,
        error: error.message,
        timestamp: new Date()
      };
    }
  }

  // 阻止可疑IP地址
  async blockSuspiciousIps(action, analysisResult) {
    const blockedIps = [];
    const details = analysisResult.details || {};
    
    // 从分析结果中提取可疑IP
    const suspiciousIps = new Set();
    
    // 从异常检测结果中获取IP
    if (Array.isArray(details.anomalies)) {
      details.anomalies.forEach(anomaly => {
        if (anomaly.sourceIp) suspiciousIps.add(anomaly.sourceIp);
        if (anomaly.ipAddress) suspiciousIps.add(anomaly.ipAddress);
      });
    }
    
    // 从规则匹配结果中获取IP
    if (Array.isArray(details.ruleMatches)) {
      details.ruleMatches.forEach(match => {
        if (match.evidence.sourceIp) suspiciousIps.add(match.evidence.sourceIp);
        if (match.evidence.ipAddress) suspiciousIps.add(match.evidence.ipAddress);
      });
    }
    
    // 从大模型分析结果中获取IP
    if (details.llmAnalysis?.details) {
      const ipMatches = details.llmAnalysis.details.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) || [];
      ipMatches.forEach(ip => suspiciousIps.add(ip));
    }
    
    // 执行阻止操作
    for (const ip of suspiciousIps) {
      try {
        await this.system.network.blockIp(ip, this.config.blockDuration);
        this.blockedIps.set(ip, {
          blockedAt: new Date(),
          duration: this.config.blockDuration,
          reason: 'Suspicious activity detected'
        });
        blockedIps.push(ip);
      } catch (error) {
        this.logger.error(`阻止IP ${ip} 失败:`, error);
      }
    }
    
    return {
      success: blockedIps.length > 0,
      details: {
        blockedIps,
        totalBlocked: blockedIps.length
      }
    };
  }

  // 终止恶意进程
  async terminateMaliciousProcesses(action, analysisResult) {
    const terminatedProcesses = [];
    const details = analysisResult.details || {};
    
    // 从分析结果中提取恶意进程
    const maliciousProcesses = new Set();
    
    // 从关键特征中提取可疑进程
    if (Array.isArray(details.keyFeatures)) {
      details.keyFeatures.forEach(feature => {
        if (feature.type === 'suspicious_process' && feature.value) {
          maliciousProcesses.add(feature.value);
        }
      });
    }
    
    // 从大模型分析结果中提取进程信息
    if (details.llmAnalysis?.details) {
      // 简单的模式匹配来提取进程名
      const processPattern = /process[:\s]+([\w\.-]+)/gi;
      let match;
      while ((match = processPattern.exec(details.llmAnalysis.details)) !== null) {
        if (match[1]) maliciousProcesses.add(match[1]);
      }
    }
    
    // 执行终止操作
    for (const processName of maliciousProcesses) {
      try {
        const result = await this.system.process.terminate(processName);
        if (result.success) {
          terminatedProcesses.push(processName);
          this.blockedProcesses.set(processName, {
            terminatedAt: new Date(),
            reason: 'Malicious activity detected'
          });
        }
      } catch (error) {
        this.logger.error(`终止进程 ${processName} 失败:`, error);
      }
    }
    
    return {
      success: terminatedProcesses.length > 0,
      details: {
        terminatedProcesses,
        totalTerminated: terminatedProcesses.length
      }
    };
  }

  // 终止可疑进程
  async terminateSuspiciousProcesses(action, analysisResult) {
    // 与终止恶意进程类似，但针对较低风险的进程
    // 这里简化为调用相同的方法
    return await this.terminateMaliciousProcesses(action, analysisResult);
  }

  // 隔离可疑文件
  async quarantineSuspiciousFiles(action, analysisResult) {
    const quarantinedFiles = [];
    const details = analysisResult.details || {};
    
    // 从分析结果中提取可疑文件
    const suspiciousFiles = new Set();
    
    // 从关键特征中提取可疑文件
    if (Array.isArray(details.keyFeatures)) {
      details.keyFeatures.forEach(feature => {
        if (feature.type === 'malicious_file' && feature.value) {
          suspiciousFiles.add(feature.value);
        }
      });
    }
    
    // 执行隔离操作
    for (const filePath of suspiciousFiles) {
      try {
        if (this.config.quarantineEnabled) {
          await this.system.file.quarantine(filePath);
          quarantinedFiles.push(filePath);
        }
      } catch (error) {
        this.logger.error(`隔离文件 ${filePath} 失败:`, error);
      }
    }
    
    return {
      success: quarantinedFiles.length > 0,
      details: {
        quarantinedFiles,
        totalQuarantined: quarantinedFiles.length
      }
    };
  }

  // 锁定被入侵的用户账户
  async lockCompromisedUsers(action, analysisResult) {
    const lockedUsers = [];
    const details = analysisResult.details || {};
    
    // 从分析结果中提取可疑用户
    const compromisedUsers = new Set();
    
    // 从关键特征中提取可疑用户活动
    if (Array.isArray(details.keyFeatures)) {
      details.keyFeatures.forEach(feature => {
        if (feature.details && feature.details.includes('用户: ')) {
          const userMatch = feature.details.match(/用户: ([^,]+)/);
          if (userMatch && userMatch[1]) {
            compromisedUsers.add(userMatch[1].trim());
          }
        }
      });
    }
    
    // 执行锁定操作
    for (const username of compromisedUsers) {
      try {
        await this.system.user.lockAccount(username);
        lockedUsers.push(username);
        this.blockedUsers.set(username, {
          lockedAt: new Date(),
          reason: 'Compromised account detected'
        });
      } catch (error) {
        this.logger.error(`锁定用户 ${username} 失败:`, error);
      }
    }
    
    return {
      success: lockedUsers.length > 0,
      details: {
        lockedUsers,
        totalLocked: lockedUsers.length
      }
    };
  }

  // 启动系统监控
  async startSystemMonitoring(action) {
    try {
      // 在实际实现中，这里会启动增强的系统监控
      this.logger.info('启动增强系统监控');
      
      // 模拟启动监控
      return { success: true, details: { message: 'Enhanced monitoring started' } };
    } catch (error) {
      this.logger.error('启动系统监控失败:', error);
      return { success: false, error: error.message };
    }
  }

  // 更新日志级别
  async updateLogLevel(action) {
    try {
      // 在实际实现中，这里会增加日志记录的详细程度
      this.logger.info('增加日志记录级别');
      return { success: true, details: { message: 'Log level increased' } };
    } catch (error) {
      this.logger.error('更新日志级别失败:', error);
      return { success: false, error: error.message };
    }
  }

  // 临时禁用服务
  async temporarilyDisableService(action, serviceName) {
    try {
      this.logger.info(`临时禁用服务: ${serviceName}`);
      // 模拟禁用服务
      return { success: true, details: { service: serviceName, action: 'disabled temporarily' } };
    } catch (error) {
      this.logger.error(`禁用服务 ${serviceName} 失败:`, error);
      return { success: false, error: error.message };
    }
  }

  // 阻止数据传输
  async blockDataTransfer(action) {
    try {
      this.logger.info('阻止可疑数据传输');
      // 模拟阻止数据传输
      return { success: true, details: { action: 'data transfer blocked' } };
    } catch (error) {
      this.logger.error('阻止数据传输失败:', error);
      return { success: false, error: error.message };
    }
  }

  // 保存证据
  async preserveEvidence(action) {
    try {
      this.logger.info('保存入侵证据');
      // 模拟保存证据
      return { success: true, details: { action: 'evidence preserved' } };
    } catch (error) {
      this.logger.error('保存证据失败:', error);
      return { success: false, error: error.message };
    }
  }

  // 扫描所有文件
  async scanAllFiles(action) {
    try {
      this.logger.info('执行全面文件扫描');
      // 模拟扫描文件
      return { success: true, details: { action: 'full file scan initiated' } };
    } catch (error) {
      this.logger.error('执行文件扫描失败:', error);
      return { success: false, error: error.message };
    }
  }

  // 加载响应规则
  loadResponseRules() {
    // 默认响应规则
    this.config.responseRules = [
      {
        name: 'SSH暴力破解响应',
        condition: {
          riskLevel: ['HIGH', 'CRITICAL'],
          invasionType: 'SSH'
        },
        actions: [
          { type: 'BLOCK_SUSPICIOUS_IPS', priority: 1, force: true },
          { type: 'TEMPORARILY_DISABLE_SSH', priority: 2 }
        ]
      },
      {
        name: '恶意软件响应',
        condition: {
          riskLevel: ['HIGH', 'CRITICAL'],
          invasionType: 'malware',
          minConfidence: 0.7
        },
        actions: [
          { type: 'TERMINATE_MALICIOUS_PROCESSES', priority: 1 },
          { type: 'QUARANTINE_FILES', priority: 2 },
          { type: 'SCAN_ALL_FILES', priority: 3 }
        ]
      },
      {
        name: '数据泄露响应',
        condition: {
          riskLevel: ['CRITICAL'],
          requiredFeatures: ['data_exfiltration']
        },
        actions: [
          { type: 'ISOLATE_SYSTEM', priority: 1, force: true },
          { type: 'BLOCK_DATA_TRANSFER', priority: 2 }
        ]
      }
    ];
  }

  // 记录响应历史
  recordResponse(analysisResult, executedActions) {
    const responseRecord = {
      timestamp: new Date(),
      analysisId: analysisResult.timestamp || new Date(),
      riskLevel: analysisResult.riskLevel,
      invasionType: analysisResult.invasionType,
      confidence: analysisResult.confidence,
      actions: executedActions,
      totalActions: executedActions.length,
      successfulActions: executedActions.filter(a => a.success).length
    };
    
    this.responseHistory.push(responseRecord);
    
    // 限制历史记录大小
    if (this.responseHistory.length > 100) {
      this.responseHistory.shift();
    }
    
    this.logger.info(`响应记录已保存: ${responseRecord.successfulActions}/${responseRecord.totalActions} 操作成功执行`);
  }

  // 发送通知
  async sendNotification(analysisResult, executedActions) {
    try {
      const notification = {
        type: 'invasion_detected',
        title: `检测到入侵行为 - 风险等级: ${analysisResult.riskLevel}`,
        message: `检测到类型为"${analysisResult.invasionType}"的入侵行为。已执行 ${executedActions.length} 项响应措施。`,
        timestamp: new Date(),
        riskLevel: analysisResult.riskLevel,
        details: {
          confidence: analysisResult.confidence,
          actions: executedActions.map(a => a.actionType)
        }
      };
      
      // 在实际实现中，这里会调用通知系统
      this.logger.info('发送入侵检测通知:', notification);
      
      // 如果系统中有通知中心，调用它
      if (window.NotificationCenter) {
        await window.NotificationCenter.send(notification);
      }
      
      return true;
    } catch (error) {
      this.logger.error('发送通知失败:', error);
      return false;
    }
  }

  // 生成响应摘要
  generateResponseSummary(analysisResult, executedActions) {
    const successfulActions = executedActions.filter(a => a.success);
    
    return {
      summary: `针对${analysisResult.invasionType}类型的${analysisResult.riskLevel}风险入侵，已执行${successfulActions.length}项响应措施。`,
      actionBreakdown: this.getActionBreakdown(successfulActions),
      recommendation: this.generateFollowUpRecommendation(analysisResult)
    };
  }

  // 获取操作分类统计
  getActionBreakdown(actions) {
    const breakdown = {};
    
    actions.forEach(action => {
      if (!breakdown[action.actionType]) {
        breakdown[action.actionType] = 0;
      }
      breakdown[action.actionType]++;
    });
    
    return breakdown;
  }

  // 生成后续建议
  generateFollowUpRecommendation(analysisResult) {
    switch (analysisResult.riskLevel) {
      case 'CRITICAL':
        return '建议立即进行全面安全审计，评估系统受损程度，并考虑从备份恢复系统。';
      case 'HIGH':
        return '建议对受影响的系统进行深度扫描，检查是否有持久化后门，并加强监控。';
      case 'MEDIUM':
        return '建议检查相关日志文件，确认是否为误报，并更新安全规则以提高准确性。';
      case 'LOW':
        return '建议继续监控相关活动，确认是否为正常操作的异常模式。';
      default:
        return '建议根据具体情况采取相应措施。';
    }
  }

  // 获取响应历史
  getResponseHistory(limit = 10) {
    return this.responseHistory.slice(-limit).reverse();
  }

  // 获取阻止列表
  getBlockLists() {
    return {
      ips: Array.from(this.blockedIps.entries()).map(([ip, details]) => ({ ip, ...details })),
      processes: Array.from(this.blockedProcesses.entries()).map(([name, details]) => ({ name, ...details })),
      users: Array.from(this.blockedUsers.entries()).map(([username, details]) => ({ username, ...details }))
    };
  }

  // 更新配置
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    this.loadResponseRules();
    this.logger.info('响应器配置已更新');
    return this.config;
  }

  // 模拟系统交互方法 (实际实现中需要替换为真实系统调用)
  async _blockIp(ip, duration) {
    this.logger.info(`[模拟] 阻止IP: ${ip}, 持续时间: ${duration/1000}秒`);
    return { success: true };
  }

  async _blockPort(port) {
    this.logger.info(`[模拟] 阻止端口: ${port}`);
    return { success: true };
  }

  async _disconnectConnection(connectionId) {
    this.logger.info(`[模拟] 断开连接: ${connectionId}`);
    return { success: true };
  }

  async _getActiveConnections() {
    this.logger.info(`[模拟] 获取活跃连接`);
    return [];
  }

  async _terminateProcess(processName) {
    this.logger.info(`[模拟] 终止进程: ${processName}`);
    return { success: true };
  }

  async _suspendProcess(processName) {
    this.logger.info(`[模拟] 挂起进程: ${processName}`);
    return { success: true };
  }

  async _monitorProcess(processName) {
    this.logger.info(`[模拟] 监控进程: ${processName}`);
    return { success: true };
  }

  async _getProcessDetails(processName) {
    this.logger.info(`[模拟] 获取进程详情: ${processName}`);
    return {};
  }

  async _quarantineFile(filePath) {
    this.logger.info(`[模拟] 隔离文件: ${filePath}`);
    return { success: true };
  }

  async _deleteFile(filePath) {
    this.logger.info(`[模拟] 删除文件: ${filePath}`);
    return { success: true };
  }

  async _getFileDetails(filePath) {
    this.logger.info(`[模拟] 获取文件详情: ${filePath}`);
    return {};
  }

  async _disableUser(username) {
    this.logger.info(`[模拟] 禁用用户: ${username}`);
    return { success: true };
  }

  async _lockUserAccount(username) {
    this.logger.info(`[模拟] 锁定用户账户: ${username}`);
    return { success: true };
  }

  async _logoffUser(username) {
    this.logger.info(`[模拟] 注销用户: ${username}`);
    return { success: true };
  }

  async _isolateSystem() {
    this.logger.info(`[模拟] 隔离系统，仅保留必要连接`);
    return { success: true };
  }

  async _restoreSystem() {
    this.logger.info(`[模拟] 恢复系统正常连接`);
    return { success: true };
  }

  async _createBackup() {
    this.logger.info(`[模拟] 创建系统备份`);
    return { success: true };
  }

  async _updateSecuritySettings(settings) {
    this.logger.info(`[模拟] 更新安全设置`);
    return { success: true };
  }
}

export default InvasionResponder;