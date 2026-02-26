// 入侵分析器模块 - 负责分析收集的数据并识别潜在的入侵行为
class InvasionAnalyzer {
  constructor() {
    this.logger = window.globalLogger || console;
    this.modelEngine = window.modelEngine;
    this.preprocessor = new DataPreprocessor();
    this.featureExtractor = new FeatureExtractor();
    this.anomalyDetector = new AnomalyDetector();
    this.analysisHistory = [];
    this.rules = this.loadDetectionRules();
  }

  // 主分析方法
  async analyze(data) {
    try {
      this.logger.info('开始分析检测数据...');
      const startTime = Date.now();
      
      // 1. 数据预处理
      const processedData = await this.preprocessor.process(data);
      if (!processedData) {
        this.logger.warn('数据预处理失败');
        return null;
      }
      
      // 2. 特征提取
      const features = await this.featureExtractor.extract(processedData);
      if (!features || Object.keys(features).length === 0) {
        this.logger.warn('特征提取失败或未提取到有效特征');
        return null;
      }
      
      // 3. 基于规则的初步检测
      const ruleResults = this.applyRules(features, processedData);
      
      // 4. 异常检测
      const anomalies = this.anomalyDetector.detect(features, processedData);
      
      // 5. 使用大模型进行深度分析（如果配置启用）
      let llmAnalysis = null;
      try {
        llmAnalysis = await this.analyzeWithLLM(processedData, features, ruleResults, anomalies);
      } catch (llmError) {
        this.logger.error('大模型分析失败:', llmError);
        // 即使大模型分析失败，也继续使用其他方法的结果
      }
      
      // 6. 综合分析结果
      const finalResult = this.synthesizeResults(
        ruleResults,
        anomalies,
        llmAnalysis,
        features
      );
      
      // 7. 风险评估
      const riskAssessment = this.assessRisk(finalResult);
      
      // 8. 生成最终分析报告
      const analysisResult = {
        timestamp: new Date(),
        analysisTime: Date.now() - startTime,
        isInvasion: finalResult.isInvasion,
        confidence: finalResult.confidence || 0.0,
        riskLevel: riskAssessment.riskLevel,
        invasionType: finalResult.invasionType || 'UNKNOWN',
        details: {
          ruleMatches: ruleResults.matches,
          anomalies: anomalies,
          llmAnalysis: llmAnalysis,
          keyFeatures: features.keyFeatures || []
        },
        recommendations: riskAssessment.recommendations
      };
      
      // 9. 保存分析历史
      this.analysisHistory.push(analysisResult);
      if (this.analysisHistory.length > 50) {
        this.analysisHistory.shift();
      }
      
      this.logger.info(`数据分析完成，耗时: ${analysisResult.analysisTime}ms, 结果: ${analysisResult.isInvasion ? '检测到入侵行为' : '未检测到入侵行为'}`);
      return analysisResult;
    } catch (error) {
      this.logger.error('执行数据分析失败:', error);
      return null;
    }
  }

  // 使用大模型分析
  async analyzeWithLLM(processedData, features, ruleResults, anomalies) {
    try {
      // 检查模型引擎是否可用
      if (!this.modelEngine || typeof this.modelEngine.analyzeSituation !== 'function') {
        this.logger.warn('模型引擎不可用，跳过大模型分析');
        return null;
      }
      
      // 准备分析提示
      const prompt = this.prepareAnalysisPrompt(processedData, features, ruleResults, anomalies);
      
      // 调用模型引擎进行分析
      const result = await this.modelEngine.analyzeSituation(
        prompt,
        {
          taskType: 'invasion_detection',
          timeout: 30000,
          maxRetries: 2
        }
      );
      
      // 验证和解析结果
      if (result && result.success && result.data) {
        return this.parseModelResponse(result.data);
      } else {
        this.logger.warn('大模型分析返回无效结果');
        return null;
      }
    } catch (error) {
      this.logger.error('使用大模型分析失败:', error);
      
      // 如果模型分析失败，生成模拟结果（仅用于开发测试）
      return this.getMockAnalysis(processedData, features, ruleResults, anomalies);
    }
  }

  // 准备大模型分析提示
  prepareAnalysisPrompt(processedData, features, ruleResults, anomalies) {
    // 构建系统角色提示
    const systemPrompt = `
你是一个专业的网络安全分析师，负责识别和分析潜在的入侵行为。
请根据提供的系统数据，判断是否存在入侵迹象，并提供详细分析。

分析要求：
1. 仔细检查所有提供的数据，寻找可疑模式和异常行为
2. 评估潜在威胁的严重程度
3. 如果识别出入侵行为，请提供详细的入侵类型和可能的攻击方法
4. 提供具体的建议来应对识别出的威胁

输出格式：
{
  "isInvasion": true/false,
  "confidence": 0.0-1.0,
  "riskLevel": "LOW"/"MEDIUM"/"HIGH"/"CRITICAL",
  "invasionType": "入侵类型描述",
  "details": "详细分析",
  "recommendations": ["建议的响应措施"]
}
`;

    // 构建用户提示
    const userPrompt = `
请分析以下安全数据，识别是否存在入侵行为：

1. 关键特征：
${JSON.stringify(features.keyFeatures || [], null, 2)}

2. 规则检测结果：
- 匹配规则数量：${ruleResults.matches.length}
- 高优先级匹配：${ruleResults.matches.filter(m => m.severity === 'HIGH' || m.severity === 'CRITICAL').length}

3. 异常检测结果：
${JSON.stringify(anomalies.slice(0, 5), null, 2)}
${anomalies.length > 5 ? `... 等共 ${anomalies.length} 个异常` : ''}

4. 网络数据摘要：
- 活跃连接数：${processedData.network?.connections?.length || 0}
- 异常网络行为：${processedData.network?.anomalies?.length || 0}

5. 系统数据摘要：
- 运行进程数：${processedData.system?.processes?.length || 0}
- 可疑文件活动：${processedData.system?.fileSystem?.criticalFileAccess?.length || 0}
- 注册表变更：${processedData.system?.registryChanges?.length || 0}

6. 安全事件摘要：
- 防火墙拦截：${processedData.securityEvents?.firewall?.filter(e => e.action === 'BLOCK').length || 0}
- 失败登录尝试：${processedData.securityEvents?.authentication?.filter(e => !e.success).length || 0}

请基于以上数据提供详细分析。
`;

    return {
      system: systemPrompt,
      user: userPrompt
    };
  }

  // 解析模型响应
  parseModelResponse(response) {
    try {
      // 确保响应是有效的JSON格式
      let parsed;
      if (typeof response === 'string') {
        parsed = JSON.parse(response);
      } else {
        parsed = response;
      }

      // 验证必需字段
      const requiredFields = ['isInvasion', 'confidence', 'riskLevel'];
      for (const field of requiredFields) {
        if (parsed[field] === undefined) {
          this.logger.warn(`模型响应缺少必需字段: ${field}`);
          return null;
        }
      }

      // 规范化风险等级
      const validRiskLevels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
      if (!validRiskLevels.includes(parsed.riskLevel)) {
        this.logger.warn(`无效的风险等级: ${parsed.riskLevel}`);
        parsed.riskLevel = 'MEDIUM'; // 默认中等风险
      }

      // 规范化置信度
      parsed.confidence = Math.max(0, Math.min(1, parseFloat(parsed.confidence) || 0));

      return {
        isInvasion: Boolean(parsed.isInvasion),
        confidence: parsed.confidence,
        riskLevel: parsed.riskLevel,
        invasionType: parsed.invasionType || 'UNKNOWN',
        details: parsed.details || '',
        recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations : []
      };
    } catch (error) {
      this.logger.error('解析模型响应失败:', error);
      return null;
    }
  }

  // 获取模拟分析结果（用于开发测试）
  getMockAnalysis(processedData, features, ruleResults, anomalies) {
    // 基于规则匹配和异常数量生成模拟结果
    const highSeverityMatches = ruleResults.matches.filter(m => 
      m.severity === 'HIGH' || m.severity === 'CRITICAL'
    ).length;
    
    const criticalAnomalies = anomalies.filter(a => 
      a.severity === 'HIGH' || a.severity === 'CRITICAL'
    ).length;
    
    const isInvasion = highSeverityMatches > 0 || criticalAnomalies > 0;
    
    let riskLevel = 'LOW';
    let confidence = 0.3;
    let invasionType = 'UNKNOWN';
    
    if (isInvasion) {
      if (highSeverityMatches >= 3 || criticalAnomalies >= 3) {
        riskLevel = 'CRITICAL';
        confidence = 0.95;
        invasionType = '可能的多向量攻击';
      } else if (highSeverityMatches >= 2 || criticalAnomalies >= 2) {
        riskLevel = 'HIGH';
        confidence = 0.85;
        invasionType = '可能的有针对性攻击';
      } else {
        riskLevel = 'MEDIUM';
        confidence = 0.75;
        invasionType = '可疑活动';
      }
    } else if (anomalies.length > 5) {
      riskLevel = 'MEDIUM';
      confidence = 0.6;
      invasionType = '异常行为';
    }
    
    return {
      isInvasion,
      confidence,
      riskLevel,
      invasionType,
      details: isInvasion 
        ? `检测到${highSeverityMatches}个高严重性规则匹配和${criticalAnomalies}个严重异常，表明可能存在入侵行为。`
        : '未检测到明确的入侵行为迹象。',
      recommendations: isInvasion
        ? [
            '立即隔离受影响的系统',
            '阻止来自可疑IP的连接',
            '检查最近的系统变更',
            '保存所有日志用于进一步分析'
          ]
        : [
            '继续监控系统活动',
            '定期检查异常行为模式'
          ]
    };
  }

  // 应用检测规则
  applyRules(features, data) {
    const matches = [];
    
    // 遍历所有规则并检查是否匹配
    for (const rule of this.rules) {
      try {
        const match = this.evaluateRule(rule, features, data);
        if (match) {
          matches.push({
            ruleId: rule.id,
            name: rule.name,
            severity: rule.severity,
            description: rule.description,
            evidence: match.evidence || {},
            confidence: match.confidence || 1.0
          });
        }
      } catch (error) {
        this.logger.error(`评估规则 ${rule.id} 失败:`, error);
      }
    }
    
    // 按严重性和置信度排序
    matches.sort((a, b) => {
      const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
      const severityDiff = severityOrder[b.severity] - severityOrder[a.severity];
      return severityDiff !== 0 ? severityDiff : b.confidence - a.confidence;
    });
    
    return {
      matches,
      totalRules: this.rules.length,
      matchedRules: matches.length
    };
  }

  // 评估单个规则
  evaluateRule(rule, features, data) {
    // 根据规则类型执行不同的评估逻辑
    switch (rule.type) {
      case 'threshold':
        return this.evaluateThresholdRule(rule, features, data);
      case 'pattern':
        return this.evaluatePatternRule(rule, features, data);
      case 'correlation':
        return this.evaluateCorrelationRule(rule, features, data);
      default:
        this.logger.warn(`未知规则类型: ${rule.type}`);
        return null;
    }
  }

  // 评估阈值规则
  evaluateThresholdRule(rule, features, data) {
    const { target, operator, value, field } = rule.condition;
    let actualValue;
    
    // 获取目标字段的值
    if (target === 'features' && features[field] !== undefined) {
      actualValue = features[field];
    } else if (target === 'data') {
      // 从数据中获取值（支持嵌套路径）
      actualValue = this.getNestedValue(data, field);
    }
    
    if (actualValue === undefined) return null;
    
    // 执行比较操作
    let isMatch = false;
    switch (operator) {
      case '>':
        isMatch = actualValue > value;
        break;
      case '<':
        isMatch = actualValue < value;
        break;
      case '>=':
        isMatch = actualValue >= value;
        break;
      case '<=':
        isMatch = actualValue <= value;
        break;
      case '==':
        isMatch = actualValue === value;
        break;
      case '!=':
        isMatch = actualValue !== value;
        break;
      default:
        return null;
    }
    
    return isMatch ? {
      evidence: { field, actualValue, expectedValue: value, operator }
    } : null;
  }

  // 评估模式规则
  evaluatePatternRule(rule, features, data) {
    const { target, pattern, field } = rule.condition;
    let targetValue;
    
    // 获取目标字段的值
    if (target === 'features' && features[field] !== undefined) {
      targetValue = features[field];
    } else if (target === 'data') {
      targetValue = this.getNestedValue(data, field);
    }
    
    if (!targetValue) return null;
    
    // 将目标值转换为字符串进行模式匹配
    const strValue = Array.isArray(targetValue) 
      ? targetValue.join(' ') 
      : String(targetValue);
    
    // 使用正则表达式进行匹配
    const regex = new RegExp(pattern, 'i');
    const matches = strValue.match(regex);
    
    return matches ? {
      evidence: { field, pattern, matches: matches.slice() }
    } : null;
  }

  // 评估关联规则
  evaluateCorrelationRule(rule, features, data) {
    const { conditions, operator } = rule.condition;
    let allMatch = true;
    let anyMatch = false;
    const evidence = [];
    
    // 评估所有子条件
    for (const subRule of conditions) {
      const match = this.evaluateRule(subRule, features, data);
      if (match) {
        evidence.push(match.evidence);
        anyMatch = true;
      } else {
        allMatch = false;
      }
    }
    
    // 根据操作符决定结果
    const isMatch = operator === 'AND' ? allMatch : anyMatch;
    
    return isMatch ? { evidence } : null;
  }

  // 获取嵌套对象的值
  getNestedValue(obj, path) {
    const keys = path.split('.');
    let value = obj;
    
    for (const key of keys) {
      if (value && typeof value === 'object' && key in value) {
        value = value[key];
      } else {
        return undefined;
      }
    }
    
    return value;
  }

  // 综合分析结果
  synthesizeResults(ruleResults, anomalies, llmAnalysis, features) {
    let isInvasion = false;
    let confidence = 0;
    let invasionType = 'UNKNOWN';
    
    // 计算规则匹配得分
    const ruleScore = this.calculateRuleScore(ruleResults.matches);
    
    // 计算异常得分
    const anomalyScore = this.calculateAnomalyScore(anomalies);
    
    // 计算特征得分
    const featureScore = this.calculateFeatureScore(features);
    
    // 如果有大模型分析结果，给予较高权重
    if (llmAnalysis) {
      isInvasion = llmAnalysis.isInvasion;
      confidence = llmAnalysis.confidence * 0.6 + (ruleScore + anomalyScore + featureScore) * 0.133;
      invasionType = llmAnalysis.invasionType;
    } else {
      // 综合其他分析结果
      confidence = (ruleScore * 0.4 + anomalyScore * 0.3 + featureScore * 0.3);
      isInvasion = confidence > 0.6;
      
      // 根据最严重的规则或异常确定入侵类型
      if (ruleResults.matches.length > 0) {
        const highestRule = ruleResults.matches[0];
        invasionType = highestRule.name;
      } else if (anomalies.length > 0) {
        const highestAnomaly = anomalies.find(a => a.severity === 'CRITICAL') || 
                              anomalies.find(a => a.severity === 'HIGH');
        if (highestAnomaly) {
          invasionType = highestAnomaly.type;
        }
      }
    }
    
    // 限制置信度范围
    confidence = Math.max(0, Math.min(1, confidence));
    
    return {
      isInvasion,
      confidence,
      invasionType
    };
  }

  // 计算规则匹配得分
  calculateRuleScore(matches) {
    const severityWeights = {
      'CRITICAL': 1.0,
      'HIGH': 0.8,
      'MEDIUM': 0.5,
      'LOW': 0.2
    };
    
    let score = 0;
    let weightSum = 0;
    
    // 对每个匹配的规则计算加权得分
    for (const match of matches) {
      const weight = severityWeights[match.severity] || 0.5;
      score += (match.confidence || 1.0) * weight;
      weightSum += weight;
    }
    
    // 归一化得分
    return weightSum > 0 ? score / weightSum : 0;
  }

  // 计算异常得分
  calculateAnomalyScore(anomalies) {
    const severityWeights = {
      'CRITICAL': 1.0,
      'HIGH': 0.8,
      'MEDIUM': 0.5,
      'LOW': 0.2
    };
    
    let score = 0;
    let weightSum = 0;
    
    // 对每个异常计算加权得分
    for (const anomaly of anomalies) {
      const weight = severityWeights[anomaly.severity] || 0.5;
      score += (anomaly.confidence || 1.0) * weight;
      weightSum += weight;
    }
    
    // 归一化得分
    return weightSum > 0 ? score / weightSum : 0;
  }

  // 计算特征得分
  calculateFeatureScore(features) {
    let score = 0;
    const suspiciousPatterns = [
      'unusual_process',
      'suspicious_network',
      'registry_modification',
      'failed_logins',
      'privilege_escalation',
      'unauthorized_access'
    ];
    
    // 检查关键特征中是否存在可疑模式
    if (features.keyFeatures) {
      for (const feature of features.keyFeatures) {
        for (const pattern of suspiciousPatterns) {
          if (feature.type === pattern || String(feature.value).includes(pattern)) {
            score += 0.2; // 每种可疑模式增加0.2分
            break;
          }
        }
      }
    }
    
    // 限制最大得分
    return Math.min(1.0, score);
  }

  // 风险评估
  assessRisk(analysisResult) {
    let riskLevel = 'LOW';
    const recommendations = [];
    
    // 基于置信度和入侵状态确定风险等级
    if (analysisResult.isInvasion) {
      if (analysisResult.confidence >= 0.9) {
        riskLevel = 'CRITICAL';
      } else if (analysisResult.confidence >= 0.7) {
        riskLevel = 'HIGH';
      } else {
        riskLevel = 'MEDIUM';
      }
      
      // 根据风险等级生成建议
      switch (riskLevel) {
        case 'CRITICAL':
          recommendations.push(
            '立即隔离受影响的系统',
            '启动安全事件响应流程',
            '阻止所有可疑IP地址和连接',
            '保存所有日志用于取证分析',
            '联系安全团队进行紧急响应'
          );
          break;
        case 'HIGH':
          recommendations.push(
            '隔离受影响的系统',
            '阻止可疑IP地址',
            '检查系统是否有未授权的更改',
            '加强监控可疑活动',
            '执行完整的安全扫描'
          );
          break;
        case 'MEDIUM':
          recommendations.push(
            '密切监控可疑活动',
            '验证系统配置和权限',
            '更新安全控制措施',
            '检查可疑的用户活动',
            '准备好应急响应计划'
          );
          break;
      }
    } else {
      // 即使没有检测到入侵，也提供一般安全建议
      recommendations.push(
        '继续常规安全监控',
        '定期更新安全策略和规则',
        '执行定期安全审计',
        '确保所有系统及时更新补丁'
      );
    }
    
    return {
      riskLevel,
      recommendations
    };
  }

  // 加载检测规则
  loadDetectionRules() {
    return [
      // 高严重性规则
      {
        id: 'RULE_001',
        name: 'SSH暴力破解尝试',
        description: '检测到多个失败的SSH登录尝试',
        severity: 'HIGH',
        type: 'threshold',
        condition: {
          target: 'features',
          field: 'failedSshAttempts',
          operator: '>=',
          value: 5
        }
      },
      {
        id: 'RULE_002',
        name: '可疑进程创建',
        description: '检测到具有可疑特征的进程',
        severity: 'HIGH',
        type: 'pattern',
        condition: {
          target: 'data',
          field: 'system.processes',
          pattern: '(powershell|cmd|wscript|cscript).*(hidden|/c|/b|download|exec)'
        }
      },
      // 中严重性规则
      {
        id: 'RULE_003',
        name: '异常网络连接',
        description: '检测到大量来自同一IP的连接',
        severity: 'MEDIUM',
        type: 'threshold',
        condition: {
          target: 'features',
          field: 'maxConnectionsFromSingleIp',
          operator: '>=',
          value: 20
        }
      },
      {
        id: 'RULE_004',
        name: '注册表自启动项修改',
        description: '检测到对自启动注册表项的修改',
        severity: 'MEDIUM',
        type: 'pattern',
        condition: {
          target: 'data',
          field: 'system.registryChanges',
          pattern: 'Run|RunOnce|Startup'
        }
      },
      // 关联规则
      {
        id: 'RULE_005',
        name: '潜在的权限提升',
        description: '检测到可能的权限提升活动',
        severity: 'CRITICAL',
        type: 'correlation',
        condition: {
          operator: 'AND',
          conditions: [
            {
              type: 'pattern',
              condition: {
                target: 'data',
                field: 'system.processes',
                pattern: '(mimikatz|privilege|token|admin)'
              }
            },
            {
              type: 'threshold',
              condition: {
                target: 'features',
                field: 'privilegedOperations',
                operator: '>=',
                value: 2
              }
            }
          ]
        }
      }
    ];
  }

  // 获取分析历史
  getAnalysisHistory(limit = 10) {
    return this.analysisHistory.slice(-limit).reverse();
  }

  // 获取统计信息
  getStatistics() {
    const totalAnalyses = this.analysisHistory.length;
    const invasionsDetected = this.analysisHistory.filter(a => a.isInvasion).length;
    const falsePositives = this.analysisHistory.filter(a => a.isInvasion && a.confidence < 0.6).length;
    
    return {
      totalAnalyses,
      invasionsDetected,
      falsePositives,
      detectionRate: totalAnalyses > 0 ? invasionsDetected / totalAnalyses : 0
    };
  }
}

// 数据预处理器类
class DataPreprocessor {
  constructor() {
    this.logger = window.globalLogger || console;
  }

  // 处理原始数据
  async process(data) {
    try {
      // 验证数据格式
      if (!data || typeof data !== 'object') {
        return null;
      }
      
      const processed = {
        timestamp: data.timestamp || new Date(),
        network: this.processNetworkData(data.network),
        system: this.processSystemData(data.system),
        logs: this.processLogData(data.logs),
        securityEvents: this.processSecurityEvents(data.securityEvents)
      };
      
      return processed;
    } catch (error) {
      this.logger.error('数据预处理失败:', error);
      return null;
    }
  }

  // 处理网络数据
  processNetworkData(networkData) {
    if (!networkData) return null;
    
    // 清理和标准化连接数据
    const connections = Array.isArray(networkData.connections) ? 
      networkData.connections.map(conn => ({
        ...conn,
        protocol: conn.protocol?.toUpperCase() || 'UNKNOWN',
        state: conn.state?.toUpperCase() || 'UNKNOWN'
      })) : [];
    
    return {
      connections,
      stats: networkData.stats || {},
      anomalies: networkData.anomalies || []
    };
  }

  // 处理系统数据
  processSystemData(systemData) {
    if (!systemData) return null;
    
    // 清理和标准化进程数据
    const processes = Array.isArray(systemData.processes) ? 
      systemData.processes.map(process => ({
        ...process,
        name: process.name?.toLowerCase() || '',
        path: process.path || '',
        commandLine: process.commandLine || ''
      })) : [];
    
    return {
      processes,
      resources: systemData.resources || {},
      fileSystem: systemData.fileSystem || {},
      registryChanges: systemData.registryChanges || [],
      userActivity: systemData.userActivity || {}
    };
  }

  // 处理日志数据
  processLogData(logData) {
    if (!logData) return null;
    
    // 过滤和分类日志
    const filterLogs = (logs) => {
      return Array.isArray(logs) ? 
        logs.filter(log => log.level && ['ERROR', 'WARNING', 'CRITICAL'].includes(log.level)) : [];
    };
    
    return {
      system: filterLogs(logData.system),
      application: filterLogs(logData.application),
      security: filterLogs(logData.security)
    };
  }

  // 处理安全事件
  processSecurityEvents(securityEvents) {
    if (!securityEvents) return null;
    
    return {
      firewall: securityEvents.firewall || [],
      antivirus: securityEvents.antivirus || [],
      ids: securityEvents.ids || [],
      authentication: securityEvents.authentication || [],
      accessControl: securityEvents.accessControl || []
    };
  }
}

// 特征提取器类
class FeatureExtractor {
  constructor() {
    this.logger = window.globalLogger || console;
  }

  // 提取特征
  async extract(data) {
    try {
      const features = {
        // 网络特征
        activeConnections: this.countConnections(data.network),
        externalConnections: this.countExternalConnections(data.network),
        failedSshAttempts: this.countFailedSshAttempts(data),
        maxConnectionsFromSingleIp: this.getMaxConnectionsFromSingleIp(data.network),
        
        // 系统特征
        processCount: this.countProcesses(data.system),
        suspiciousProcesses: this.countSuspiciousProcesses(data.system),
        criticalFileAccess: this.countCriticalFileAccess(data.system),
        registryChanges: this.countRegistryChanges(data.system),
        privilegedOperations: this.countPrivilegedOperations(data.system),
        
        // 安全事件特征
        failedLogins: this.countFailedLogins(data),
        blockedConnections: this.countBlockedConnections(data),
        securityAlerts: this.countSecurityAlerts(data),
        
        // 关键特征（用于大模型分析）
        keyFeatures: this.extractKeyFeatures(data)
      };
      
      return features;
    } catch (error) {
      this.logger.error('特征提取失败:', error);
      return null;
    }
  }

  // 计算活跃连接数
  countConnections(networkData) {
    return networkData?.connections?.length || 0;
  }

  // 计算外部连接数
  countExternalConnections(networkData) {
    if (!networkData?.connections) return 0;
    
    const privateIps = ['10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.'];
    
    return networkData.connections.filter(conn => {
      return !privateIps.some(ip => conn.remoteAddress?.startsWith(ip));
    }).length;
  }

  // 计算SSH失败尝试次数
  countFailedSshAttempts(data) {
    let count = 0;
    
    // 检查安全事件中的失败认证
    if (data.securityEvents?.authentication) {
      count += data.securityEvents.authentication.filter(auth => 
        !auth.success && auth.method === 'PASSWORD' && (auth.destPort === 22 || auth.details?.includes('SSH'))
      ).length;
    }
    
    // 检查安全日志中的失败登录
    if (data.logs?.security) {
      count += data.logs.security.filter(log => 
        log.message?.includes('failed to log on') && log.message?.includes('SSH')
      ).length;
    }
    
    return count;
  }

  // 获取单个IP的最大连接数
  getMaxConnectionsFromSingleIp(networkData) {
    if (!networkData?.connections) return 0;
    
    const ipCounts = {};
    for (const conn of networkData.connections) {
      if (conn.remoteAddress) {
        ipCounts[conn.remoteAddress] = (ipCounts[conn.remoteAddress] || 0) + 1;
      }
    }
    
    const counts = Object.values(ipCounts);
    return counts.length > 0 ? Math.max(...counts) : 0;
  }

  // 计算进程数
  countProcesses(systemData) {
    return systemData?.processes?.length || 0;
  }

  // 计算可疑进程数
  countSuspiciousProcesses(systemData) {
    if (!systemData?.processes) return 0;
    
    const suspiciousPatterns = [
      'cmd.exe.*\/c', 'powershell.exe.*-enc', 'wscript.exe', 'cscript.exe',
      'regsvr32.exe', 'mshta.exe', 'bitsadmin.exe', 'certutil.exe',
      'mimikatz', 'pwdump', 'gsecdump', 'procdump',
      'nslookup.exe', 'netsh.exe', 'whoami.exe'
    ];
    
    return systemData.processes.filter(process => {
      const processStr = `${process.name} ${process.commandLine}`.toLowerCase();
      return suspiciousPatterns.some(pattern => 
        new RegExp(pattern, 'i').test(processStr)
      );
    }).length;
  }

  // 计算关键文件访问数
  countCriticalFileAccess(systemData) {
    return systemData?.fileSystem?.criticalFileAccess?.length || 0;
  }

  // 计算注册表变更数
  countRegistryChanges(systemData) {
    return systemData?.registryChanges?.length || 0;
  }

  // 计算特权操作数
  countPrivilegedOperations(systemData) {
    return systemData?.userActivity?.privilegedOperations?.length || 0;
  }

  // 计算失败登录数
  countFailedLogins(data) {
    let count = 0;
    
    // 检查系统用户活动
    if (data.system?.userActivity?.failedLogins) {
      count += data.system.userActivity.failedLogins.length;
    }
    
    // 检查安全事件
    if (data.securityEvents?.authentication) {
      count += data.securityEvents.authentication.filter(auth => !auth.success).length;
    }
    
    // 检查安全日志
    if (data.logs?.security) {
      count += data.logs.security.filter(log => 
        log.message?.includes('failed to log on')
      ).length;
    }
    
    return count;
  }

  // 计算被阻止的连接数
  countBlockedConnections(data) {
    return data?.securityEvents?.firewall?.filter(event => 
      event.action === 'BLOCK'
    ).length || 0;
  }

  // 计算安全告警数
  countSecurityAlerts(data) {
    let count = 0;
    
    // 检查杀毒软件事件
    if (data.securityEvents?.antivirus) {
      count += data.securityEvents.antivirus.length;
    }
    
    // 检查IDS事件
    if (data.securityEvents?.ids) {
      count += data.securityEvents.ids.length;
    }
    
    // 检查高严重性日志
    if (data.logs) {
      ['system', 'application', 'security'].forEach(logType => {
        if (data.logs[logType]) {
          count += data.logs[logType].filter(log => 
            log.level === 'ERROR' || log.level === 'CRITICAL'
          ).length;
        }
      });
    }
    
    return count;
  }

  // 提取关键特征
  extractKeyFeatures(data) {
    const keyFeatures = [];
    
    // 网络关键特征
    if (data.network) {
      // 检查异常连接
      if (data.network.anomalies && data.network.anomalies.length > 0) {
        data.network.anomalies.forEach(anomaly => {
          keyFeatures.push({
            type: 'network_anomaly',
            value: anomaly.type,
            severity: anomaly.severity || 'MEDIUM',
            details: anomaly.message || ''
          });
        });
      }
    }
    
    // 系统关键特征
    if (data.system) {
      // 检查可疑进程
      if (data.system.processes) {
        const suspiciousProcesses = this.findSuspiciousProcesses(data.system.processes);
        suspiciousProcesses.forEach(process => {
          keyFeatures.push({
            type: 'suspicious_process',
            value: process.name,
            details: process.path || process.commandLine || ''
          });
        });
      }
      
      // 检查注册表更改
      if (data.system.registryChanges && data.system.registryChanges.length > 0) {
        const startupChanges = data.system.registryChanges.filter(change => 
          change.key?.includes('Run') || change.key?.includes('Startup')
        );
        startupChanges.forEach(change => {
          keyFeatures.push({
            type: 'registry_modification',
            value: change.key,
            details: `${change.oldValue} -> ${change.newValue}`
          });
        });
      }
    }
    
    // 安全事件关键特征
    if (data.securityEvents) {
      // 检查失败登录
      if (this.countFailedLogins(data) > 3) {
        keyFeatures.push({
          type: 'failed_logins',
          value: this.countFailedLogins(data),
          details: '多次登录失败尝试'
        });
      }
      
      // 检查权限提升
      if (data.system?.userActivity?.privilegedOperations && data.system.userActivity.privilegedOperations.length > 0) {
        data.system.userActivity.privilegedOperations.forEach(operation => {
          keyFeatures.push({
            type: 'privilege_escalation',
            value: operation.operation,
            details: `用户: ${operation.user}`
          });
        });
      }
      
      // 检查防火墙阻止
      const blockedEvents = data.securityEvents.firewall?.filter(event => event.action === 'BLOCK') || [];
      if (blockedEvents.length > 5) {
        keyFeatures.push({
          type: 'firewall_blocks',
          value: blockedEvents.length,
          details: '多次连接被防火墙阻止'
        });
      }
    }
    
    return keyFeatures;
  }

  // 查找可疑进程
  findSuspiciousProcesses(processes) {
    const suspiciousPatterns = [
      { pattern: 'mimikatz', severity: 'CRITICAL' },
      { pattern: 'pwdump', severity: 'CRITICAL' },
      { pattern: 'cmd.exe.*\/c', severity: 'HIGH' },
      { pattern: 'powershell.exe.*-enc', severity: 'HIGH' },
      { pattern: 'wscript.exe', severity: 'MEDIUM' },
      { pattern: 'regsvr32.exe', severity: 'MEDIUM' }
    ];
    
    const suspiciousProcesses = [];
    
    for (const process of processes) {
      const processStr = `${process.name} ${process.commandLine}`.toLowerCase();
      
      for (const { pattern, severity } of suspiciousPatterns) {
        if (new RegExp(pattern, 'i').test(processStr)) {
          suspiciousProcesses.push({
            ...process,
            suspiciousReason: pattern,
            severity
          });
          break;
        }
      }
    }
    
    return suspiciousProcesses;
  }
}

// 异常检测器类
class AnomalyDetector {
  constructor() {
    this.logger = window.globalLogger || console;
  }

  // 检测异常
  detect(features, data) {
    const anomalies = [];
    
    // 检测网络异常
    anomalies.push(...this.detectNetworkAnomalies(features, data.network));
    
    // 检测系统异常
    anomalies.push(...this.detectSystemAnomalies(features, data.system));
    
    // 检测安全事件异常
    anomalies.push(...this.detectSecurityEventAnomalies(features, data.securityEvents));
    
    // 检测综合异常
    anomalies.push(...this.detectCompositeAnomalies(features, data));
    
    // 按严重性排序
    return anomalies.sort((a, b) => {
      const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
      return severityOrder[b.severity] - severityOrder[a.severity];
    });
  }

  // 检测网络异常
  detectNetworkAnomalies(features, networkData) {
    const anomalies = [];
    
    // 检测高连接数
    if (features.activeConnections > 100) {
      anomalies.push({
        type: 'HIGH_CONNECTION_COUNT',
        severity: 'MEDIUM',
        description: `检测到异常高的网络连接数: ${features.activeConnections}`,
        confidence: Math.min(1.0, features.activeConnections / 200),
        timestamp: new Date()
      });
    }
    
    // 检测大量外部连接
    if (features.externalConnections > 50) {
      anomalies.push({
        type: 'HIGH_EXTERNAL_CONNECTIONS',
        severity: 'MEDIUM',
        description: `检测到异常多的外部连接: ${features.externalConnections}`,
        confidence: Math.min(1.0, features.externalConnections / 100),
        timestamp: new Date()
      });
    }
    
    // 检测单一IP大量连接
    if (features.maxConnectionsFromSingleIp > 20) {
      anomalies.push({
        type: 'SINGLE_IP_FLOOD',
        severity: 'HIGH',
        description: `检测到单一IP的异常多连接: ${features.maxConnectionsFromSingleIp}`,
        confidence: Math.min(1.0, features.maxConnectionsFromSingleIp / 50),
        timestamp: new Date()
      });
    }
    
    // 检测已知的网络异常模式
    if (networkData?.anomalies) {
      networkData.anomalies.forEach(anomaly => {
        anomalies.push({
          ...anomaly,
          timestamp: new Date()
        });
      });
    }
    
    return anomalies;
  }

  // 检测系统异常
  detectSystemAnomalies(features, systemData) {
    const anomalies = [];
    
    // 检测可疑进程
    if (features.suspiciousProcesses > 0) {
      anomalies.push({
        type: 'SUSPICIOUS_PROCESSES',
        severity: 'HIGH',
        description: `检测到可疑进程: ${features.suspiciousProcesses}`,
        confidence: Math.min(1.0, features.suspiciousProcesses / 5),
        timestamp: new Date()
      });
    }
    
    // 检测注册表自启动项修改
    if (features.registryChanges > 0) {
      anomalies.push({
        type: 'REGISTRY_MODIFICATIONS',
        severity: 'MEDIUM',
        description: `检测到注册表修改: ${features.registryChanges}`,
        confidence: Math.min(1.0, features.registryChanges / 3),
        timestamp: new Date()
      });
    }
    
    // 检测关键文件访问
    if (features.criticalFileAccess > 0) {
      anomalies.push({
        type: 'CRITICAL_FILE_ACCESS',
        severity: 'HIGH',
        description: `检测到对关键文件的访问: ${features.criticalFileAccess}`,
        confidence: Math.min(1.0, features.criticalFileAccess / 5),
        timestamp: new Date()
      });
    }
    
    // 检测权限提升操作
    if (features.privilegedOperations > 0) {
      anomalies.push({
        type: 'PRIVILEGE_ESCALATION_ATTEMPT',
        severity: 'CRITICAL',
        description: `检测到权限提升操作: ${features.privilegedOperations}`,
        confidence: Math.min(1.0, features.privilegedOperations / 2),
        timestamp: new Date()
      });
    }
    
    return anomalies;
  }

  // 检测安全事件异常
  detectSecurityEventAnomalies(features, securityEvents) {
    const anomalies = [];
    
    // 检测SSH暴力破解
    if (features.failedSshAttempts > 5) {
      anomalies.push({
        type: 'SSH_BRUTE_FORCE',
        severity: 'HIGH',
        description: `检测到SSH暴力破解尝试: ${features.failedSshAttempts}`,
        confidence: Math.min(1.0, features.failedSshAttempts / 10),
        timestamp: new Date()
      });
    }
    
    // 检测登录失败
    if (features.failedLogins > 3) {
      anomalies.push({
        type: 'MULTIPLE_FAILED_LOGINS',
        severity: 'MEDIUM',
        description: `检测到多次登录失败: ${features.failedLogins}`,
        confidence: Math.min(1.0, features.failedLogins / 8),
        timestamp: new Date()
      });
    }
    
    // 检测防火墙阻止
    if (features.blockedConnections > 10) {
      anomalies.push({
        type: 'FIREWALL_BLOCKS',
        severity: 'MEDIUM',
        description: `检测到大量防火墙阻止: ${features.blockedConnections}`,
        confidence: Math.min(1.0, features.blockedConnections / 20),
        timestamp: new Date()
      });
    }
    
    // 检测杀毒软件告警
    if (securityEvents?.antivirus && securityEvents.antivirus.length > 0) {
      const highSeverityThreats = securityEvents.antivirus.filter(threat => 
        threat.severity === 'HIGH' || threat.severity === 'CRITICAL'
      );
      
      if (highSeverityThreats.length > 0) {
        anomalies.push({
          type: 'MALWARE_DETECTION',
          severity: 'CRITICAL',
          description: `检测到高风险恶意软件: ${highSeverityThreats.length}`,
          confidence: 1.0,
          timestamp: new Date()
        });
      }
    }
    
    return anomalies;
  }

  // 检测综合异常
  detectCompositeAnomalies(features, data) {
    const anomalies = [];
    
    // 检测可能的横向移动
    const hasFailedLogins = features.failedLogins > 2;
    const hasMultipleConnections = features.maxConnectionsFromSingleIp > 15;
    const hasPrivilegedOperations = features.privilegedOperations > 0;
    
    if (hasFailedLogins && hasMultipleConnections) {
      anomalies.push({
        type: 'POSSIBLE_LATERAL_MOVEMENT',
        severity: 'CRITICAL',
        description: '检测到可能的横向移动行为',
        confidence: 0.8,
        timestamp: new Date()
      });
    }
    
    // 检测可能的数据泄露
    const hasHighOutboundTraffic = data.network?.stats?.bytesSent > 100000000; // 100MB
    const hasSuspiciousProcesses = features.suspiciousProcesses > 0;
    
    if (hasHighOutboundTraffic && hasSuspiciousProcesses) {
      anomalies.push({
        type: 'POSSIBLE_DATA_EXFILTRATION',
        severity: 'CRITICAL',
        description: '检测到可能的数据泄露行为',
        confidence: 0.75,
        timestamp: new Date()
      });
    }
    
    // 检测可能的持久性机制
    const hasRegistryChanges = features.registryChanges > 0;
    const hasStartupChanges = data.system?.registryChanges?.some(change => 
      change.key?.includes('Run') || change.key?.includes('Startup')
    );
    
    if (hasRegistryChanges && hasStartupChanges) {
      anomalies.push({
        type: 'PERSISTENCE_MECHANISM',
        severity: 'HIGH',
        description: '检测到可能的持久性机制',
        confidence: 0.9,
        timestamp: new Date()
      });
    }
    
    return anomalies;
  }
}

export default InvasionAnalyzer;