// 基于大模型的入侵分析器 - 负责利用大模型进行深度入侵行为分析
class LLMInvasionAnalyzer {
  constructor(config = {}) {
    this.logger = window.globalLogger || console;
    this.modelEngine = window.modelEngine;
    
    // 配置项
    this.config = {
      modelName: 'security-analyzer',
      maxTokens: 2000,
      temperature: 0.3, // 较低的温度以确保分析的一致性和准确性
      timeout: 30000,
      maxRetries: 2,
      retryDelay: 1000,
      contextSize: 5, // 保留的历史上下文数量
      useVectorStore: true,
      enableChainOfThought: true,
      enableFewShotLearning: true,
      enableRAG: true, // 启用检索增强生成
      ...config
    };
    
    // 分析历史和上下文
    this.analysisHistory = [];
    this.conversationContexts = new Map();
    
    // 提示模板
    this.promptTemplates = this.initializePromptTemplates();
    
    // 示例库 (用于少样本学习)
    this.examples = this.initializeExamples();
    
    // RAG知识库
    this.knowledgeBase = this.initializeKnowledgeBase();
    
    this.logger.info('LLM入侵分析器初始化完成');
  }

  // 初始化提示模板
  initializePromptTemplates() {
    return {
      // 系统提示
      systemPrompt: `
你是一个专业的网络安全分析师和入侵检测专家，拥有丰富的网络安全经验和深厚的技术知识。

你的任务是：
1. 仔细分析提供的系统数据，寻找入侵行为的证据和迹象
2. 使用专业的安全知识，识别攻击类型和技术
3. 评估威胁的严重程度和潜在影响
4. 提供详细、准确的分析结果和具体的应对建议

分析标准：
- 严格基于提供的事实数据进行分析，不凭空猜测
- 提供明确的证据支持你的结论
- 使用精确的安全术语和技术名称
- 考虑误报的可能性，提供置信度评估
- 当信息不足时，明确指出并提供基于已知信息的最佳分析

输出格式要求：
{
  "analysis": {
    "isInvasion": true/false, // 是否检测到入侵行为
    "confidence": 0.0-1.0,   // 分析的置信度
    "riskLevel": "LOW"/"MEDIUM"/"HIGH"/"CRITICAL", // 风险等级
    "invasionType": "具体的入侵类型描述", // 例如："SSH暴力破解", "SQL注入攻击", "勒索软件感染"等
    "attackStage": "初始访问"/"执行"/"持久化"/"权限提升"/"防御规避"/"凭证访问"/"发现"/"横向移动"/"收集"/"命令与控制"/"数据渗透"/"影响", // MITRE ATT&CK框架阶段
    "tactics": ["使用的战术列表"], // MITRE ATT&CK战术
    "techniques": ["使用的技术列表"], // MITRE ATT&CK技术
    "evidence": ["支持结论的证据列表"], // 每条证据应包含源数据引用
    "falsePositiveAnalysis": "对误报可能性的分析" // 为什么这可能是/不是误报
  },
  "impact": {
    "affectedSystems": ["受影响的系统组件"],
    "potentialDamage": "潜在损害描述",
    "dataExposureRisk": "数据泄露风险评估",
    "persistenceRisk": "持久化风险评估", // 攻击者是否可能已建立持久访问
    "lateralMovementRisk": "横向移动风险评估" // 攻击者是否可能已移动到其他系统
  },
  "recommendations": {
    "immediate": ["立即执行的措施"], // 紧急响应措施
    "shortTerm": ["短期措施"],      // 24-48小时内执行的措施
    "longTerm": ["长期措施"]        // 长期安全强化措施
  },
  "chainOfThought": "你的思考过程" // 详细说明你的分析推理过程
}

请确保你的输出是有效的JSON格式，不要包含任何额外的文本或解释。
`,
      
      // 用户提示模板
      userPromptTemplate: `
# 安全数据分析请求

## 分析目标
请基于以下安全数据，分析是否存在入侵行为，并提供详细分析报告。

## 系统数据

### 1. 网络数据
- 活跃连接数: {{network.activeConnections}}
- 外部连接数: {{network.externalConnections}}
- 异常连接模式: {{network.anomalies}}
- 可疑IP地址: {{network.suspiciousIps}}

### 2. 系统活动
- 可疑进程: {{system.suspiciousProcesses}}
- 注册表变更: {{system.registryChanges}}
- 关键文件访问: {{system.criticalFileAccess}}
- 特权操作: {{system.privilegedOperations}}

### 3. 安全事件
- 认证事件: {{security.authenticationEvents}}
- 失败登录尝试: {{security.failedLogins}}
- 防火墙事件: {{security.firewallEvents}}
- 告警信息: {{security.alerts}}

### 4. 日志数据
- 错误日志: {{logs.errors}}
- 警告日志: {{logs.warnings}}
- 安全日志: {{logs.securityEvents}}

## 上下文信息
- 分析时间: {{context.timestamp}}
- 系统类型: {{context.systemType}}
- 最近更新: {{context.lastUpdated}}
- 历史威胁情报: {{context.threatIntelligence}}

## 请根据上述数据提供完整的入侵分析报告
`,
      
      // 追问提示模板
      followUpTemplate: `
# 分析追问

## 当前分析结果
之前的分析: {{previousAnalysis}}

## 新数据
{{newData}}

## 分析任务
请基于新提供的数据，更新你的分析结果。如果你之前的结论需要修改，请说明原因。
请保持与之前相同的输出格式。
`
    };
  }

  // 初始化示例库
  initializeExamples() {
    return [
      {
        // SSH暴力破解示例
        type: 'ssh_brute_force',
        input: {
          network: {
            suspiciousIps: ['198.51.100.73'],
            activeConnections: 34,
            externalConnections: 12
          },
          security: {
            failedLogins: 27,
            authenticationEvents: [
              { username: 'root', ip: '198.51.100.73', timestamp: '2023-06-15T14:32:11', success: false },
              { username: 'admin', ip: '198.51.100.73', timestamp: '2023-06-15T14:32:15', success: false },
              { username: 'user1', ip: '198.51.100.73', timestamp: '2023-06-15T14:32:20', success: false }
            ]
          },
          logs: {
            securityEvents: [
              'Failed password for root from 198.51.100.73 port 45687 ssh2',
              'Failed password for admin from 198.51.100.73 port 45687 ssh2'
            ]
          }
        },
        output: {
          analysis: {
            isInvasion: true,
            confidence: 0.95,
            riskLevel: 'HIGH',
            invasionType: 'SSH暴力破解攻击',
            attackStage: '初始访问',
            tactics: ['初始访问'],
            techniques: ['暴力破解'],
            evidence: [
              '来自IP 198.51.100.73的27次失败登录尝试',
              'SSH日志中记录的多个不同用户名的失败认证尝试',
              '短时间内来自同一IP的多次连接尝试'
            ],
            falsePositiveAnalysis: '误报可能性极低，攻击模式符合典型的SSH暴力破解特征'
          },
          impact: {
            affectedSystems: ['SSH服务'],
            potentialDamage: '未授权的系统访问',
            dataExposureRisk: '中等',
            persistenceRisk: '低',
            lateralMovementRisk: '低'
          },
          recommendations: {
            immediate: [
              '立即阻止来自198.51.100.73的所有连接',
              '考虑临时限制SSH访问来源IP'
            ],
            shortTerm: [
              '实施登录失败锁定机制',
              '更改所有系统密码',
              '检查是否有成功的入侵迹象'
            ],
            longTerm: [
              '禁用密码认证，改用SSH密钥认证',
              '更改SSH默认端口',
              '实施IP白名单访问控制'
            ]
          }
        }
      },
      {
        // 恶意软件感染示例
        type: 'malware_infection',
        input: {
          system: {
            suspiciousProcesses: [
              { name: 'svch0st.exe', path: 'C:\\Windows\\Temp\\', commandLine: 'svch0st.exe -hidden -net' },
              { name: 'rundll32.exe', path: 'C:\\Windows\\System32\\', commandLine: 'rundll32.exe shell32.dll,Control_RunDLL C:\\Users\\temp\\AppData\\Local\\Temp\\update.dll' }
            ],
            registryChanges: [
              { key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', value: 'WindowsUpdate', data: 'C:\\Windows\\Temp\\svch0st.exe' }
            ],
            criticalFileAccess: [
              { file: 'C:\\Windows\\System32\\drivers\\etc\\hosts', process: 'svch0st.exe', action: 'WRITE' }
            ]
          },
          network: {
            anomalies: [
              '异常的DNS请求到unknown-domain.com',
              '向可疑IP 203.0.113.42的定期加密通信'
            ]
          },
          logs: {
            securityEvents: [
              '检测到可疑进程svch0st.exe修改hosts文件',
              '检测到进程svch0st.exe建立异常网络连接'
            ]
          }
        },
        output: {
          analysis: {
            isInvasion: true,
            confidence: 0.98,
            riskLevel: 'CRITICAL',
            invasionType: '恶意软件感染',
            attackStage: '持久化',
            tactics: ['持久化', '命令与控制'],
            techniques: ['注册表运行项', '伪装系统进程', 'DLL侧加载', '命令与控制通道'],
            evidence: [
              '可疑进程svch0st.exe（注意是数字0而不是字母o）',
              '在临时目录中运行的可执行文件',
              '修改启动注册表项以实现持久化',
              '修改hosts文件可能用于DNS劫持',
              '与已知恶意IP的通信'
            ],
            falsePositiveAnalysis: '误报可能性极低，观察到多个恶意软件感染的典型特征'
          },
          impact: {
            affectedSystems: ['操作系统', '网络通信'],
            potentialDamage: '系统完全控制权丢失，数据泄露，勒索软件攻击风险',
            dataExposureRisk: '高',
            persistenceRisk: '高',
            lateralMovementRisk: '高'
          },
          recommendations: {
            immediate: [
              '立即隔离受感染系统',
              '终止可疑进程svch0st.exe和可疑的rundll32.exe进程',
              '断网以阻止数据外泄和命令控制通信'
            ],
            shortTerm: [
              '删除恶意文件和注册表项',
              '执行完整的恶意软件扫描',
              '重置所有凭据',
              '从已知良好备份恢复系统（如果可能）'
            ],
            longTerm: [
              '实施应用程序白名单',
              '加强端点保护解决方案',
              '定期系统备份',
              '用户安全意识培训'
            ]
          }
        }
      }
    ];
  }

  // 初始化知识库
  initializeKnowledgeBase() {
    return {
      attackPatterns: [
        {
          id: 'APT29',
          name: 'APT29 (Cozy Bear)',
          description: '俄罗斯国家支持的高级持续性威胁组织，以使用定制恶意软件和鱼叉式钓鱼著称',
          indicators: [
            '使用PowerShell进行编码命令执行',
            'WMI横向移动',
            '使用合法系统工具进行操作'
          ]
        },
        {
          id: 'ransomware_TTPs',
          name: '勒索软件战术技术',
          description: '典型勒索软件攻击的战术、技术和程序',
          indicators: [
            '初始访问通常通过钓鱼邮件或漏洞利用',
            '使用PsExec或WMI进行横向移动',
            '加密前会关闭安全软件和备份服务',
            '建立持久性机制如计划任务或启动项',
            '大量文件系统活动和加密操作'
          ]
        }
      ],
      mitreAttck: [
        {
          id: 'T1059',
          name: '命令和脚本解释器',
          description: '使用命令和脚本解释器执行代码',
          subtechniques: ['PowerShell', '命令提示符', 'WMI', 'Python']
        },
        {
          id: 'T1078',
          name: '有效的账户',
          description: '使用合法用户账户进行身份验证',
          subtechniques: ['默认账户', '域账户', '本地账户', '服务账户']
        },
        {
          id: 'T1547',
          name: '启动项和服务',
          description: '通过修改启动项或服务实现持久化',
          subtechniques: ['注册表运行项', '计划任务', '系统服务', 'WMI事件订阅']
        }
      ],
      iocTypes: [
        {
          type: 'IP',
          description: '已知恶意的IP地址',
          example: '198.51.100.1'
        },
        {
          type: 'Domain',
          description: '已知恶意的域名',
          example: 'malicious-domain.com'
        },
        {
          type: 'Hash',
          description: '恶意文件的哈希值',
          example: 'a1b2c3d4e5f6...'
        },
        {
          type: 'YARA',
          description: '用于恶意软件检测的模式规则',
          example: '规则定义'
        }
      ]
    };
  }

  // 主分析方法
  async analyze(data, conversationId = null) {
    try {
      this.logger.info('开始LLM入侵行为分析...');
      
      // 准备分析数据
      const preparedData = this.prepareAnalysisData(data);
      
      // 生成分析提示
      const prompt = await this.generateAnalysisPrompt(preparedData, conversationId);
      
      // 调用模型引擎进行分析
      const analysisResult = await this.callModel(prompt);
      
      // 验证和解析结果
      const parsedResult = this.parseAnalysisResult(analysisResult);
      
      // 保存分析历史
      this.saveAnalysisHistory(data, parsedResult, conversationId);
      
      return parsedResult;
    } catch (error) {
      this.logger.error('LLM入侵分析失败:', error);
      return this.getFallbackAnalysis(data, error);
    }
  }

  // 准备分析数据
  prepareAnalysisData(data) {
    // 数据标准化和预处理
    return {
      network: {
        activeConnections: data.network?.activeConnections || 0,
        externalConnections: data.network?.externalConnections || 0,
        anomalies: this.summarizeNetworkAnomalies(data.network?.anomalies),
        suspiciousIps: this.extractSuspiciousIps(data)
      },
      system: {
        suspiciousProcesses: this.summarizeProcesses(data.system?.suspiciousProcesses || data.system?.processes),
        registryChanges: this.summarizeRegistryChanges(data.system?.registryChanges),
        criticalFileAccess: this.summarizeFileAccess(data.system?.fileSystem?.criticalFileAccess),
        privilegedOperations: this.summarizePrivilegedOperations(data.system?.userActivity?.privilegedOperations)
      },
      security: {
        authenticationEvents: this.summarizeAuthEvents(data.securityEvents?.authentication),
        failedLogins: this.countFailedLogins(data),
        firewallEvents: this.summarizeFirewallEvents(data.securityEvents?.firewall),
        alerts: this.summarizeAlerts(data)
      },
      logs: {
        errors: this.summarizeLogs(data.logs?.system?.filter(log => log.level === 'ERROR')),
        warnings: this.summarizeLogs(data.logs?.system?.filter(log => log.level === 'WARNING')),
        securityEvents: this.summarizeLogs(data.logs?.security)
      },
      context: {
        timestamp: new Date().toISOString(),
        systemType: 'Web安全系统',
        lastUpdated: new Date().toISOString(),
        threatIntelligence: this.getRelevantThreatIntelligence(data)
      }
    };
  }

  // 生成分析提示
  async generateAnalysisPrompt(preparedData, conversationId) {
    let prompt = {
      system: this.promptTemplates.systemPrompt,
      user: ''
    };

    // 构建用户提示
    let userPrompt = this.promptTemplates.userPromptTemplate;
    
    // 替换模板变量
    userPrompt = this.replaceTemplateVariables(userPrompt, preparedData);
    
    // 如果是对话的后续部分，使用追问模板
    if (conversationId && this.conversationContexts.has(conversationId)) {
      const context = this.conversationContexts.get(conversationId);
      userPrompt = this.promptTemplates.followUpTemplate
        .replace('{{previousAnalysis}}', JSON.stringify(context.lastAnalysis))
        .replace('{{newData}}', JSON.stringify(preparedData));
    }
    
    // 添加少样本学习示例
    if (this.config.enableFewShotLearning) {
      const relevantExamples = this.getRelevantExamples(preparedData);
      userPrompt = this.addFewShotExamples(userPrompt, relevantExamples);
    }
    
    // 添加RAG知识增强
    if (this.config.enableRAG) {
      const relevantKnowledge = this.retrieveRelevantKnowledge(preparedData);
      userPrompt = this.addRetrievalKnowledge(userPrompt, relevantKnowledge);
    }
    
    // 如果启用链式思考，添加相关提示
    if (this.config.enableChainOfThought) {
      userPrompt += "\n\n请在分析中包含详细的思考过程，解释你的推理和结论依据。";
    }
    
    prompt.user = userPrompt;
    return prompt;
  }

  // 调用大模型
  async callModel(prompt) {
    try {
      if (!this.modelEngine || typeof this.modelEngine.analyzeSituation !== 'function') {
        throw new Error('模型引擎不可用');
      }
      
      const result = await this.modelEngine.analyzeSituation(
        prompt,
        {
          taskType: 'invasion_detection',
          timeout: this.config.timeout,
          maxRetries: this.config.maxRetries,
          modelName: this.config.modelName,
          maxTokens: this.config.maxTokens,
          temperature: this.config.temperature
        }
      );
      
      if (!result || !result.success || !result.data) {
        throw new Error('模型返回无效结果');
      }
      
      return result.data;
    } catch (error) {
      this.logger.error('调用大模型失败:', error);
      throw error;
    }
  }

  // 解析分析结果
  parseAnalysisResult(result) {
    try {
      // 确保结果是有效的JSON
      let parsed;
      if (typeof result === 'string') {
        // 尝试从文本中提取JSON
        const jsonMatch = result.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          parsed = JSON.parse(jsonMatch[0]);
        } else {
          throw new Error('无法从响应中提取JSON');
        }
      } else {
        parsed = result;
      }
      
      // 验证必要字段
      if (!parsed.analysis || parsed.analysis.isInvasion === undefined) {
        throw new Error('分析结果缺少必要字段');
      }
      
      // 规范化输出格式
      return {
        ...parsed,
        timestamp: new Date(),
        rawResult: result
      };
    } catch (error) {
      this.logger.error('解析模型响应失败:', error);
      throw new Error(`无效的分析结果格式: ${error.message}`);
    }
  }

  // 保存分析历史
  saveAnalysisHistory(originalData, analysisResult, conversationId) {
    const historyEntry = {
      timestamp: new Date(),
      dataSummary: this.generateDataSummary(originalData),
      result: analysisResult,
      conversationId
    };
    
    this.analysisHistory.push(historyEntry);
    
    // 限制历史记录大小
    if (this.analysisHistory.length > 100) {
      this.analysisHistory.shift();
    }
    
    // 更新对话上下文
    if (conversationId) {
      let context = this.conversationContexts.get(conversationId) || {
        conversationId,
        history: []
      };
      
      context.lastAnalysis = analysisResult;
      context.history.push(historyEntry);
      
      // 限制上下文大小
      if (context.history.length > this.config.contextSize) {
        context.history.shift();
      }
      
      this.conversationContexts.set(conversationId, context);
    }
  }

  // 获取备用分析结果（当LLM不可用时）
  getFallbackAnalysis(data, error) {
    this.logger.warn('使用备用分析逻辑');
    
    // 简单的基于规则的备用分析
    const failedLogins = this.countFailedLogins(data);
    const suspiciousProcesses = data.system?.processes?.filter(p => this.isProcessSuspicious(p)) || [];
    const registryChanges = data.system?.registryChanges?.length || 0;
    const highSeverityAlerts = this.countHighSeverityAlerts(data);
    
    let isInvasion = false;
    let riskLevel = 'LOW';
    let invasionType = 'UNKNOWN';
    
    if (failedLogins > 10) {
      isInvasion = true;
      riskLevel = 'HIGH';
      invasionType = '可能的暴力破解攻击';
    } else if (suspiciousProcesses.length > 0 && registryChanges > 0) {
      isInvasion = true;
      riskLevel = 'CRITICAL';
      invasionType = '可能的恶意软件感染';
    } else if (highSeverityAlerts > 3) {
      isInvasion = true;
      riskLevel = 'MEDIUM';
      invasionType = '检测到可疑活动';
    }
    
    return {
      analysis: {
        isInvasion,
        confidence: 0.6, // 备用分析的置信度较低
        riskLevel,
        invasionType,
        attackStage: '未知',
        tactics: [],
        techniques: [],
        evidence: [
          failedLogins > 10 ? `${failedLogins}次失败登录尝试` : '',
          suspiciousProcesses.length > 0 ? `${suspiciousProcesses.length}个可疑进程` : '',
          registryChanges > 0 ? `${registryChanges}个注册表变更` : '',
          highSeverityAlerts > 0 ? `${highSeverityAlerts}个高严重性告警` : ''
        ].filter(Boolean),
        falsePositiveAnalysis: '此分析基于备用逻辑，建议进一步人工检查'
      },
      impact: {
        affectedSystems: ['未知'],
        potentialDamage: '需要进一步分析确定',
        dataExposureRisk: '未知',
        persistenceRisk: '未知',
        lateralMovementRisk: '未知'
      },
      recommendations: {
        immediate: ['执行完整的安全扫描', '检查系统日志获取更多信息'],
        shortTerm: ['考虑隔离系统进行深度检查'],
        longTerm: ['调查LLM分析失败原因', '加强监控']
      },
      fallbackUsed: true,
      fallbackReason: error.message
    };
  }

  // 辅助方法：替换模板变量
  replaceTemplateVariables(template, data) {
    let result = template;
    
    // 递归替换所有变量
    const replaceNestedVariables = (obj, prefix = '') => {
      for (const [key, value] of Object.entries(obj)) {
        const varName = `${prefix}{{${key}}}`;
        if (result.includes(varName)) {
          result = result.replace(varName, this.formatValueForTemplate(value));
        }
        
        if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
          replaceNestedVariables(value, `${prefix}${key}.`);
        }
      }
    };
    
    replaceNestedVariables(data);
    return result;
  }

  // 辅助方法：格式化值用于模板
  formatValueForTemplate(value) {
    if (value === null || value === undefined) return '未知';
    
    if (Array.isArray(value)) {
      return value.length > 0 ? JSON.stringify(value.slice(0, 5)) + (value.length > 5 ? '...' : '') : '无';
    }
    
    if (typeof value === 'object') {
      return JSON.stringify(value);
    }
    
    return String(value);
  }

  // 获取相关示例
  getRelevantExamples(preparedData) {
    const examples = [];
    
    // 基于数据特征匹配合适的示例
    if (preparedData.security.failedLogins > 5) {
      const bruteForceExample = this.examples.find(ex => ex.type === 'ssh_brute_force');
      if (bruteForceExample) examples.push(bruteForceExample);
    }
    
    if (preparedData.system.suspiciousProcesses.length > 0 && 
        preparedData.system.registryChanges.length > 0) {
      const malwareExample = this.examples.find(ex => ex.type === 'malware_infection');
      if (malwareExample) examples.push(malwareExample);
    }
    
    return examples.slice(0, 2); // 最多使用2个示例
  }

  // 添加少样本学习示例
  addFewShotExamples(prompt, examples) {
    if (examples.length === 0) return prompt;
    
    let examplesText = "\n\n## 分析示例\n\n";
    
    examples.forEach((example, index) => {
      examplesText += `### 示例 ${index + 1}\n`;
      examplesText += "输入数据:\n";
      examplesText += JSON.stringify(example.input, null, 2) + "\n\n";
      examplesText += "分析结果:\n";
      examplesText += JSON.stringify(example.output, null, 2) + "\n\n";
    });
    
    return examplesText + prompt;
  }

  // 检索相关知识
  retrieveRelevantKnowledge(preparedData) {
    const relevantKnowledge = [];
    
    // 基于数据特征检索相关知识
    if (preparedData.system.suspiciousProcesses.some(p => p.includes('PowerShell'))) {
      const psTechnique = this.knowledgeBase.mitreAttck.find(t => 
        t.id === 'T1059' && t.subtechniques.includes('PowerShell')
      );
      if (psTechnique) relevantKnowledge.push(psTechnique);
    }
    
    if (preparedData.system.registryChanges.some(c => c.includes('Run') || c.includes('Startup'))) {
      const persistenceTechnique = this.knowledgeBase.mitreAttck.find(t => 
        t.id === 'T1547'
      );
      if (persistenceTechnique) relevantKnowledge.push(persistenceTechnique);
    }
    
    // 检查是否有勒索软件特征
    const hasRansomwareIndicators = 
      preparedData.system.criticalFileAccess.length > 100 ||
      preparedData.security.alerts.some(a => a.includes('encryption'));
      
    if (hasRansomwareIndicators) {
      const ransomwareInfo = this.knowledgeBase.attackPatterns.find(p => 
        p.name.includes('ransomware')
      );
      if (ransomwareInfo) relevantKnowledge.push(ransomwareInfo);
    }
    
    return relevantKnowledge;
  }

  // 添加检索到的知识
  addRetrievalKnowledge(prompt, knowledge) {
    if (knowledge.length === 0) return prompt;
    
    let knowledgeText = "\n\n## 相关安全知识\n\n";
    
    knowledge.forEach(item => {
      knowledgeText += `### ${item.id || ''} ${item.name}\n`;
      knowledgeText += `${item.description}\n\n`;
      
      if (item.indicators) {
        knowledgeText += "指示特征:\n";
        item.indicators.forEach(indicator => {
          knowledgeText += `- ${indicator}\n`;
        });
        knowledgeText += "\n";
      }
      
      if (item.subtechniques) {
        knowledgeText += "子技术:\n";
        item.subtechniques.forEach(technique => {
          knowledgeText += `- ${technique}\n`;
        });
        knowledgeText += "\n";
      }
    });
    
    return knowledgeText + prompt;
  }

  // 生成数据摘要
  generateDataSummary(data) {
    return {
      network: {
        connections: data.network?.connections?.length || 0,
        anomalies: data.network?.anomalies?.length || 0
      },
      system: {
        processes: data.system?.processes?.length || 0,
        registryChanges: data.system?.registryChanges?.length || 0
      },
      security: {
        failedLogins: this.countFailedLogins(data),
        alerts: this.countHighSeverityAlerts(data)
      }
    };
  }

  // 辅助方法：统计失败登录次数
  countFailedLogins(data) {
    let count = 0;
    
    if (data.securityEvents?.authentication) {
      count += data.securityEvents.authentication.filter(auth => !auth.success).length;
    }
    
    if (data.system?.userActivity?.failedLogins) {
      count += data.system.userActivity.failedLogins.length;
    }
    
    return count;
  }

  // 辅助方法：统计高严重性告警
  countHighSeverityAlerts(data) {
    let count = 0;
    
    if (data.securityEvents?.ids) {
      count += data.securityEvents.ids.filter(alert => 
        alert.severity === 'HIGH' || alert.severity === 'CRITICAL'
      ).length;
    }
    
    if (data.logs?.security) {
      count += data.logs.security.filter(log => 
        log.level === 'ERROR' || log.level === 'CRITICAL'
      ).length;
    }
    
    return count;
  }

  // 辅助方法：检查进程是否可疑
  isProcessSuspicious(process) {
    const suspiciousPatterns = [
      'cmd.exe.*\\/c', 
      'powershell.exe.*-enc', 
      'wscript.exe', 
      'cscript.exe',
      'regsvr32.exe', 
      'mshta.exe', 
      'bitsadmin.exe', 
      'certutil.exe',
      'mimikatz', 
      'pwdump', 
      'procdump'
    ];
    
    const processStr = `${process.name || ''} ${process.commandLine || ''}`.toLowerCase();
    return suspiciousPatterns.some(pattern => 
      new RegExp(pattern, 'i').test(processStr)
    );
  }

  // 辅助方法：总结网络异常
  summarizeNetworkAnomalies(anomalies) {
    if (!anomalies || anomalies.length === 0) return '无';
    
    // 按类型分组统计
    const typeCounts = {};
    anomalies.forEach(anomaly => {
      const type = anomaly.type || 'Unknown';
      typeCounts[type] = (typeCounts[type] || 0) + 1;
    });
    
    return Object.entries(typeCounts)
      .map(([type, count]) => `${type}: ${count}次`)
      .join(', ');
  }

  // 辅助方法：提取可疑IP
  extractSuspiciousIps(data) {
    const suspiciousIps = new Set();
    
    // 从安全事件中提取
    if (data.securityEvents?.firewall) {
      data.securityEvents.firewall
        .filter(event => event.action === 'BLOCK')
        .forEach(event => {
          if (event.sourceIp) suspiciousIps.add(event.sourceIp);
        });
    }
    
    // 从失败登录中提取
    if (data.securityEvents?.authentication) {
      data.securityEvents.authentication
        .filter(auth => !auth.success)
        .forEach(auth => {
          if (auth.ip) suspiciousIps.add(auth.ip);
        });
    }
    
    return Array.from(suspiciousIps).slice(0, 10); // 限制数量
  }

  // 辅助方法：总结进程
  summarizeProcesses(processes) {
    if (!processes || processes.length === 0) return [];
    
    // 筛选和格式化可疑进程
    return processes
      .filter(process => this.isProcessSuspicious(process))
      .slice(0, 5)
      .map(process => `${process.name}${process.path ? ` (${process.path})` : ''}`);
  }

  // 辅助方法：总结注册表变更
  summarizeRegistryChanges(changes) {
    if (!changes || changes.length === 0) return [];
    
    // 筛选关键注册表变更
    return changes
      .filter(change => 
        change.key?.includes('Run') || 
        change.key?.includes('Startup') ||
        change.key?.includes('Services')
      )
      .slice(0, 5)
      .map(change => `${change.key}: ${change.oldValue || ''} -> ${change.newValue || ''}`);
  }

  // 辅助方法：总结文件访问
  summarizeFileAccess(accessEvents) {
    if (!accessEvents || accessEvents.length === 0) return [];
    
    return accessEvents
      .slice(0, 5)
      .map(event => `${event.action}: ${event.file} by ${event.process}`);
  }

  // 辅助方法：总结特权操作
  summarizePrivilegedOperations(operations) {
    if (!operations || operations.length === 0) return [];
    
    return operations
      .slice(0, 5)
      .map(op => `${op.operation} by ${op.user}`);
  }

  // 辅助方法：总结认证事件
  summarizeAuthEvents(events) {
    if (!events || events.length === 0) return [];
    
    // 统计不同结果的认证事件
    const successCount = events.filter(e => e.success).length;
    const failureCount = events.filter(e => !e.success).length;
    
    return [`成功: ${successCount}次`, `失败: ${failureCount}次`];
  }

  // 辅助方法：总结防火墙事件
  summarizeFirewallEvents(events) {
    if (!events || events.length === 0) return [];
    
    // 统计不同操作的防火墙事件
    const blockCount = events.filter(e => e.action === 'BLOCK').length;
    const allowCount = events.filter(e => e.action === 'ALLOW').length;
    
    return [`阻止: ${blockCount}次`, `允许: ${allowCount}次`];
  }

  // 辅助方法：总结告警
  summarizeAlerts(data) {
    const alerts = [];
    
    // 从安全事件中收集告警
    if (data.securityEvents?.ids) {
      data.securityEvents.ids.slice(0, 5).forEach(alert => {
        alerts.push(`${alert.severity}: ${alert.type}`);
      });
    }
    
    return alerts;
  }

  // 辅助方法：总结日志
  summarizeLogs(logs) {
    if (!logs || logs.length === 0) return '无';
    
    return logs
      .slice(0, 5)
      .map(log => log.message || log.description || '未知日志')
      .join('; ');
  }

  // 获取相关威胁情报
  getRelevantThreatIntelligence(data) {
    const intel = [];
    
    // 检查是否有已知攻击模式的特征
    const suspiciousIps = this.extractSuspiciousIps(data);
    if (suspiciousIps.length > 0) {
      intel.push(`检测到 ${suspiciousIps.length} 个可疑IP地址`);
    }
    
    if (this.countFailedLogins(data) > 10) {
      intel.push('观察到可能的暴力破解攻击模式');
    }
    
    const suspiciousProcesses = data.system?.processes?.filter(p => this.isProcessSuspicious(p)) || [];
    if (suspiciousProcesses.length > 0) {
      intel.push(`检测到 ${suspiciousProcesses.length} 个可疑进程`);
    }
    
    return intel.length > 0 ? intel.join(', ') : '无特定威胁情报';
  }

  // 更新配置
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    return this.config;
  }

  // 获取分析历史
  getAnalysisHistory(limit = 10) {
    return this.analysisHistory.slice(-limit).reverse();
  }

  // 获取统计信息
  getStatistics() {
    const totalAnalyses = this.analysisHistory.length;
    const invasionsDetected = this.analysisHistory.filter(h => h.result.analysis?.isInvasion).length;
    const fallbackUsed = this.analysisHistory.filter(h => h.result.fallbackUsed).length;
    
    return {
      totalAnalyses,
      invasionsDetected,
      fallbackUsed,
      detectionRate: totalAnalyses > 0 ? invasionsDetected / totalAnalyses : 0,
      successRate: totalAnalyses > 0 ? (totalAnalyses - fallbackUsed) / totalAnalyses : 0
    };
  }

  // 清除分析历史
  clearHistory() {
    this.analysisHistory = [];
    this.conversationContexts.clear();
    return true;
  }

  // 导出分析报告
  exportReport(analysisId) {
    const analysis = this.analysisHistory.find(h => h.timestamp.getTime() === analysisId);
    if (!analysis) return null;
    
    return {
      reportId: Date.now(),
      generatedAt: new Date(),
      analysisTimestamp: analysis.timestamp,
      dataSummary: analysis.dataSummary,
      result: analysis.result
    };
  }
}

export default LLMInvasionAnalyzer;