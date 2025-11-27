// 系统行为监控器 - 负责收集和分析系统级别的行为数据，如进程活动、系统调用、资源使用等
class SystemBehaviorMonitor {
  constructor(config = {}) {
    this.logger = window.globalLogger || console;
    
    // 配置项
    this.config = {
      // 监控设置
      enabled: true,
      
      // 进程监控
      monitorProcesses: true,
      processScanInterval: 5000, // 5秒
      trackProcessLifetime: true,
      monitorProcessDetails: true,
      
      // 系统调用监控
      monitorSystemCalls: true,
      systemCallBufferSize: 10000,
      
      // 资源使用监控
      monitorCPU: true,
      monitorMemory: true,
      monitorDisk: true,
      monitorNetworkStats: true,
      resourceScanInterval: 2000, // 2秒
      
      // 文件系统监控
      monitorFileAccess: true,
      monitorFileModifications: true,
      monitoredFilePaths: [],
      
      // 注册表监控（Windows系统）
      monitorRegistry: true,
      monitoredRegistryPaths: [],
      
      // 用户活动监控
      monitorUserActivity: true,
      monitorLoginAttempts: true,
      
      // 服务监控
      monitorServices: true,
      serviceScanInterval: 60000, // 1分钟
      
      // 异常检测
      enableAnomalyDetection: true,
      baselineUpdateInterval: 3600000, // 1小时
      
      // 警报设置
      alertOnAnomalies: true,
      alertOnHighResourceUsage: true,
      
      // 阈值设置
      cpuThreshold: 80, // 80%
      memoryThreshold: 85, // 85%
      diskSpaceThreshold: 90, // 90%
      processCountThreshold: 500,
      
      // 集成设置
      reportToInvasionDetector: true,
      
      ...config
    };
    
    // 状态和数据存储
    this.isRunning = false;
    this.monitoringStartTime = null;
    
    // 进程数据
    this.processSnapshot = new Map();
    this.processHistory = [];
    this.processBaseline = new Map();
    
    // 系统调用数据
    this.systemCalls = [];
    this.systemCallStats = new Map();
    
    // 资源使用数据
    this.resourceHistory = [];
    this.resourceBaseline = {
      cpu: [],
      memory: [],
      disk: [],
      network: []
    };
    
    // 文件系统事件
    this.fileEvents = [];
    
    // 注册表事件
    this.registryEvents = [];
    
    // 用户活动数据
    this.userSessions = new Map();
    this.loginAttempts = [];
    
    // 服务数据
    this.serviceSnapshot = new Map();
    this.serviceChanges = [];
    
    // 基线数据
    this.systemBaselines = this.initializeSystemBaselines();
    
    // 异常记录
    this.anomalies = [];
    
    // 监控计时器
    this.timers = {};
    
    // 事件监听器
    this.listeners = new Map();
    
    // 初始化
    this.initialize();
  }

  // 初始化监控器
  initialize() {
    try {
      // 注册到全局对象
      if (typeof window !== 'undefined' && !window.systemBehaviorMonitor) {
        window.systemBehaviorMonitor = this;
      }
      
      this.logger.info('系统行为监控器初始化完成');
      return true;
    } catch (error) {
      this.logger.error('初始化系统行为监控器失败:', error);
      return false;
    }
  }

  // 初始化系统基线
  initializeSystemBaselines() {
    return {
      processNames: new Map(),
      processPaths: new Map(),
      processUserAccounts: new Map(),
      processCommandLines: new Map(),
      serviceNames: new Map(),
      serviceStates: new Map(),
      resourceUsage: {
        cpu: { min: 0, max: 100, avg: 0 },
        memory: { min: 0, max: 100, avg: 0 },
        disk: { min: 0, max: 100, avg: 0 }
      },
      systemCallFrequencies: new Map(),
      fileAccessPatterns: new Map(),
      loginPatterns: {
        hours: new Array(24).fill(0),
        successRate: 0.9
      },
      lastUpdated: new Date()
    };
  }

  // 启动监控
  start() {
    try {
      if (this.isRunning) {
        this.logger.warn('系统行为监控已在运行');
        return false;
      }
      
      this.isRunning = true;
      this.monitoringStartTime = new Date();
      
      // 启动各种监控
      this.startProcessMonitoring();
      this.startResourceMonitoring();
      this.startServiceMonitoring();
      this.startFileSystemMonitoring();
      this.startRegistryMonitoring();
      this.startUserActivityMonitoring();
      this.startSystemCallMonitoring();
      
      // 启动基线更新
      if (this.config.enableAnomalyDetection) {
        this.startBaselineUpdates();
      }
      
      this.logger.info('系统行为监控已启动');
      this.notify('monitoringStarted', { startTime: this.monitoringStartTime });
      
      return true;
    } catch (error) {
      this.logger.error('启动系统行为监控失败:', error);
      this.isRunning = false;
      return false;
    }
  }

  // 停止监控
  stop() {
    try {
      if (!this.isRunning) {
        this.logger.warn('系统行为监控未在运行');
        return false;
      }
      
      this.isRunning = false;
      
      // 停止所有计时器
      this.clearAllTimers();
      
      // 清理资源
      this.cleanupResources();
      
      this.logger.info('系统行为监控已停止');
      this.notify('monitoringStopped', { 
        endTime: new Date(),
        totalRuntime: new Date() - this.monitoringStartTime
      });
      
      return true;
    } catch (error) {
      this.logger.error('停止系统行为监控失败:', error);
      return false;
    }
  }

  // 启动进程监控
  startProcessMonitoring() {
    if (!this.config.monitorProcesses) return;
    
    this.logger.info('启动进程监控');
    
    // 初始扫描
    this.scanProcesses();
    
    // 设置定期扫描
    this.timers.processScan = setInterval(() => {
      if (this.isRunning) {
        this.scanProcesses();
      }
    }, this.config.processScanInterval);
  }

  // 扫描进程
  scanProcesses() {
    try {
      // 获取当前进程列表
      const currentProcesses = this.getProcessList();
      const currentProcessMap = new Map();
      
      // 构建当前进程映射
      currentProcesses.forEach(process => {
        currentProcessMap.set(process.pid, process);
      });
      
      // 检测新进程
      this.detectNewProcesses(currentProcessMap);
      
      // 检测终止的进程
      this.detectTerminatedProcesses(currentProcessMap);
      
      // 检测进程状态变化
      this.detectProcessChanges(currentProcessMap);
      
      // 更新进程快照
      this.processSnapshot = currentProcessMap;
      
      // 限制历史记录大小
      this.limitProcessHistory();
      
    } catch (error) {
      this.logger.error('扫描进程失败:', error);
    }
  }

  // 获取进程列表
  getProcessList() {
    try {
      // 在真实环境中，这里应该调用系统API获取进程列表
      // 返回模拟的进程数据
      return this.generateMockProcessList();
    } catch (error) {
      this.logger.error('获取进程列表失败:', error);
      return [];
    }
  }

  // 检测新进程
  detectNewProcesses(currentProcesses) {
    for (const [pid, process] of currentProcesses.entries()) {
      if (!this.processSnapshot.has(pid)) {
        // 发现新进程
        this.onProcessCreated(process);
      }
    }
  }

  // 检测终止的进程
  detectTerminatedProcesses(currentProcesses) {
    for (const [pid, process] of this.processSnapshot.entries()) {
      if (!currentProcesses.has(pid)) {
        // 进程已终止
        this.onProcessTerminated(process);
      }
    }
  }

  // 检测进程变化
  detectProcessChanges(currentProcesses) {
    for (const [pid, currentProcess] of currentProcesses.entries()) {
      const oldProcess = this.processSnapshot.get(pid);
      if (oldProcess) {
        // 检查进程变化
        this.checkProcessChanges(oldProcess, currentProcess);
      }
    }
  }

  // 检查进程变化
  checkProcessChanges(oldProcess, newProcess) {
    const changes = [];
    
    // 检查优先级变化
    if (oldProcess.priority !== newProcess.priority) {
      changes.push({ type: 'priority', old: oldProcess.priority, new: newProcess.priority });
    }
    
    // 检查CPU使用率变化
    if (Math.abs(oldProcess.cpuUsage - newProcess.cpuUsage) > 20) {
      changes.push({ type: 'cpuUsage', old: oldProcess.cpuUsage, new: newProcess.cpuUsage });
    }
    
    // 检查内存使用变化
    if (Math.abs(oldProcess.memoryUsage - newProcess.memoryUsage) > 100 * 1024 * 1024) { // 100MB
      changes.push({ type: 'memoryUsage', old: oldProcess.memoryUsage, new: newProcess.memoryUsage });
    }
    
    // 检查状态变化
    if (oldProcess.status !== newProcess.status) {
      changes.push({ type: 'status', old: oldProcess.status, new: newProcess.status });
    }
    
    if (changes.length > 0) {
      this.onProcessChanged(newProcess, changes);
    }
  }

  // 进程创建事件处理
  onProcessCreated(process) {
    // 记录进程创建
    const processEvent = {
      type: 'processCreated',
      process,
      timestamp: new Date()
    };
    
    this.processHistory.push(processEvent);
    
    // 检查进程是否可疑
    if (this.config.enableAnomalyDetection) {
      const isSuspicious = this.checkProcessSuspicious(process);
      if (isSuspicious) {
        this.onSuspiciousProcess(process, isSuspicious.reason);
      }
    }
    
    // 更新进程基线
    this.updateProcessBaseline(process);
    
    // 通知监听器
    this.notify('processCreated', processEvent);
  }

  // 进程终止事件处理
  onProcessTerminated(process) {
    // 计算进程生命周期
    const lifetime = new Date() - new Date(process.startTime);
    
    const processEvent = {
      type: 'processTerminated',
      process: {
        ...process,
        lifetime
      },
      timestamp: new Date()
    };
    
    this.processHistory.push(processEvent);
    
    // 检查异常终止
    if (this.config.enableAnomalyDetection) {
      this.checkAbnormalTermination(process);
    }
    
    // 通知监听器
    this.notify('processTerminated', processEvent);
  }

  // 进程变化事件处理
  onProcessChanged(process, changes) {
    const processEvent = {
      type: 'processChanged',
      process,
      changes,
      timestamp: new Date()
    };
    
    this.processHistory.push(processEvent);
    
    // 通知监听器
    this.notify('processChanged', processEvent);
  }

  // 可疑进程检测
  checkProcessSuspicious(process) {
    // 检查进程路径
    if (this.isSuspiciousProcessPath(process.path)) {
      return { reason: 'suspiciousPath', details: process.path };
    }
    
    // 检查进程名
    if (this.isSuspiciousProcessName(process.name)) {
      return { reason: 'suspiciousName', details: process.name };
    }
    
    // 检查命令行参数
    if (this.isSuspiciousCommandLine(process.commandLine)) {
      return { reason: 'suspiciousCommandLine', details: process.commandLine };
    }
    
    // 检查启动用户
    if (this.isSuspiciousUser(process.user)) {
      return { reason: 'suspiciousUser', details: process.user };
    }
    
    // 检查是否在基线中
    if (!this.isProcessInBaseline(process)) {
      return { reason: 'notInBaseline', details: process.name };
    }
    
    return null;
  }

  // 检查可疑进程路径
  isSuspiciousProcessPath(path) {
    const suspiciousPaths = [
      '\\temp\\', 
      '\\tmp\\', 
      '\\appdata\\local\\temp\\',
      '\\windows\\temp\\',
      '\\documents and settings\\',
      '\\recycler\\'
    ];
    
    return suspiciousPaths.some(suspiciousPath => 
      path.toLowerCase().includes(suspiciousPath)
    );
  }

  // 检查可疑进程名
  isSuspiciousProcessName(name) {
    const suspiciousNames = [
      'svch0st.exe', 'expl0rer.exe', 'csrsss.exe', 'winlog0n.exe', // 常见的恶意程序伪装名
      'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', // 脚本和命令行解释器
      'regsvr32.exe', 'rundll32.exe', 'mshta.exe' // 可执行脚本和DLL的程序
    ];
    
    return suspiciousNames.includes(name.toLowerCase());
  }

  // 检查可疑命令行
  isSuspiciousCommandLine(commandLine) {
    if (!commandLine) return false;
    
    const suspiciousPatterns = [
      'powershell -enc', 'powershell -encodedcommand',
      'cmd.exe /c', 'cmd.exe /k',
      'reg add', 'reg delete', 'reg modify',
      'format ', 'diskpart',
      'wmic process call create',
      'bitsadmin /transfer',
      'certutil -urlcache',
      '-nop', '-noni', '-w hidden'
    ];
    
    return suspiciousPatterns.some(pattern => 
      commandLine.toLowerCase().includes(pattern)
    );
  }

  // 检查可疑用户
  isSuspiciousUser(user) {
    const suspiciousUsers = ['system', 'administrator', 'nt authority\system'];
    return suspiciousUsers.includes(user.toLowerCase());
  }

  // 检查进程是否在基线中
  isProcessInBaseline(process) {
    // 如果基线为空，默认认为是正常的
    if (this.systemBaselines.processNames.size === 0) return true;
    
    return this.systemBaselines.processNames.has(process.name.toLowerCase());
  }

  // 可疑进程处理
  onSuspiciousProcess(process, reason) {
    const anomaly = {
      type: 'suspiciousProcess',
      process,
      reason,
      timestamp: new Date()
    };
    
    this.anomalies.push(anomaly);
    
    // 通知监听器
    this.notify('suspiciousProcess', anomaly);
    
    // 记录详细日志
    this.logger.warn('检测到可疑进程:', { processName: process.name, pid: process.pid, reason });
  }

  // 检查异常终止
  checkAbnormalTermination(process) {
    // 检查进程是否在短时间内启动和终止
    const startTime = new Date(process.startTime);
    const lifetime = new Date() - startTime;
    
    if (lifetime < 5000) { // 5秒内启动和终止
      const anomaly = {
        type: 'abnormalProcessTermination',
        process,
        reason: 'shortLifetime',
        lifetime,
        timestamp: new Date()
      };
      
      this.anomalies.push(anomaly);
      this.notify('abnormalProcessTermination', anomaly);
    }
  }

  // 更新进程基线
  updateProcessBaseline(process) {
    // 更新进程名基线
    const processName = process.name.toLowerCase();
    const currentCount = this.systemBaselines.processNames.get(processName) || 0;
    this.systemBaselines.processNames.set(processName, currentCount + 1);
    
    // 更新进程路径基线
    const processPath = process.path.toLowerCase();
    const pathCount = this.systemBaselines.processPaths.get(processPath) || 0;
    this.systemBaselines.processPaths.set(processPath, pathCount + 1);
    
    // 更新用户基线
    const userName = process.user.toLowerCase();
    const userCount = this.systemBaselines.processUserAccounts.get(userName) || 0;
    this.systemBaselines.processUserAccounts.set(userName, userCount + 1);
  }

  // 限制进程历史记录大小
  limitProcessHistory() {
    const maxHistorySize = 10000;
    if (this.processHistory.length > maxHistorySize) {
      this.processHistory = this.processHistory.slice(-maxHistorySize);
    }
  }

  // 启动资源监控
  startResourceMonitoring() {
    if (!this.config.monitorCPU && !this.config.monitorMemory && 
        !this.config.monitorDisk && !this.config.monitorNetworkStats) {
      return;
    }
    
    this.logger.info('启动资源使用监控');
    
    // 初始收集
    this.collectResourceUsage();
    
    // 设置定期收集
    this.timers.resourceMonitor = setInterval(() => {
      if (this.isRunning) {
        this.collectResourceUsage();
      }
    }, this.config.resourceScanInterval);
  }

  // 收集资源使用情况
  collectResourceUsage() {
    try {
      // 获取系统资源使用情况
      const resourceUsage = this.getSystemResourceUsage();
      
      // 记录资源使用历史
      this.resourceHistory.push(resourceUsage);
      
      // 限制历史记录大小
      this.limitResourceHistory();
      
      // 检查资源使用阈值
      this.checkResourceThresholds(resourceUsage);
      
      // 检查资源使用异常
      if (this.config.enableAnomalyDetection) {
        this.checkResourceUsageAnomalies(resourceUsage);
      }
      
      // 通知监听器
      this.notify('resourceUsageUpdated', resourceUsage);
      
    } catch (error) {
      this.logger.error('收集资源使用情况失败:', error);
    }
  }

  // 获取系统资源使用情况
  getSystemResourceUsage() {
    try {
      // 在真实环境中，这里应该调用系统API获取资源使用情况
      // 返回模拟的资源使用数据
      return this.generateMockResourceUsage();
    } catch (error) {
      this.logger.error('获取系统资源使用情况失败:', error);
      return this.getDefaultResourceUsage();
    }
  }

  // 检查资源使用阈值
  checkResourceThresholds(resourceUsage) {
    if (!this.config.alertOnHighResourceUsage) return;
    
    const alerts = [];
    
    // 检查CPU使用率
    if (this.config.monitorCPU && resourceUsage.cpu.usage > this.config.cpuThreshold) {
      alerts.push({
        type: 'highCpuUsage',
        value: resourceUsage.cpu.usage,
        threshold: this.config.cpuThreshold
      });
    }
    
    // 检查内存使用率
    if (this.config.monitorMemory && resourceUsage.memory.usage > this.config.memoryThreshold) {
      alerts.push({
        type: 'highMemoryUsage',
        value: resourceUsage.memory.usage,
        threshold: this.config.memoryThreshold
      });
    }
    
    // 检查磁盘空间
    if (this.config.monitorDisk && resourceUsage.disk.usedPercentage > this.config.diskSpaceThreshold) {
      alerts.push({
        type: 'lowDiskSpace',
        value: 100 - resourceUsage.disk.usedPercentage,
        threshold: 100 - this.config.diskSpaceThreshold
      });
    }
    
    // 检查进程数量
    if (resourceUsage.processCount > this.config.processCountThreshold) {
      alerts.push({
        type: 'highProcessCount',
        value: resourceUsage.processCount,
        threshold: this.config.processCountThreshold
      });
    }
    
    // 发送警报
    for (const alert of alerts) {
      const alertEvent = {
        ...alert,
        timestamp: new Date(),
        resourceUsage
      };
      
      this.notify('resourceThresholdExceeded', alertEvent);
      this.logger.warn(`资源使用警报: ${alert.type}`, { value: alert.value, threshold: alert.threshold });
    }
  }

  // 检查资源使用异常
  checkResourceUsageAnomalies(resourceUsage) {
    // 检查CPU使用异常
    if (this.config.monitorCPU && this.systemBaselines.resourceUsage.cpu.avg > 0) {
      const cpuAvg = this.systemBaselines.resourceUsage.cpu.avg;
      if (resourceUsage.cpu.usage > cpuAvg * 3) {
        this.reportResourceAnomaly('cpuUsageAnomaly', resourceUsage.cpu.usage, cpuAvg);
      }
    }
    
    // 检查内存使用异常
    if (this.config.monitorMemory && this.systemBaselines.resourceUsage.memory.avg > 0) {
      const memoryAvg = this.systemBaselines.resourceUsage.memory.avg;
      if (resourceUsage.memory.usage > memoryAvg * 2) {
        this.reportResourceAnomaly('memoryUsageAnomaly', resourceUsage.memory.usage, memoryAvg);
      }
    }
  }

  // 报告资源使用异常
  reportResourceAnomaly(type, current, baseline) {
    const anomaly = {
      type,
      current,
      baseline,
      deviation: current / baseline,
      timestamp: new Date()
    };
    
    this.anomalies.push(anomaly);
    this.notify('resourceAnomaly', anomaly);
  }

  // 限制资源历史记录大小
  limitResourceHistory() {
    const maxHistorySize = 3600; // 1小时，假设每2秒一个样本
    if (this.resourceHistory.length > maxHistorySize) {
      this.resourceHistory = this.resourceHistory.slice(-maxHistorySize);
    }
  }

  // 启动服务监控
  startServiceMonitoring() {
    if (!this.config.monitorServices) return;
    
    this.logger.info('启动服务监控');
    
    // 初始扫描
    this.scanServices();
    
    // 设置定期扫描
    this.timers.serviceScan = setInterval(() => {
      if (this.isRunning) {
        this.scanServices();
      }
    }, this.config.serviceScanInterval);
  }

  // 扫描服务
  scanServices() {
    try {
      // 获取当前服务列表
      const currentServices = this.getServiceList();
      const currentServiceMap = new Map();
      
      // 构建当前服务映射
      currentServices.forEach(service => {
        currentServiceMap.set(service.name, service);
      });
      
      // 检测新服务
      this.detectNewServices(currentServiceMap);
      
      // 检测服务状态变化
      this.detectServiceChanges(currentServiceMap);
      
      // 更新服务快照
      this.serviceSnapshot = currentServiceMap;
      
    } catch (error) {
      this.logger.error('扫描服务失败:', error);
    }
  }

  // 获取服务列表
  getServiceList() {
    try {
      // 在真实环境中，这里应该调用系统API获取服务列表
      // 返回模拟的服务数据
      return this.generateMockServiceList();
    } catch (error) {
      this.logger.error('获取服务列表失败:', error);
      return [];
    }
  }

  // 检测新服务
  detectNewServices(currentServices) {
    for (const [name, service] of currentServices.entries()) {
      if (!this.serviceSnapshot.has(name)) {
        // 发现新服务
        this.onServiceCreated(service);
      }
    }
  }

  // 检测服务变化
  detectServiceChanges(currentServices) {
    for (const [name, currentService] of currentServices.entries()) {
      const oldService = this.serviceSnapshot.get(name);
      if (oldService) {
        // 检查服务状态变化
        if (oldService.status !== currentService.status) {
          this.onServiceStatusChanged(currentService, oldService.status, currentService.status);
        }
        
        // 检查服务启动类型变化
        if (oldService.startType !== currentService.startType) {
          this.onServiceConfigChanged(currentService, 'startType', oldService.startType, currentService.startType);
        }
      }
    }
  }

  // 服务创建事件处理
  onServiceCreated(service) {
    const serviceEvent = {
      type: 'serviceCreated',
      service,
      timestamp: new Date()
    };
    
    this.serviceChanges.push(serviceEvent);
    
    // 检查服务是否可疑
    if (this.config.enableAnomalyDetection) {
      const isSuspicious = this.checkServiceSuspicious(service);
      if (isSuspicious) {
        this.onSuspiciousService(service, isSuspicious.reason);
      }
    }
    
    // 更新服务基线
    this.updateServiceBaseline(service);
    
    // 通知监听器
    this.notify('serviceCreated', serviceEvent);
  }

  // 服务状态变化事件处理
  onServiceStatusChanged(service, oldStatus, newStatus) {
    const serviceEvent = {
      type: 'serviceStatusChanged',
      service,
      oldStatus,
      newStatus,
      timestamp: new Date()
    };
    
    this.serviceChanges.push(serviceEvent);
    
    // 检查异常状态变化
    if (this.config.enableAnomalyDetection) {
      this.checkAbnormalServiceStatusChange(service, oldStatus, newStatus);
    }
    
    // 通知监听器
    this.notify('serviceStatusChanged', serviceEvent);
  }

  // 服务配置变化事件处理
  onServiceConfigChanged(service, configType, oldValue, newValue) {
    const serviceEvent = {
      type: 'serviceConfigChanged',
      service,
      configType,
      oldValue,
      newValue,
      timestamp: new Date()
    };
    
    this.serviceChanges.push(serviceEvent);
    
    // 通知监听器
    this.notify('serviceConfigChanged', serviceEvent);
  }

  // 检查可疑服务
  checkServiceSuspicious(service) {
    // 检查服务名
    if (this.isSuspiciousServiceName(service.name)) {
      return { reason: 'suspiciousName', details: service.name };
    }
    
    // 检查服务路径
    if (this.isSuspiciousServicePath(service.path)) {
      return { reason: 'suspiciousPath', details: service.path };
    }
    
    // 检查启动用户
    if (this.isSuspiciousServiceUser(service.user)) {
      return { reason: 'suspiciousUser', details: service.user };
    }
    
    // 检查是否在基线中
    if (!this.isServiceInBaseline(service)) {
      return { reason: 'notInBaseline', details: service.name };
    }
    
    return null;
  }

  // 检查可疑服务名
  isSuspiciousServiceName(name) {
    const suspiciousPatterns = [
      'svchost_', 'update service', 'windows update',
      'system service', 'microsoft service',
      'antivirus service', 'security service'
    ];
    
    return suspiciousPatterns.some(pattern => 
      name.toLowerCase().includes(pattern)
    );
  }

  // 检查可疑服务路径
  isSuspiciousServicePath(path) {
    return this.isSuspiciousProcessPath(path);
  }

  // 检查可疑服务用户
  isSuspiciousServiceUser(user) {
    return this.isSuspiciousUser(user);
  }

  // 检查服务是否在基线中
  isServiceInBaseline(service) {
    // 如果基线为空，默认认为是正常的
    if (this.systemBaselines.serviceNames.size === 0) return true;
    
    return this.systemBaselines.serviceNames.has(service.name.toLowerCase());
  }

  // 可疑服务处理
  onSuspiciousService(service, reason) {
    const anomaly = {
      type: 'suspiciousService',
      service,
      reason,
      timestamp: new Date()
    };
    
    this.anomalies.push(anomaly);
    
    // 通知监听器
    this.notify('suspiciousService', anomaly);
    
    // 记录详细日志
    this.logger.warn('检测到可疑服务:', { serviceName: service.name, reason });
  }

  // 检查异常服务状态变化
  checkAbnormalServiceStatusChange(service, oldStatus, newStatus) {
    // 检查关键服务的停止
    if (this.isCriticalService(service.name) && newStatus === 'stopped') {
      const anomaly = {
        type: 'criticalServiceStopped',
        service,
        oldStatus,
        newStatus,
        timestamp: new Date()
      };
      
      this.anomalies.push(anomaly);
      this.notify('criticalServiceStopped', anomaly);
    }
  }

  // 检查是否为关键服务
  isCriticalService(name) {
    const criticalServices = [
      'winlogon', 'lsass', 'services', 'svchost',
      'spooler', 'dhcp', 'dns', 'rpcss',
      'eventlog', 'wmi'
    ];
    
    return criticalServices.some(serviceName => 
      name.toLowerCase().includes(serviceName)
    );
  }

  // 更新服务基线
  updateServiceBaseline(service) {
    // 更新服务名基线
    const serviceName = service.name.toLowerCase();
    this.systemBaselines.serviceNames.set(serviceName, true);
    
    // 更新服务状态基线
    this.systemBaselines.serviceStates.set(serviceName, service.status);
  }

  // 启动文件系统监控
  startFileSystemMonitoring() {
    if (!this.config.monitorFileAccess && !this.config.monitorFileModifications) return;
    
    this.logger.info('启动文件系统监控');
    
    // 在真实环境中，这里应该设置文件系统监听器
    // 模拟文件系统事件
    this.timers.fileSystemMonitor = setInterval(() => {
      if (this.isRunning) {
        this.generateMockFileEvents();
      }
    }, 10000); // 每10秒生成一次模拟事件
  }

  // 生成模拟文件系统事件
  generateMockFileEvents() {
    // 生成随机文件事件
    const eventTypes = ['created', 'modified', 'deleted', 'accessed'];
    const filePaths = [
      'C:\\Windows\\System32\\drivers\\etc\\hosts',
      'C:\\Windows\\System32\\services.exe',
      'C:\\Program Files\\Application\\config.ini',
      'C:\\Users\\User\\Documents\\test.txt',
      'C:\\Temp\\temp_file.exe'
    ];
    
    const eventCount = Math.floor(Math.random() * 5) + 1;
    
    for (let i = 0; i < eventCount; i++) {
      const event = {
        type: eventTypes[Math.floor(Math.random() * eventTypes.length)],
        path: filePaths[Math.floor(Math.random() * filePaths.length)],
        process: this.getRandomProcessFromSnapshot(),
        timestamp: new Date()
      };
      
      this.fileEvents.push(event);
      this.handleFileEvent(event);
      
      // 限制事件历史大小
      this.limitFileEvents();
    }
  }

  // 处理文件系统事件
  handleFileEvent(event) {
    // 检查可疑文件操作
    if (this.config.enableAnomalyDetection) {
      const isSuspicious = this.checkSuspiciousFileOperation(event);
      if (isSuspicious) {
        this.onSuspiciousFileOperation(event, isSuspicious.reason);
      }
    }
    
    // 通知监听器
    this.notify('fileSystemEvent', event);
  }

  // 检查可疑文件操作
  checkSuspiciousFileOperation(event) {
    // 检查关键系统文件的修改
    if (this.isCriticalSystemFile(event.path) && 
        (event.type === 'modified' || event.type === 'deleted')) {
      return { reason: 'criticalFileModified', details: event.path };
    }
    
    // 检查敏感目录的活动
    if (this.isSensitiveDirectory(event.path)) {
      return { reason: 'sensitiveDirectoryAccess', details: event.path };
    }
    
    // 检查可疑进程访问文件
    if (event.process && this.isSuspiciousProcessName(event.process.name)) {
      return { reason: 'suspiciousProcessAccess', details: event.process.name };
    }
    
    return null;
  }

  // 检查是否为关键系统文件
  isCriticalSystemFile(path) {
    const criticalFiles = [
      'hosts', 'services.exe', 'ntoskrnl.exe', 
      'winlogon.exe', 'lsass.exe', 'sam',
      'system32', 'win.ini', 'system.ini'
    ];
    
    return criticalFiles.some(file => 
      path.toLowerCase().includes(file)
    );
  }

  // 检查是否为敏感目录
  isSensitiveDirectory(path) {
    const sensitiveDirs = [
      '\\windows\\system32\\', 
      '\\windows\\syswow64\\',
      '\\programdata\\',
      '\\users\\\\appdata\\',
      '\\windows\\temp\\'
    ];
    
    return sensitiveDirs.some(dir => 
      path.toLowerCase().includes(dir)
    );
  }

  // 可疑文件操作处理
  onSuspiciousFileOperation(event, reason) {
    const anomaly = {
      type: 'suspiciousFileOperation',
      event,
      reason,
      timestamp: new Date()
    };
    
    this.anomalies.push(anomaly);
    
    // 通知监听器
    this.notify('suspiciousFileOperation', anomaly);
    
    // 记录详细日志
    this.logger.warn('检测到可疑文件操作:', {
      eventType: event.type,
      filePath: event.path,
      process: event.process?.name,
      reason
    });
  }

  // 限制文件事件历史
  limitFileEvents() {
    const maxEvents = 10000;
    if (this.fileEvents.length > maxEvents) {
      this.fileEvents = this.fileEvents.slice(-maxEvents);
    }
  }

  // 启动注册表监控
  startRegistryMonitoring() {
    if (!this.config.monitorRegistry) return;
    
    this.logger.info('启动注册表监控');
    
    // 在真实环境中，这里应该设置注册表监听器
    // 模拟注册表事件
    this.timers.registryMonitor = setInterval(() => {
      if (this.isRunning) {
        this.generateMockRegistryEvents();
      }
    }, 15000); // 每15秒生成一次模拟事件
  }

  // 生成模拟注册表事件
  generateMockRegistryEvents() {
    // 生成随机注册表事件
    const eventTypes = ['created', 'modified', 'deleted'];
    const registryPaths = [
      'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
      'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKLM\\SYSTEM\\CurrentControlSet\\Services',
      'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows',
      'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced'
    ];
    
    const eventCount = Math.floor(Math.random() * 3) + 1;
    
    for (let i = 0; i < eventCount; i++) {
      const event = {
        type: eventTypes[Math.floor(Math.random() * eventTypes.length)],
        path: registryPaths[Math.floor(Math.random() * registryPaths.length)],
        valueName: this.generateRandomRegistryValueName(),
        process: this.getRandomProcessFromSnapshot(),
        timestamp: new Date()
      };
      
      this.registryEvents.push(event);
      this.handleRegistryEvent(event);
      
      // 限制事件历史大小
      this.limitRegistryEvents();
    }
  }

  // 处理注册表事件
  handleRegistryEvent(event) {
    // 检查可疑注册表操作
    if (this.config.enableAnomalyDetection) {
      const isSuspicious = this.checkSuspiciousRegistryOperation(event);
      if (isSuspicious) {
        this.onSuspiciousRegistryOperation(event, isSuspicious.reason);
      }
    }
    
    // 通知监听器
    this.notify('registryEvent', event);
  }

  // 检查可疑注册表操作
  checkSuspiciousRegistryOperation(event) {
    // 检查自启动项修改
    if (this.isStartupRegistryPath(event.path)) {
      return { reason: 'startupRegistryModified', details: event.path };
    }
    
    // 检查服务注册表修改
    if (event.path.includes('\\Services\\') && event.type === 'modified') {
      return { reason: 'serviceRegistryModified', details: event.path };
    }
    
    // 检查安全相关注册表修改
    if (this.isSecurityRegistryPath(event.path)) {
      return { reason: 'securityRegistryModified', details: event.path };
    }
    
    // 检查可疑进程修改注册表
    if (event.process && this.isSuspiciousProcessName(event.process.name)) {
      return { reason: 'suspiciousProcessModifyingRegistry', details: event.process.name };
    }
    
    return null;
  }

  // 检查是否为自启动注册表路径
  isStartupRegistryPath(path) {
    return path.includes('\\Run\\') || path.includes('\\RunOnce\\');
  }

  // 检查是否为安全相关注册表路径
  isSecurityRegistryPath(path) {
    const securityPaths = [
      '\\Policies\\', 
      '\\Windows Defender\\',
      '\\Security Center\\',
      '\\Firewall\\'
    ];
    
    return securityPaths.some(securityPath => 
      path.toLowerCase().includes(securityPath.toLowerCase())
    );
  }

  // 可疑注册表操作处理
  onSuspiciousRegistryOperation(event, reason) {
    const anomaly = {
      type: 'suspiciousRegistryOperation',
      event,
      reason,
      timestamp: new Date()
    };
    
    this.anomalies.push(anomaly);
    
    // 通知监听器
    this.notify('suspiciousRegistryOperation', anomaly);
    
    // 记录详细日志
    this.logger.warn('检测到可疑注册表操作:', {
      eventType: event.type,
      registryPath: event.path,
      valueName: event.valueName,
      process: event.process?.name,
      reason
    });
  }

  // 限制注册表事件历史
  limitRegistryEvents() {
    const maxEvents = 5000;
    if (this.registryEvents.length > maxEvents) {
      this.registryEvents = this.registryEvents.slice(-maxEvents);
    }
  }

  // 启动用户活动监控
  startUserActivityMonitoring() {
    if (!this.config.monitorUserActivity) return;
    
    this.logger.info('启动用户活动监控');
    
    // 初始化用户会话
    this.initializeUserSessions();
    
    // 模拟登录尝试
    if (this.config.monitorLoginAttempts) {
      this.timers.loginMonitor = setInterval(() => {
        if (this.isRunning) {
          this.generateMockLoginAttempts();
        }
      }, 20000); // 每20秒生成一次模拟登录尝试
    }
  }

  // 初始化用户会话
  initializeUserSessions() {
    // 在真实环境中，这里应该获取当前活动的用户会话
    // 模拟用户会话
    const mockSessions = [
      {
        sessionId: '1',
        userName: 'user1',
        loginTime: new Date(Date.now() - 3600000), // 1小时前
        status: 'active',
        remote: false
      },
      {
        sessionId: '2',
        userName: 'admin',
        loginTime: new Date(Date.now() - 7200000), // 2小时前
        status: 'active',
        remote: true
      }
    ];
    
    mockSessions.forEach(session => {
      this.userSessions.set(session.sessionId, session);
    });
  }

  // 生成模拟登录尝试
  generateMockLoginAttempts() {
    const attemptCount = Math.floor(Math.random() * 3) + 1;
    const users = ['user1', 'admin', 'guest', 'test', 'root'];
    
    for (let i = 0; i < attemptCount; i++) {
      const isSuccess = Math.random() > 0.3; // 70%成功率
      
      const loginAttempt = {
        username: users[Math.floor(Math.random() * users.length)],
        success: isSuccess,
        source: isSuccess ? 'local' : this.generateRandomIp(),
        timestamp: new Date()
      };
      
      this.loginAttempts.push(loginAttempt);
      this.handleLoginAttempt(loginAttempt);
      
      // 限制登录尝试历史大小
      this.limitLoginAttempts();
    }
  }

  // 处理登录尝试
  handleLoginAttempt(attempt) {
    // 检查失败的登录尝试
    if (!attempt.success) {
      this.onFailedLoginAttempt(attempt);
    } else {
      this.onSuccessfulLogin(attempt);
    }
    
    // 通知监听器
    this.notify('loginAttempt', attempt);
  }

  // 失败登录尝试处理
  onFailedLoginAttempt(attempt) {
    // 检查失败登录尝试频率
    const recentFailures = this.countRecentFailedLogins(attempt.username, 60000); // 1分钟内
    
    if (recentFailures >= 3) {
      const anomaly = {
        type: 'bruteForceAttempt',
        username: attempt.username,
        source: attempt.source,
        failureCount: recentFailures,
        timestamp: new Date()
      };
      
      this.anomalies.push(anomaly);
      
      // 通知监听器
      this.notify('bruteForceAttempt', anomaly);
      
      // 记录详细日志
      this.logger.warn('检测到暴力破解尝试:', {
        username: attempt.username,
        source: attempt.source,
        failureCount: recentFailures
      });
    }
  }

  // 成功登录处理
  onSuccessfulLogin(attempt) {
    // 更新用户会话
    const existingSession = Array.from(this.userSessions.values()).find(
      session => session.userName === attempt.username && session.status === 'active'
    );
    
    if (!existingSession) {
      // 创建新会话
      const newSession = {
        sessionId: Date.now().toString(),
        userName: attempt.username,
        loginTime: attempt.timestamp,
        status: 'active',
        remote: attempt.source !== 'local'
      };
      
      this.userSessions.set(newSession.sessionId, newSession);
      
      // 检查异常登录时间
      if (this.config.enableAnomalyDetection) {
        this.checkAbnormalLoginTime(attempt);
      }
    }
  }

  // 计算最近失败的登录尝试次数
  countRecentFailedLogins(username, timeWindow) {
    const cutoffTime = Date.now() - timeWindow;
    
    return this.loginAttempts.filter(attempt => 
      attempt.username === username && 
      !attempt.success && 
      attempt.timestamp.getTime() > cutoffTime
    ).length;
  }

  // 检查异常登录时间
  checkAbnormalLoginTime(attempt) {
    const hour = attempt.timestamp.getHours();
    
    // 检查非工作时间登录 (晚上10点到早上6点)
    if (hour >= 22 || hour < 6) {
      const anomaly = {
        type: 'abnormalLoginTime',
        username: attempt.username,
        time: attempt.timestamp,
        source: attempt.source,
        timestamp: new Date()
      };
      
      this.anomalies.push(anomaly);
      this.notify('abnormalLoginTime', anomaly);
    }
  }

  // 限制登录尝试历史
  limitLoginAttempts() {
    const maxAttempts = 1000;
    if (this.loginAttempts.length > maxAttempts) {
      this.loginAttempts = this.loginAttempts.slice(-maxAttempts);
    }
  }

  // 启动系统调用监控
  startSystemCallMonitoring() {
    if (!this.config.monitorSystemCalls) return;
    
    this.logger.info('启动系统调用监控');
    
    // 在真实环境中，这里应该设置系统调用监控
    // 模拟系统调用
    this.timers.systemCallMonitor = setInterval(() => {
      if (this.isRunning) {
        this.generateMockSystemCalls();
      }
    }, 5000); // 每5秒生成一次模拟系统调用
  }

  // 生成模拟系统调用
  generateMockSystemCalls() {
    const syscalls = [
      'open', 'read', 'write', 'close',
      'execve', 'fork', 'clone', 'pipe',
      'socket', 'connect', 'bind', 'listen',
      'accept', 'send', 'recv', 'stat',
      'lstat', 'fstat', 'chmod', 'chown',
      'unlink', 'rmdir', 'mkdir', 'link',
      'symlink', 'rename', 'truncate', 'ftruncate'
    ];
    
    const callCount = Math.floor(Math.random() * 10) + 5;
    
    for (let i = 0; i < callCount; i++) {
      const syscall = syscalls[Math.floor(Math.random() * syscalls.length)];
      
      const syscallData = {
        call: syscall,
        pid: this.getRandomProcessId(),
        arguments: this.generateMockSyscallArguments(syscall),
        timestamp: new Date()
      };
      
      this.systemCalls.push(syscallData);
      this.handleSystemCall(syscallData);
      
      // 更新系统调用统计
      this.updateSystemCallStats(syscall);
      
      // 限制系统调用历史大小
      this.limitSystemCalls();
    }
  }

  // 处理系统调用
  handleSystemCall(syscall) {
    // 检查可疑系统调用模式
    if (this.config.enableAnomalyDetection) {
      const isSuspicious = this.checkSuspiciousSystemCall(syscall);
      if (isSuspicious) {
        this.onSuspiciousSystemCall(syscall, isSuspicious.reason);
      }
    }
    
    // 通知监听器
    this.notify('systemCall', syscall);
  }

  // 检查可疑系统调用
  checkSuspiciousSystemCall(syscall) {
    const suspiciousCalls = [
      { call: 'execve', reason: 'suspiciousProcessExecution' },
      { call: 'connect', reason: 'suspiciousNetworkConnection' },
      { call: 'chmod', reason: 'suspiciousFilePermissionChange' },
      { call: 'unlink', reason: 'suspiciousFileDeletion' },
      { call: 'rename', reason: 'suspiciousFileRenaming' },
      { call: 'socket', reason: 'suspiciousNetworkActivity' }
    ];
    
    const match = suspiciousCalls.find(item => item.call === syscall.call);
    if (match) {
      return { reason: match.reason, details: syscall };
    }
    
    // 检查系统调用频率异常
    if (this.checkSystemCallFrequencyAnomaly(syscall.call)) {
      return { reason: 'abnormalSystemCallFrequency', details: syscall.call };
    }
    
    return null;
  }

  // 检查系统调用频率异常
  checkSystemCallFrequencyAnomaly(callName) {
    const recentCalls = this.countRecentSystemCalls(callName, 60000); // 1分钟内
    const baselineFreq = this.systemBaselines.systemCallFrequencies.get(callName) || 0;
    
    // 如果基线频率为0或低于阈值，认为是正常的
    if (baselineFreq === 0 || recentCalls <= baselineFreq * 3) {
      return false;
    }
    
    return true;
  }

  // 计算最近的系统调用次数
  countRecentSystemCalls(callName, timeWindow) {
    const cutoffTime = Date.now() - timeWindow;
    
    return this.systemCalls.filter(syscall => 
      syscall.call === callName && 
      syscall.timestamp.getTime() > cutoffTime
    ).length;
  }

  // 可疑系统调用处理
  onSuspiciousSystemCall(syscall, reason) {
    const anomaly = {
      type: 'suspiciousSystemCall',
      syscall,
      reason,
      timestamp: new Date()
    };
    
    this.anomalies.push(anomaly);
    
    // 通知监听器
    this.notify('suspiciousSystemCall', anomaly);
    
    // 记录详细日志
    this.logger.warn('检测到可疑系统调用:', {
      call: syscall.call,
      pid: syscall.pid,
      reason
    });
  }

  // 更新系统调用统计
  updateSystemCallStats(callName) {
    const currentCount = this.systemCallStats.get(callName) || 0;
    this.systemCallStats.set(callName, currentCount + 1);
  }

  // 限制系统调用历史
  limitSystemCalls() {
    const maxCalls = this.config.systemCallBufferSize;
    if (this.systemCalls.length > maxCalls) {
      this.systemCalls = this.systemCalls.slice(-maxCalls);
    }
  }

  // 启动基线更新
  startBaselineUpdates() {
    this.logger.info('启动系统基线更新');
    
    // 初始基线更新
    this.updateSystemBaselines();
    
    // 设置定期基线更新
    this.timers.baselineUpdate = setInterval(() => {
      if (this.isRunning) {
        this.updateSystemBaselines();
      }
    }, this.config.baselineUpdateInterval);
  }

  // 更新系统基线
  updateSystemBaselines() {
    try {
      // 更新资源使用基线
      this.updateResourceBaselines();
      
      // 更新系统调用频率基线
      this.updateSystemCallFrequencyBaselines();
      
      // 更新登录模式基线
      this.updateLoginPatternBaselines();
      
      // 更新基线时间戳
      this.systemBaselines.lastUpdated = new Date();
      
      this.logger.info('系统基线已更新');
      
    } catch (error) {
      this.logger.error('更新系统基线失败:', error);
    }
  }

  // 更新资源使用基线
  updateResourceBaselines() {
    if (this.resourceHistory.length === 0) return;
    
    // 计算CPU使用基线
    const cpuUsages = this.resourceHistory.map(item => item.cpu.usage);
    this.systemBaselines.resourceUsage.cpu = this.calculateBaselineStats(cpuUsages);
    
    // 计算内存使用基线
    const memoryUsages = this.resourceHistory.map(item => item.memory.usage);
    this.systemBaselines.resourceUsage.memory = this.calculateBaselineStats(memoryUsages);
    
    // 计算磁盘使用基线
    const diskUsages = this.resourceHistory.map(item => item.disk.usedPercentage);
    this.systemBaselines.resourceUsage.disk = this.calculateBaselineStats(diskUsages);
  }

  // 更新系统调用频率基线
  updateSystemCallFrequencyBaselines() {
    // 复制当前系统调用统计作为基线
    this.systemCallStats.forEach((count, callName) => {
      this.systemBaselines.systemCallFrequencies.set(callName, count / (this.config.baselineUpdateInterval / 60000)); // 每分钟频率
    });
  }

  // 更新登录模式基线
  updateLoginPatternBaselines() {
    if (this.loginAttempts.length === 0) return;
    
    // 计算每小时登录尝试次数
    const hourlyLoginCounts = new Array(24).fill(0);
    this.loginAttempts.forEach(attempt => {
      const hour = attempt.timestamp.getHours();
      hourlyLoginCounts[hour]++;
    });
    
    this.systemBaselines.loginPatterns.hours = hourlyLoginCounts;
    
    // 计算成功率
    const successCount = this.loginAttempts.filter(attempt => attempt.success).length;
    this.systemBaselines.loginPatterns.successRate = successCount / this.loginAttempts.length;
  }

  // 计算基线统计信息
  calculateBaselineStats(values) {
    const sortedValues = values.sort((a, b) => a - b);
    const sum = sortedValues.reduce((acc, val) => acc + val, 0);
    
    return {
      min: sortedValues[0],
      max: sortedValues[sortedValues.length - 1],
      avg: sum / sortedValues.length
    };
  }

  // 事件监听
  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    
    this.listeners.get(event).push(callback);
    return this;
  }

  // 移除事件监听
  off(event, callback) {
    if (this.listeners.has(event)) {
      const callbacks = this.listeners.get(event);
      const index = callbacks.indexOf(callback);
      
      if (index > -1) {
        callbacks.splice(index, 1);
      }
      
      // 如果没有监听器了，删除事件
      if (callbacks.length === 0) {
        this.listeners.delete(event);
      }
    }
    
    return this;
  }

  // 通知事件
  notify(event, data) {
    if (this.listeners.has(event)) {
      for (const callback of this.listeners.get(event)) {
        try {
          callback(data);
        } catch (error) {
          this.logger.error(`执行事件监听器失败 (${event}):`, error);
        }
      }
    }
    
    // 如果配置了向入侵检测器报告，并且事件是安全相关的
    if (this.config.reportToInvasionDetector && this.isSecurityEvent(event)) {
      this.reportToInvasionDetector(event, data);
    }
  }

  // 检查是否为安全事件
  isSecurityEvent(event) {
    const securityEvents = [
      'suspiciousProcess',
      'abnormalProcessTermination',
      'resourceAnomaly',
      'suspiciousService',
      'criticalServiceStopped',
      'suspiciousFileOperation',
      'suspiciousRegistryOperation',
      'bruteForceAttempt',
      'abnormalLoginTime',
      'suspiciousSystemCall'
    ];
    
    return securityEvents.includes(event);
  }

  // 向入侵检测器报告
  reportToInvasionDetector(event, data) {
    try {
      if (window.invasionDetector) {
        window.invasionDetector.reportSystemEvent({
          eventType: event,
          source: 'system_monitor',
          timestamp: new Date(),
          data: data
        });
      }
    } catch (error) {
      this.logger.error('向入侵检测器报告事件失败:', error);
    }
  }

  // 清除所有计时器
  clearAllTimers() {
    for (const timer in this.timers) {
      clearInterval(this.timers[timer]);
    }
    this.timers = {};
  }

  // 清理资源
  cleanupResources() {
    this.processSnapshot.clear();
    this.processHistory = [];
    this.systemCalls = [];
    this.systemCallStats.clear();
    this.resourceHistory = [];
    this.fileEvents = [];
    this.registryEvents = [];
    this.userSessions.clear();
    this.loginAttempts = [];
    this.serviceSnapshot.clear();
    this.serviceChanges = [];
    this.anomalies = [];
  }

  // 工具方法
  generateRandomIp() {
    return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
  }

  generateRandomProcessId() {
    const pids = Array.from(this.processSnapshot.keys());
    return pids.length > 0 ? pids[Math.floor(Math.random() * pids.length)] : Math.floor(Math.random() * 10000);
  }

  getRandomProcessFromSnapshot() {
    const processes = Array.from(this.processSnapshot.values());
    return processes.length > 0 ? processes[Math.floor(Math.random() * processes.length)] : null;
  }

  generateRandomRegistryValueName() {
    const valueNames = ['ServiceDll', 'ImagePath', 'Start', 'DisplayName', 'Description', 'Debugger', 'Shell'];
    return valueNames[Math.floor(Math.random() * valueNames.length)];
  }

  generateMockSyscallArguments(call) {
    switch (call) {
      case 'open':
        return { path: this.generateRandomFilePath(), flags: 'O_RDWR' };
      case 'connect':
        return { socket: Math.floor(Math.random() * 1000), address: this.generateRandomIp(), port: this.getRandomPort() };
      case 'execve':
        return { path: this.generateRandomFilePath(), argv: ['arg1', 'arg2'] };
      case 'chmod':
        return { path: this.generateRandomFilePath(), mode: '0755' };
      default:
        return { arg1: 'value1', arg2: 'value2' };
    }
  }

  generateRandomFilePath() {
    const paths = [
      '/etc/passwd', '/bin/bash', '/tmp/file.txt',
      '/var/log/syslog', '/home/user/file.dat'
    ];
    return paths[Math.floor(Math.random() * paths.length)];
  }

  getRandomPort() {
    return Math.floor(Math.random() * 65535) + 1;
  }

  // 模拟数据生成方法
  generateMockProcessList() {
    const processNames = [
      'system', 'explorer.exe', 'svchost.exe', 'services.exe',
      'lsass.exe', 'winlogon.exe', 'csrss.exe', 'taskmgr.exe',
      'notepad.exe', 'chrome.exe', 'firefox.exe', 'word.exe',
      'excel.exe', 'powerpoint.exe', 'outlook.exe', 'teams.exe',
      'vscode.exe', 'visualstudio.exe', 'docker.exe', 'wslhost.exe'
    ];
    
    const users = ['SYSTEM', 'NETWORK SERVICE', 'LOCAL SERVICE', 'user1', 'admin'];
    const statuses = ['running', 'sleeping', 'zombie'];
    
    const processes = [];
    const processCount = Math.floor(Math.random() * 50) + 30; // 30-80个进程
    
    for (let i = 0; i < processCount; i++) {
      const name = processNames[Math.floor(Math.random() * processNames.length)];
      const pid = Math.floor(Math.random() * 65535) + 1;
      const priority = Math.floor(Math.random() * 6) + 1; // 1-6
      const cpuUsage = Math.random() * 10; // 0-10% CPU
      const memoryUsage = Math.floor(Math.random() * 100 * 1024 * 1024); // 0-100MB内存
      const user = users[Math.floor(Math.random() * users.length)];
      const status = statuses[Math.floor(Math.random() * statuses.length)];
      const startTime = new Date(Date.now() - Math.floor(Math.random() * 86400000)); // 最近24小时内启动
      
      processes.push({
        pid,
        name,
        path: `C:\\Windows\\System32\\${name}`.replace(/\\/g, '\\\\'),
        commandLine: `${name} /param1 /param2`,
        priority,
        cpuUsage,
        memoryUsage,
        user,
        status,
        startTime
      });
    }
    
    return processes;
  }

  generateMockResourceUsage() {
    return {
      timestamp: new Date(),
      cpu: {
        usage: Math.random() * 50 + 5, // 5-55% CPU使用率
        cores: 8,
        processes: Math.floor(Math.random() * 50) + 30
      },
      memory: {
        usage: Math.random() * 40 + 10, // 10-50% 内存使用率
        total: 16 * 1024 * 1024 * 1024, // 16GB
        available: Math.floor(Math.random() * 8 * 1024 * 1024 * 1024) + 4 * 1024 * 1024 * 1024 // 4-12GB可用
      },
      disk: {
        total: 500 * 1024 * 1024 * 1024, // 500GB
        used: Math.floor(Math.random() * 200 * 1024 * 1024 * 1024) + 50 * 1024 * 1024 * 1024, // 50-250GB已用
        usedPercentage: Math.random() * 40 + 10 // 10-50% 磁盘使用率
      },
      network: {
        bytesSent: Math.floor(Math.random() * 100 * 1024 * 1024), // 0-100MB发送
        bytesReceived: Math.floor(Math.random() * 200 * 1024 * 1024), // 0-200MB接收
        connections: Math.floor(Math.random() * 100) + 10 // 10-110个连接
      },
      processCount: Math.floor(Math.random() * 50) + 30 // 30-80个进程
    };
  }

  getDefaultResourceUsage() {
    return {
      timestamp: new Date(),
      cpu: { usage: 0, cores: 8, processes: 0 },
      memory: { usage: 0, total: 16 * 1024 * 1024 * 1024, available: 16 * 1024 * 1024 * 1024 },
      disk: { total: 500 * 1024 * 1024 * 1024, used: 0, usedPercentage: 0 },
      network: { bytesSent: 0, bytesReceived: 0, connections: 0 },
      processCount: 0
    };
  }

  generateMockServiceList() {
    const serviceNames = [
      'Windows Update', 'Windows Defender Firewall', 'Windows Event Log',
      'Windows Management Instrumentation', 'Remote Procedure Call (RPC)',
      'Background Intelligent Transfer Service', 'Cryptographic Services',
      'DHCP Client', 'DNS Client', 'Print Spooler', 'Task Scheduler',
      'Windows Audio', 'Windows Search', 'Windows Time',
      'WLAN AutoConfig', 'Workstation', 'Server', 'Superfetch'
    ];
    
    const startTypes = ['Automatic', 'Manual', 'Disabled'];
    const statuses = ['Running', 'Stopped', 'Paused'];
    const users = ['SYSTEM', 'NETWORK SERVICE', 'LOCAL SERVICE'];
    
    const services = [];
    const serviceCount = Math.floor(Math.random() * 10) + 15; // 15-25个服务
    
    for (let i = 0; i < serviceCount; i++) {
      const name = serviceNames[Math.floor(Math.random() * serviceNames.length)];
      const displayName = name;
      const startType = startTypes[Math.floor(Math.random() * startTypes.length)];
      const status = startType === 'Disabled' ? 'Stopped' : statuses[Math.floor(Math.random() * statuses.length)];
      const user = users[Math.floor(Math.random() * users.length)];
      const path = `C:\\Windows\\System32\\svchost.exe -k netsvcs`.replace(/\\/g, '\\\\');
      
      services.push({
        name: name.replace(/\s+/g, ''),
        displayName,
        startType,
        status,
        user,
        path,
        description: `${name} is a Windows service.`
      });
    }
    
    return services;
  }
}

// 导出SystemBehaviorMonitor类
if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
  module.exports = SystemBehaviorMonitor;
} else if (typeof window !== 'undefined') {
  window.SystemBehaviorMonitor = SystemBehaviorMonitor;
}

// 如果是直接在浏览器中加载，创建一个全局实例
if (typeof window !== 'undefined' && !window.systemBehaviorMonitor) {
  window.systemBehaviorMonitor = new SystemBehaviorMonitor();
}