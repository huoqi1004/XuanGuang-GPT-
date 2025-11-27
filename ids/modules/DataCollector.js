// 数据收集器模块 - 负责从各种来源收集入侵检测所需的数据
class DataCollector {
  constructor() {
    this.logger = window.globalLogger || console;
    this.networkMonitor = new NetworkMonitor();
    this.systemMonitor = new SystemMonitor();
    this.logCollector = new LogCollector();
    this.eventCollector = new SecurityEventCollector();
    this.collectionStats = {
      network: { count: 0, lastTime: null, errors: 0 },
      system: { count: 0, lastTime: null, errors: 0 },
      logs: { count: 0, lastTime: null, errors: 0 },
      securityEvents: { count: 0, lastTime: null, errors: 0 }
    };
  }

  // 收集网络流量数据
  async collectNetworkData() {
    try {
      this.logger.info('开始收集网络流量数据...');
      const startTime = Date.now();
      
      // 收集网络连接信息
      const connections = await this.networkMonitor.getActiveConnections();
      
      // 收集网络统计信息
      const stats = await this.networkMonitor.getNetworkStats();
      
      // 收集异常网络行为指标
      const anomalies = await this.networkMonitor.detectAnomalies();
      
      const data = {
        timestamp: new Date(),
        connections: connections || [],
        stats: stats || {},
        anomalies: anomalies || [],
        collectionTime: Date.now() - startTime
      };
      
      // 更新统计信息
      this.updateCollectionStats('network', data.connections.length);
      
      this.logger.info(`网络数据收集完成，共收集 ${data.connections.length} 个连接信息`);
      return data;
    } catch (error) {
      this.logger.error('收集网络数据失败:', error);
      this.collectionStats.network.errors++;
      return null;
    }
  }

  // 收集系统行为数据
  async collectSystemData() {
    try {
      this.logger.info('开始收集系统行为数据...');
      const startTime = Date.now();
      
      // 收集进程信息
      const processes = await this.systemMonitor.getProcesses();
      
      // 收集系统资源使用情况
      const resources = await this.systemMonitor.getResourceUsage();
      
      // 收集文件系统活动
      const fileSystem = await this.systemMonitor.getFileSystemActivity();
      
      // 收集注册表变更（Windows系统）
      const registryChanges = await this.systemMonitor.getRegistryChanges();
      
      // 收集用户活动
      const userActivity = await this.systemMonitor.getUserActivity();
      
      const data = {
        timestamp: new Date(),
        processes: processes || [],
        resources: resources || {},
        fileSystem: fileSystem || {},
        registryChanges: registryChanges || [],
        userActivity: userActivity || {},
        collectionTime: Date.now() - startTime
      };
      
      // 更新统计信息
      this.updateCollectionStats('system', data.processes.length);
      
      this.logger.info(`系统数据收集完成，共收集 ${data.processes.length} 个进程信息`);
      return data;
    } catch (error) {
      this.logger.error('收集系统数据失败:', error);
      this.collectionStats.system.errors++;
      return null;
    }
  }

  // 收集日志数据
  async collectLogData() {
    try {
      this.logger.info('开始收集日志数据...');
      const startTime = Date.now();
      
      // 收集系统日志
      const systemLogs = await this.logCollector.getSystemLogs();
      
      // 收集应用日志
      const appLogs = await this.logCollector.getApplicationLogs();
      
      // 收集安全日志
      const securityLogs = await this.logCollector.getSecurityLogs();
      
      const data = {
        timestamp: new Date(),
        system: systemLogs || [],
        application: appLogs || [],
        security: securityLogs || [],
        collectionTime: Date.now() - startTime
      };
      
      // 计算总日志条数
      const totalLogs = 
        (data.system.length || 0) + 
        (data.application.length || 0) + 
        (data.security.length || 0);
      
      // 更新统计信息
      this.updateCollectionStats('logs', totalLogs);
      
      this.logger.info(`日志数据收集完成，共收集 ${totalLogs} 条日志记录`);
      return data;
    } catch (error) {
      this.logger.error('收集日志数据失败:', error);
      this.collectionStats.logs.errors++;
      return null;
    }
  }

  // 收集安全事件
  async collectSecurityEvents() {
    try {
      this.logger.info('开始收集安全事件...');
      const startTime = Date.now();
      
      // 收集防火墙事件
      const firewallEvents = await this.eventCollector.getFirewallEvents();
      
      // 收集杀毒软件事件
      const antivirusEvents = await this.eventCollector.getAntivirusEvents();
      
      // 收集入侵检测事件（如果有）
      const idsEvents = await this.eventCollector.getIDSEvents();
      
      // 收集身份验证事件
      const authEvents = await this.eventCollector.getAuthenticationEvents();
      
      // 收集访问控制事件
      const accessEvents = await this.eventCollector.getAccessControlEvents();
      
      const data = {
        timestamp: new Date(),
        firewall: firewallEvents || [],
        antivirus: antivirusEvents || [],
        ids: idsEvents || [],
        authentication: authEvents || [],
        accessControl: accessEvents || [],
        collectionTime: Date.now() - startTime
      };
      
      // 计算总事件数
      const totalEvents = 
        (data.firewall.length || 0) + 
        (data.antivirus.length || 0) + 
        (data.ids.length || 0) + 
        (data.authentication.length || 0) + 
        (data.accessControl.length || 0);
      
      // 更新统计信息
      this.updateCollectionStats('securityEvents', totalEvents);
      
      this.logger.info(`安全事件收集完成，共收集 ${totalEvents} 个安全事件`);
      return data;
    } catch (error) {
      this.logger.error('收集安全事件失败:', error);
      this.collectionStats.securityEvents.errors++;
      return null;
    }
  }

  // 综合数据收集
  async collectAllData() {
    try {
      this.logger.info('开始综合数据收集...');
      const startTime = Date.now();
      
      // 并行收集所有数据以提高效率
      const [networkData, systemData, logData, securityEvents] = await Promise.all([
        this.collectNetworkData(),
        this.collectSystemData(),
        this.collectLogData(),
        this.collectSecurityEvents()
      ]);
      
      const data = {
        timestamp: new Date(),
        network: networkData,
        system: systemData,
        logs: logData,
        securityEvents: securityEvents,
        collectionTime: Date.now() - startTime
      };
      
      this.logger.info(`综合数据收集完成，总耗时: ${data.collectionTime}ms`);
      return data;
    } catch (error) {
      this.logger.error('综合数据收集失败:', error);
      return null;
    }
  }

  // 更新收集统计信息
  updateCollectionStats(type, count) {
    this.collectionStats[type].count = count;
    this.collectionStats[type].lastTime = new Date();
  }

  // 获取收集统计信息
  getCollectionStats() {
    return { ...this.collectionStats };
  }

  // 重置收集统计信息
  resetCollectionStats() {
    Object.keys(this.collectionStats).forEach(type => {
      this.collectionStats[type] = {
        count: 0,
        lastTime: null,
        errors: 0
      };
    });
  }
}

// 网络监控器类
class NetworkMonitor {
  constructor() {
    this.logger = window.globalLogger || console;
  }

  // 获取活跃连接
  async getActiveConnections() {
    try {
      // 这里应该调用底层API获取网络连接
      // 由于是Web环境，这里提供模拟数据
      return [
        {
          protocol: 'TCP',
          localAddress: '192.168.1.100',
          localPort: 52341,
          remoteAddress: '203.0.113.42',
          remotePort: 443,
          state: 'ESTABLISHED',
          processId: 1234,
          processName: 'chrome.exe',
          createTime: new Date(Date.now() - 300000)
        },
        {
          protocol: 'TCP',
          localAddress: '192.168.1.100',
          localPort: 49872,
          remoteAddress: '198.51.100.23',
          remotePort: 80,
          state: 'TIME_WAIT',
          processId: 5678,
          processName: 'firefox.exe',
          createTime: new Date(Date.now() - 600000)
        }
      ];
    } catch (error) {
      this.logger.error('获取网络连接失败:', error);
      return [];
    }
  }

  // 获取网络统计信息
  async getNetworkStats() {
    try {
      // 模拟网络统计数据
      return {
        bytesSent: 12580,
        bytesReceived: 453289,
        packetsSent: 156,
        packetsReceived: 782,
        errorsSent: 0,
        errorsReceived: 2,
        time: new Date()
      };
    } catch (error) {
      this.logger.error('获取网络统计失败:', error);
      return {};
    }
  }

  // 检测网络异常
  async detectAnomalies() {
    try {
      // 模拟异常检测
      const anomalies = [];
      
      // 检查连接数
      const connections = await this.getActiveConnections();
      if (connections.length > 100) {
        anomalies.push({
          type: 'HIGH_CONNECTION_COUNT',
          severity: 'MEDIUM',
          message: '检测到异常高的网络连接数',
          value: connections.length,
          timestamp: new Date()
        });
      }
      
      // 检查端口扫描迹象
      const uniqueRemoteIps = new Set(connections.map(conn => conn.remoteAddress));
      const uniqueRemotePorts = new Set(connections.map(conn => conn.remotePort));
      
      if (uniqueRemotePorts.size > 50 && uniqueRemoteIps.size < 10) {
        anomalies.push({
          type: 'POSSIBLE_PORT_SCAN',
          severity: 'HIGH',
          message: '检测到可能的端口扫描行为',
          details: {
            ipCount: uniqueRemoteIps.size,
            portCount: uniqueRemotePorts.size
          },
          timestamp: new Date()
        });
      }
      
      return anomalies;
    } catch (error) {
      this.logger.error('检测网络异常失败:', error);
      return [];
    }
  }
}

// 系统监控器类
class SystemMonitor {
  constructor() {
    this.logger = window.globalLogger || console;
  }

  // 获取进程信息
  async getProcesses() {
    try {
      // 模拟进程数据
      return [
        {
          id: 1234,
          name: 'chrome.exe',
          path: 'C:\\Program Files\\Google\\Chrome\\chrome.exe',
          commandLine: 'chrome.exe --type=renderer',
          cpuUsage: 5.2,
          memoryUsage: 256.5,
          user: 'SYSTEM',
          priority: 'NORMAL',
          startTime: new Date(Date.now() - 7200000),
          threads: 24
        },
        {
          id: 5678,
          name: 'explorer.exe',
          path: 'C:\\Windows\\explorer.exe',
          commandLine: 'explorer.exe',
          cpuUsage: 1.8,
          memoryUsage: 145.2,
          user: 'User1',
          priority: 'NORMAL',
          startTime: new Date(Date.now() - 86400000),
          threads: 12
        }
      ];
    } catch (error) {
      this.logger.error('获取进程信息失败:', error);
      return [];
    }
  }

  // 获取资源使用情况
  async getResourceUsage() {
    try {
      // 模拟资源使用数据
      return {
        cpu: {
          totalUsage: 23.5,
          cores: 4,
          perCoreUsage: [15.2, 28.7, 22.1, 27.9]
        },
        memory: {
          total: 8192,
          used: 3456,
          available: 4736,
          percent: 42.2
        },
        disk: {
          total: 500,
          used: 320,
          available: 180,
          percent: 64.0
        },
        timestamp: new Date()
      };
    } catch (error) {
      this.logger.error('获取资源使用情况失败:', error);
      return {};
    }
  }

  // 获取文件系统活动
  async getFileSystemActivity() {
    try {
      // 模拟文件系统活动
      return {
        recentReads: [
          { path: 'C:\\Windows\\System32\\kernel32.dll', processId: 1234, time: new Date(Date.now() - 60000) },
          { path: 'C:\\Users\\User1\\Documents\\file.txt', processId: 5678, time: new Date(Date.now() - 30000) }
        ],
        recentWrites: [
          { path: 'C:\\Windows\\Temp\\temp.dat', processId: 9012, time: new Date(Date.now() - 45000) }
        ],
        criticalFileAccess: [
          { path: 'C:\\Windows\\System32\\', processId: 1234, accessType: 'READ', time: new Date(Date.now() - 120000) }
        ]
      };
    } catch (error) {
      this.logger.error('获取文件系统活动失败:', error);
      return {};
    }
  }

  // 获取注册表变更
  async getRegistryChanges() {
    try {
      // 模拟注册表变更
      return [
        {
          key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          value: 'NewStartupItem',
          oldValue: null,
          newValue: 'C:\\Program Files\\Unknown\\unknown.exe',
          changeType: 'ADD',
          processId: 4321,
          time: new Date(Date.now() - 180000)
        }
      ];
    } catch (error) {
      this.logger.error('获取注册表变更失败:', error);
      return [];
    }
  }

  // 获取用户活动
  async getUserActivity() {
    try {
      // 模拟用户活动
      return {
        logins: [
          { user: 'User1', time: new Date(Date.now() - 3600000), success: true, ip: '127.0.0.1' },
          { user: 'Administrator', time: new Date(Date.now() - 7200000), success: true, ip: '192.168.1.100' }
        ],
        failedLogins: [
          { user: 'Administrator', time: new Date(Date.now() - 300000), ip: '203.0.113.42' }
        ],
        privilegedOperations: [
          { user: 'Administrator', operation: 'InstallService', time: new Date(Date.now() - 2400000) }
        ]
      };
    } catch (error) {
      this.logger.error('获取用户活动失败:', error);
      return {};
    }
  }
}

// 日志收集器类
class LogCollector {
  constructor() {
    this.logger = window.globalLogger || console;
  }

  // 获取系统日志
  async getSystemLogs() {
    try {
      // 模拟系统日志
      return [
        {
          id: 1001,
          time: new Date(Date.now() - 300000),
          source: 'System',
          eventId: 7036,
          level: 'INFO',
          message: 'The Windows Firewall service entered the running state.'
        }
      ];
    } catch (error) {
      this.logger.error('获取系统日志失败:', error);
      return [];
    }
  }

  // 获取应用日志
  async getApplicationLogs() {
    try {
      // 模拟应用日志
      return [
        {
          id: 2001,
          time: new Date(Date.now() - 180000),
          source: 'Application Error',
          eventId: 1000,
          level: 'ERROR',
          message: 'Faulting application name: app.exe, version: 1.0.0.0, time stamp: 0x5f000000'
        }
      ];
    } catch (error) {
      this.logger.error('获取应用日志失败:', error);
      return [];
    }
  }

  // 获取安全日志
  async getSecurityLogs() {
    try {
      // 模拟安全日志
      return [
        {
          id: 3001,
          time: new Date(Date.now() - 240000),
          source: 'Security',
          eventId: 4624,
          level: 'INFO',
          message: 'An account was successfully logged on.'
        },
        {
          id: 3002,
          time: new Date(Date.now() - 300000),
          source: 'Security',
          eventId: 4625,
          level: 'WARNING',
          message: 'An account failed to log on.'
        }
      ];
    } catch (error) {
      this.logger.error('获取安全日志失败:', error);
      return [];
    }
  }
}

// 安全事件收集器类
class SecurityEventCollector {
  constructor() {
    this.logger = window.globalLogger || console;
  }

  // 获取防火墙事件
  async getFirewallEvents() {
    try {
      // 模拟防火墙事件
      return [
        {
          id: 4001,
          time: new Date(Date.now() - 60000),
          action: 'BLOCK',
          protocol: 'TCP',
          sourceIp: '203.0.113.42',
          sourcePort: 54321,
          destIp: '192.168.1.100',
          destPort: 22,
          reason: 'Blocked by rule'
        }
      ];
    } catch (error) {
      this.logger.error('获取防火墙事件失败:', error);
      return [];
    }
  }

  // 获取杀毒软件事件
  async getAntivirusEvents() {
    try {
      // 模拟杀毒软件事件
      return [
        {
          id: 5001,
          time: new Date(Date.now() - 120000),
          type: 'DETECTION',
          severity: 'MEDIUM',
          threat: 'Trojan.GenericKD.123456',
          file: 'C:\\Downloads\\file.exe',
          action: 'QUARANTINED'
        }
      ];
    } catch (error) {
      this.logger.error('获取杀毒软件事件失败:', error);
      return [];
    }
  }

  // 获取IDS事件
  async getIDSEvents() {
    try {
      // 模拟IDS事件
      return [
        {
          id: 6001,
          time: new Date(Date.now() - 90000),
          signature: 'SUSPICIOUS_SSH_BRUTE_FORCE',
          severity: 'HIGH',
          sourceIp: '203.0.113.42',
          destIp: '192.168.1.100',
          details: 'Multiple failed SSH login attempts'
        }
      ];
    } catch (error) {
      this.logger.error('获取IDS事件失败:', error);
      return [];
    }
  }

  // 获取身份验证事件
  async getAuthenticationEvents() {
    try {
      // 模拟身份验证事件
      return [
        {
          id: 7001,
          time: new Date(Date.now() - 150000),
          type: 'LOGIN',
          user: 'User1',
          success: true,
          method: 'PASSWORD',
          ip: '192.168.1.100'
        },
        {
          id: 7002,
          time: new Date(Date.now() - 180000),
          type: 'LOGIN',
          user: 'Administrator',
          success: false,
          method: 'PASSWORD',
          ip: '203.0.113.42',
          reason: 'Invalid password'
        }
      ];
    } catch (error) {
      this.logger.error('获取身份验证事件失败:', error);
      return [];
    }
  }

  // 获取访问控制事件
  async getAccessControlEvents() {
    try {
      // 模拟访问控制事件
      return [
        {
          id: 8001,
          time: new Date(Date.now() - 210000),
          type: 'PERMISSION_CHANGE',
          user: 'Administrator',
          object: 'C:\\SensitiveData',
          change: 'Full Control granted to User1'
        }
      ];
    } catch (error) {
      this.logger.error('获取访问控制事件失败:', error);
      return [];
    }
  }
}

export default DataCollector;