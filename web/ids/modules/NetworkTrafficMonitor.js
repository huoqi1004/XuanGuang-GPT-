// 网络流量监控器 - 负责实时收集、分析和处理网络流量数据
class NetworkTrafficMonitor {
  constructor(config = {}) {
    this.logger = window.globalLogger || console;
    
    // 配置项
    this.config = {
      // 监控设置
      enabled: true,
      captureEnabled: true,
      samplingRate: 100, // 采样率百分比
      maxPacketSize: 1500, // 最大数据包大小
      
      // 过滤器配置
      filterRules: [],
      captureLocalhost: true,
      ignoredIps: [],
      ignoredPorts: [],
      
      // 协议监控
      monitorTcp: true,
      monitorUdp: true,
      monitorIcmp: true,
      monitorHttp: true,
      monitorHttps: false, // 默认不监控HTTPS内容
      
      // 性能设置
      bufferSize: 1024 * 1024, // 1MB缓冲区
      maxConnections: 10000, // 最大连接数
      maxFlows: 5000, // 最大流数量
      
      // 流量分析
      enableFlowAnalysis: true,
      flowTimeout: 60000, // 流超时时间（毫秒）
      enableAnomalyDetection: true,
      baselineUpdateInterval: 3600000, // 基线更新间隔（毫秒）
      
      // 警报设置
      alertOnSuspiciousPatterns: true,
      alertOnHighBandwidth: true,
      bandwidthThreshold: 1024 * 1024 * 10, // 10MB/s带宽阈值
      
      // 存储设置
      storePackets: false,
      maxStoredPackets: 10000,
      packetStoragePath: 'network_packets',
      
      // 集成设置
      reportToInvasionDetector: true,
      
      ...config
    };
    
    // 状态和数据存储
    this.isRunning = false;
    this.captureStartTime = null;
    this.statistics = this.initializeStatistics();
    
    // 流量数据存储
    this.activeConnections = new Map();
    this.flowTable = new Map();
    this.recentPackets = [];
    this.trafficBaselines = this.initializeBaselines();
    
    // 采样计数器
    this.packetCounter = 0;
    this.sampledPacketCounter = 0;
    
    // 时间窗口数据
    this.timeWindows = {
      '1m': [], // 1分钟窗口
      '5m': [], // 5分钟窗口
      '15m': [], // 15分钟窗口
      '1h': []  // 1小时窗口
    };
    
    // 事件监听器
    this.listeners = new Map();
    
    // 初始化
    this.initialize();
  }

  // 初始化监控器
  initialize() {
    try {
      // 注册到全局对象
      if (typeof window !== 'undefined' && !window.networkTrafficMonitor) {
        window.networkTrafficMonitor = this;
      }
      
      // 设置定期任务
      this.setupScheduledTasks();
      
      this.logger.info('网络流量监控器初始化完成');
      return true;
    } catch (error) {
      this.logger.error('初始化网络流量监控器失败:', error);
      return false;
    }
  }

  // 初始化统计数据
  initializeStatistics() {
    return {
      totalPackets: 0,
      totalBytes: 0,
      tcpPackets: 0,
      udpPackets: 0,
      icmpPackets: 0,
      httpRequests: 0,
      httpsRequests: 0,
      droppedPackets: 0,
      samplingRate: this.config.samplingRate,
      activeConnections: 0,
      peakConnections: 0,
      bandwidth: {
        inbound: 0,
        outbound: 0,
        total: 0
      },
      protocols: {},
      ipAddresses: {
        sources: new Map(),
        destinations: new Map()
      },
      ports: {
        sources: new Map(),
        destinations: new Map()
      },
      errors: {
        checksumErrors: 0,
        malformedPackets: 0,
        bufferOverflows: 0
      },
      lastUpdated: new Date()
    };
  }

  // 初始化流量基线
  initializeBaselines() {
    return {
      hourlyTraffic: new Array(24).fill(0), // 24小时的流量基线
      dailyTraffic: new Array(7).fill(0),   // 7天的流量基线
      protocolDistribution: {},
      connectionRate: {
        min: 0,
        max: 0,
        avg: 0
      },
      bandwidthUsage: {
        min: 0,
        max: 0,
        avg: 0
      },
      lastUpdated: new Date()
    };
  }

  // 设置定期任务
  setupScheduledTasks() {
    // 定期清理过期流
    setInterval(() => this.cleanupExpiredFlows(), 30000); // 每30秒
    
    // 更新统计信息
    setInterval(() => this.updateStatistics(), 5000); // 每5秒
    
    // 更新流量基线
    if (this.config.enableAnomalyDetection) {
      setInterval(() => this.updateTrafficBaselines(), this.config.baselineUpdateInterval);
    }
    
    // 更新时间窗口数据
    setInterval(() => this.updateTimeWindows(), 60000); // 每分钟
  }

  // 启动监控
  start() {
    try {
      if (this.isRunning) {
        this.logger.warn('网络流量监控已在运行');
        return false;
      }
      
      this.isRunning = true;
      this.captureStartTime = new Date();
      
      // 初始化捕获引擎
      this.initializeCaptureEngine();
      
      // 重置统计信息
      this.statistics = this.initializeStatistics();
      
      // 通知启动
      this.logger.info('网络流量监控已启动');
      this.notify('monitoringStarted', { startTime: this.captureStartTime });
      
      return true;
    } catch (error) {
      this.logger.error('启动网络流量监控失败:', error);
      this.isRunning = false;
      return false;
    }
  }

  // 停止监控
  stop() {
    try {
      if (!this.isRunning) {
        this.logger.warn('网络流量监控未在运行');
        return false;
      }
      
      this.isRunning = false;
      
      // 停止捕获引擎
      this.stopCaptureEngine();
      
      // 清理资源
      this.cleanupResources();
      
      // 通知停止
      this.logger.info('网络流量监控已停止');
      this.notify('monitoringStopped', { 
        endTime: new Date(),
        totalRuntime: new Date() - this.captureStartTime
      });
      
      return true;
    } catch (error) {
      this.logger.error('停止网络流量监控失败:', error);
      return false;
    }
  }

  // 初始化捕获引擎
  initializeCaptureEngine() {
    try {
      // 在真实环境中，这里应该初始化一个网络捕获库
      // 如pcap.js、libpcap或系统API
      
      this.logger.info('初始化网络捕获引擎');
      
      // 应用过滤器
      this.applyCaptureFilters();
      
      // 启动模拟捕获（在没有真实捕获库的情况下）
      this.startMockCapture();
      
      return true;
    } catch (error) {
      this.logger.error('初始化捕获引擎失败:', error);
      return false;
    }
  }

  // 停止捕获引擎
  stopCaptureEngine() {
    try {
      // 在真实环境中，这里应该停止网络捕获
      this.logger.info('停止网络捕获引擎');
      
      // 停止模拟捕获
      this.stopMockCapture();
      
      return true;
    } catch (error) {
      this.logger.error('停止捕获引擎失败:', error);
      return false;
    }
  }

  // 应用捕获过滤器
  applyCaptureFilters() {
    try {
      const filters = [];
      
      // 应用协议过滤器
      if (!this.config.monitorTcp) filters.push('!tcp');
      if (!this.config.monitorUdp) filters.push('!udp');
      if (!this.config.monitorIcmp) filters.push('!icmp');
      
      // 应用IP过滤器
      for (const ip of this.config.ignoredIps) {
        filters.push(`!host ${ip}`);
      }
      
      // 应用端口过滤器
      for (const port of this.config.ignoredPorts) {
        filters.push(`!port ${port}`);
      }
      
      // 应用localhost过滤
      if (!this.config.captureLocalhost) {
        filters.push('!host 127.0.0.1');
        filters.push('!host ::1');
      }
      
      this.logger.info(`应用捕获过滤器: ${filters.join(' ')}`);
      
      // 在真实环境中，这里应该将过滤器应用到捕获引擎
      this.activeFilters = filters.join(' ');
      
      return true;
    } catch (error) {
      this.logger.error('应用捕获过滤器失败:', error);
      return false;
    }
  }

  // 处理网络数据包
  handlePacket(packet) {
    if (!this.isRunning || !this.config.captureEnabled) return;
    
    try {
      // 增加数据包计数
      this.packetCounter++;
      
      // 应用采样率
      if (this.shouldSamplePacket()) {
        this.sampledPacketCounter++;
        
        // 解析数据包
        const parsedPacket = this.parsePacket(packet);
        
        if (parsedPacket) {
          // 更新统计信息
          this.updatePacketStatistics(parsedPacket);
          
          // 处理连接
          this.trackConnection(parsedPacket);
          
          // 分析流量流
          this.analyzeFlow(parsedPacket);
          
          // 检测异常
          if (this.config.enableAnomalyDetection) {
            this.detectAnomalies(parsedPacket);
          }
          
          // 存储数据包（如果启用）
          if (this.config.storePackets) {
            this.storePacket(parsedPacket);
          }
          
          // 通知监听器
          this.notify('packetCaptured', parsedPacket);
          
          // 检查可疑模式
          if (this.config.alertOnSuspiciousPatterns) {
            this.checkSuspiciousPatterns(parsedPacket);
          }
        }
      }
    } catch (error) {
      this.statistics.errors.malformedPackets++;
      this.logger.error('处理数据包失败:', error);
    }
  }

  // 判断是否采样数据包
  shouldSamplePacket() {
    // 简单采样逻辑
    return (this.packetCounter % 100) < this.config.samplingRate;
  }

  // 解析数据包
  parsePacket(packetData) {
    try {
      // 在真实环境中，这里应该使用协议解析库解析数据包
      // 这里返回模拟的解析结果
      
      // 模拟IP头信息
      const ipHeader = {
        version: 4,
        sourceIp: this.generateRandomIp(),
        destinationIp: this.generateRandomIp(),
        protocol: this.getRandomProtocol(),
        ttl: Math.floor(Math.random() * 64) + 64
      };
      
      // 模拟传输层信息
      const transportHeader = {
        sourcePort: this.getRandomPort(),
        destinationPort: this.getRandomPort(),
        flags: this.getRandomTcpFlags(),
        windowSize: Math.floor(Math.random() * 65535)
      };
      
      // 模拟应用层信息
      let applicationData = null;
      let packetType = 'OTHER';
      
      if (transportHeader.destinationPort === 80 || transportHeader.sourcePort === 80) {
        applicationData = this.generateRandomHttpData();
        packetType = 'HTTP';
      } else if (transportHeader.destinationPort === 443 || transportHeader.sourcePort === 443) {
        packetType = 'HTTPS';
      } else if (ipHeader.protocol === 'ICMP') {
        packetType = 'ICMP';
      }
      
      // 计算数据包大小
      const packetSize = Math.floor(Math.random() * 1500) + 64;
      
      // 构建解析后的数据包
      const parsedPacket = {
        timestamp: new Date(),
        size: packetSize,
        direction: Math.random() > 0.5 ? 'inbound' : 'outbound',
        ipHeader,
        transportHeader,
        applicationData,
        type: packetType,
        protocol: ipHeader.protocol,
        isFragmented: Math.random() < 0.01
      };
      
      return parsedPacket;
    } catch (error) {
      this.logger.error('解析数据包失败:', error);
      return null;
    }
  }

  // 更新数据包统计信息
  updatePacketStatistics(parsedPacket) {
    const { protocol, size, direction, ipHeader, transportHeader, type } = parsedPacket;
    
    // 更新总体统计
    this.statistics.totalPackets++;
    this.statistics.totalBytes += size;
    
    // 更新带宽统计
    if (direction === 'inbound') {
      this.statistics.bandwidth.inbound += size;
    } else {
      this.statistics.bandwidth.outbound += size;
    }
    this.statistics.bandwidth.total = this.statistics.bandwidth.inbound + this.statistics.bandwidth.outbound;
    
    // 更新协议统计
    switch (protocol) {
      case 'TCP':
        this.statistics.tcpPackets++;
        break;
      case 'UDP':
        this.statistics.udpPackets++;
        break;
      case 'ICMP':
        this.statistics.icmpPackets++;
        break;
    }
    
    // 更新应用层协议统计
    if (type === 'HTTP') {
      this.statistics.httpRequests++;
    } else if (type === 'HTTPS') {
      this.statistics.httpsRequests++;
    }
    
    // 更新协议分布
    this.updateProtocolDistribution(protocol);
    
    // 更新IP地址统计
    this.updateIpStatistics(ipHeader.sourceIp, 'sources');
    this.updateIpStatistics(ipHeader.destinationIp, 'destinations');
    
    // 更新端口统计
    this.updatePortStatistics(transportHeader.sourcePort, 'sources');
    this.updatePortStatistics(transportHeader.destinationPort, 'destinations');
    
    // 更新活动连接数
    this.statistics.activeConnections = this.activeConnections.size;
    
    // 更新峰值连接数
    if (this.activeConnections.size > this.statistics.peakConnections) {
      this.statistics.peakConnections = this.activeConnections.size;
    }
    
    // 更新最后更新时间
    this.statistics.lastUpdated = new Date();
  }

  // 更新协议分布
  updateProtocolDistribution(protocol) {
    if (!this.statistics.protocols[protocol]) {
      this.statistics.protocols[protocol] = 0;
    }
    this.statistics.protocols[protocol]++;
  }

  // 更新IP统计
  updateIpStatistics(ip, type) {
    const ipMap = this.statistics.ipAddresses[type];
    
    if (!ipMap.has(ip)) {
      ipMap.set(ip, 0);
    }
    ipMap.set(ip, ipMap.get(ip) + 1);
  }

  // 更新端口统计
  updatePortStatistics(port, type) {
    const portMap = this.statistics.ports[type];
    
    if (!portMap.has(port)) {
      portMap.set(port, 0);
    }
    portMap.set(port, portMap.get(port) + 1);
  }

  // 跟踪连接
  trackConnection(parsedPacket) {
    const { ipHeader, transportHeader, timestamp, direction } = parsedPacket;
    
    // 创建连接标识符
    const srcEndpoint = `${ipHeader.sourceIp}:${transportHeader.sourcePort}`;
    const dstEndpoint = `${ipHeader.destinationIp}:${transportHeader.destinationPort}`;
    const connectionId = direction === 'inbound' ? `${dstEndpoint}-${srcEndpoint}` : `${srcEndpoint}-${dstEndpoint}`;
    
    // 获取或创建连接记录
    let connection = this.activeConnections.get(connectionId);
    
    if (!connection) {
      connection = {
        id: connectionId,
        source: srcEndpoint,
        destination: dstEndpoint,
        protocol: ipHeader.protocol,
        startTime: timestamp,
        lastActivity: timestamp,
        packets: {
          inbound: 0,
          outbound: 0,
          total: 0
        },
        bytes: {
          inbound: 0,
          outbound: 0,
          total: 0
        },
        state: 'ESTABLISHED'
      };
      
      this.activeConnections.set(connectionId, connection);
      
      // 通知新连接
      this.notify('connectionEstablished', connection);
    }
    
    // 更新连接统计
    connection.lastActivity = timestamp;
    connection.packets[direction]++;
    connection.packets.total++;
    connection.bytes[direction] += parsedPacket.size;
    connection.bytes.total += parsedPacket.size;
    
    // 更新连接状态（基于TCP标志等）
    if (transportHeader.flags) {
      this.updateConnectionState(connection, transportHeader.flags);
    }
  }

  // 更新连接状态
  updateConnectionState(connection, flags) {
    if (flags.includes('FIN') || flags.includes('RST')) {
      connection.state = 'CLOSING';
      
      // 标记为待清理
      setTimeout(() => {
        this.activeConnections.delete(connection.id);
        this.notify('connectionClosed', connection);
      }, 5000);
    }
  }

  // 分析流量流
  analyzeFlow(parsedPacket) {
    if (!this.config.enableFlowAnalysis) return;
    
    const { ipHeader, transportHeader, size, direction } = parsedPacket;
    
    // 创建流标识符（5元组）
    const flowKey = `${ipHeader.sourceIp}:${transportHeader.sourcePort}-${ipHeader.destinationIp}:${transportHeader.destinationPort}-${ipHeader.protocol}`;
    
    // 获取或创建流记录
    let flow = this.flowTable.get(flowKey);
    
    if (!flow) {
      flow = {
        key: flowKey,
        startTime: new Date(),
        lastSeen: new Date(),
        packets: 0,
        bytes: 0,
        bytesIn: 0,
        bytesOut: 0,
        sourceIp: ipHeader.sourceIp,
        destinationIp: ipHeader.destinationIp,
        sourcePort: transportHeader.sourcePort,
        destinationPort: transportHeader.destinationPort,
        protocol: ipHeader.protocol
      };
      
      this.flowTable.set(flowKey, flow);
    }
    
    // 更新流统计
    flow.lastSeen = new Date();
    flow.packets++;
    flow.bytes += size;
    
    if (direction === 'inbound') {
      flow.bytesIn += size;
    } else {
      flow.bytesOut += size;
    }
    
    // 检查流阈值
    this.checkFlowThresholds(flow);
  }

  // 检查流阈值
  checkFlowThresholds(flow) {
    // 检测大流量
    if (flow.bytes > 1024 * 1024 * 100) { // 100MB
      this.notify('largeFlowDetected', flow);
    }
    
    // 检测异常字节比例
    const totalBytes = flow.bytesIn + flow.bytesOut;
    if (totalBytes > 0) {
      const inRatio = flow.bytesIn / totalBytes;
      const outRatio = flow.bytesOut / totalBytes;
      
      // 检查数据倾斜（95%以上单向）
      if (inRatio > 0.95 || outRatio > 0.95) {
        this.notify('flowDataSkew', {
          flow,
          inRatio,
          outRatio
        });
      }
    }
  }

  // 清理过期流
  cleanupExpiredFlows() {
    const now = Date.now();
    const expiredKeys = [];
    
    for (const [key, flow] of this.flowTable.entries()) {
      if (now - flow.lastSeen.getTime() > this.config.flowTimeout) {
        expiredKeys.push(key);
        
        // 通知流超时
        this.notify('flowExpired', flow);
      }
    }
    
    // 删除过期流
    for (const key of expiredKeys) {
      this.flowTable.delete(key);
    }
    
    // 限制流表大小
    if (this.flowTable.size > this.config.maxFlows) {
      const oldestKeys = Array.from(this.flowTable.entries())
        .sort((a, b) => a[1].lastSeen - b[1].lastSeen)
        .slice(0, this.flowTable.size - this.config.maxFlows)
        .map(entry => entry[0]);
      
      for (const key of oldestKeys) {
        this.flowTable.delete(key);
      }
    }
  }

  // 检测异常
  detectAnomalies(parsedPacket) {
    // 检查带宽异常
    this.checkBandwidthAnomalies();
    
    // 检查连接率异常
    this.checkConnectionRateAnomalies();
    
    // 检查协议分布异常
    this.checkProtocolDistributionAnomalies();
    
    // 检查特定IP的异常行为
    this.checkIpAnomalies(parsedPacket.ipHeader.sourceIp);
  }

  // 检查带宽异常
  checkBandwidthAnomalies() {
    const currentBandwidth = this.statistics.bandwidth.total / 5; // 5秒间隔
    
    // 检查配置的带宽阈值
    if (this.config.alertOnHighBandwidth && currentBandwidth > this.config.bandwidthThreshold) {
      this.notify('bandwidthThresholdExceeded', {
        currentBandwidth,
        threshold: this.config.bandwidthThreshold,
        timestamp: new Date()
      });
    }
    
    // 检查基线偏差
    const baselineAvg = this.trafficBaselines.bandwidthUsage.avg;
    if (baselineAvg > 0 && currentBandwidth > baselineAvg * 3) {
      this.notify('bandwidthAnomaly', {
        currentBandwidth,
        baselineAverage: baselineAvg,
        deviation: currentBandwidth / baselineAvg,
        timestamp: new Date()
      });
    }
  }

  // 检查连接率异常
  checkConnectionRateAnomalies() {
    const currentConnections = this.activeConnections.size;
    const baselineMax = this.trafficBaselines.connectionRate.max;
    
    // 检查连接数突增
    if (baselineMax > 0 && currentConnections > baselineMax * 2) {
      this.notify('connectionRateAnomaly', {
        currentConnections,
        baselineMax,
        timestamp: new Date()
      });
    }
  }

  // 检查协议分布异常
  checkProtocolDistributionAnomalies() {
    const total = this.statistics.totalPackets;
    if (total < 100) return; // 数据不足
    
    for (const [protocol, count] of Object.entries(this.statistics.protocols)) {
      const percentage = (count / total) * 100;
      const baselinePercentage = this.trafficBaselines.protocolDistribution[protocol] || 0;
      
      // 检查协议分布突变
      if (baselinePercentage > 0 && percentage > baselinePercentage * 5) {
        this.notify('protocolDistributionAnomaly', {
          protocol,
          currentPercentage: percentage,
          baselinePercentage,
          timestamp: new Date()
        });
      }
    }
  }

  // 检查IP异常
  checkIpAnomalies(ipAddress) {
    const sourceCount = this.statistics.ipAddresses.sources.get(ipAddress) || 0;
    
    // 检查单一IP的连接数过多
    if (sourceCount > 100) {
      this.notify('suspiciousIpActivity', {
        ipAddress,
        connectionCount: sourceCount,
        timestamp: new Date()
      });
    }
  }

  // 检查可疑模式
  checkSuspiciousPatterns(parsedPacket) {
    const { ipHeader, transportHeader, applicationData } = parsedPacket;
    
    // 检查SYN扫描
    if (transportHeader.flags && transportHeader.flags === 'SYN' && 
        this.isPotentialSynScan(ipHeader.sourceIp)) {
      this.notify('potentialSynScan', parsedPacket);
    }
    
    // 检查端口扫描（连接到多个目标端口）
    this.checkPortScanActivity(ipHeader.sourceIp);
    
    // 检查HTTP中的可疑模式
    if (applicationData && typeof applicationData === 'object') {
      this.checkHttpSuspiciousPatterns(applicationData, parsedPacket);
    }
    
    // 检查异常TTL值
    if (ipHeader.ttl < 20 || ipHeader.ttl > 250) {
      this.notify('abnormalTtl', {
        ipAddress: ipHeader.sourceIp,
        ttl: ipHeader.ttl,
        timestamp: new Date()
      });
    }
  }

  // 检查潜在的SYN扫描
  isPotentialSynScan(sourceIp) {
    // 简化实现，在真实环境中需要更复杂的逻辑
    const synPackets = this.countSynPacketsFromIp(sourceIp);
    return synPackets > 10; // 如果短时间内SYN包超过10个
  }

  // 计算来自特定IP的SYN包数量
  countSynPacketsFromIp(ipAddress) {
    // 简化实现，在真实环境中需要维护一个计数器
    return Math.floor(Math.random() * 20);
  }

  // 检查端口扫描活动
  checkPortScanActivity(sourceIp) {
    // 简化实现，检查目标端口多样性
    const uniquePorts = this.getUniqueDestinationPortsFromIp(sourceIp);
    
    if (uniquePorts > 20) {
      this.notify('potentialPortScan', {
        ipAddress: sourceIp,
        uniquePortsScanned: uniquePorts,
        timestamp: new Date()
      });
    }
  }

  // 获取来自特定IP的唯一目标端口数
  getUniqueDestinationPortsFromIp(ipAddress) {
    // 简化实现
    return Math.floor(Math.random() * 30);
  }

  // 检查HTTP可疑模式
  checkHttpSuspiciousPatterns(httpData, packet) {
    const { method, uri, headers, body } = httpData;
    
    // 检查可疑HTTP方法
    if (['CONNECT', 'TRACE', 'TRACK'].includes(method)) {
      this.notify('suspiciousHttpMethod', { ...packet, httpData });
    }
    
    // 检查可能的路径遍历
    if (uri && (uri.includes('../') || uri.includes('..\\') || uri.includes('\x2e\x2e'))) {
      this.notify('pathTraversalAttempt', { ...packet, httpData });
    }
    
    // 检查SQL注入模式
    const sqlPatterns = ['SELECT.*FROM', 'INSERT.*INTO', 'DELETE.*FROM', 'DROP.*TABLE', '--', ';'];
    if ((uri && sqlPatterns.some(pattern => uri.match(new RegExp(pattern, 'i')))) ||
        (body && sqlPatterns.some(pattern => body.match(new RegExp(pattern, 'i'))))) {
      this.notify('potentialSqlInjection', { ...packet, httpData });
    }
    
    // 检查XSS模式
    const xssPatterns = ['<script', 'javascript:', 'onerror=', 'onload='];
    if ((uri && xssPatterns.some(pattern => uri.match(new RegExp(pattern, 'i')))) ||
        (body && xssPatterns.some(pattern => body.match(new RegExp(pattern, 'i'))))) {
      this.notify('potentialXss', { ...packet, httpData });
    }
  }

  // 存储数据包
  storePacket(packet) {
    try {
      // 添加到最近数据包列表
      this.recentPackets.push(packet);
      
      // 限制存储大小
      if (this.recentPackets.length > this.config.maxStoredPackets) {
        this.recentPackets.shift();
      }
      
      // 在真实环境中，这里应该将数据包保存到磁盘
      
    } catch (error) {
      this.logger.error('存储数据包失败:', error);
      this.statistics.errors.bufferOverflows++;
    }
  }

  // 更新统计信息
  updateStatistics() {
    // 计算实际带宽（字节/秒）
    const currentTime = Date.now();
    
    // 更新时间窗口数据
    this.addToTimeWindows({
      timestamp: currentTime,
      packets: this.statistics.totalPackets,
      bytes: this.statistics.totalBytes,
      connections: this.activeConnections.size
    });
    
    // 重置带宽计数器（用于下一个时间窗口）
    this.statistics.bandwidth = {
      inbound: 0,
      outbound: 0,
      total: 0
    };
  }

  // 更新流量基线
  updateTrafficBaselines() {
    try {
      const now = new Date();
      const hour = now.getHours();
      const day = now.getDay();
      
      // 更新小时流量基线
      this.trafficBaselines.hourlyTraffic[hour] = this.statistics.bandwidth.total;
      
      // 更新日流量基线
      this.trafficBaselines.dailyTraffic[day] = this.statistics.bandwidth.total;
      
      // 更新协议分布基线
      const totalPackets = this.statistics.totalPackets;
      if (totalPackets > 0) {
        for (const [protocol, count] of Object.entries(this.statistics.protocols)) {
          this.trafficBaselines.protocolDistribution[protocol] = (count / totalPackets) * 100;
        }
      }
      
      // 更新连接率基线
      this.trafficBaselines.connectionRate = {
        min: Math.min(this.statistics.activeConnections, this.trafficBaselines.connectionRate.min || Infinity),
        max: Math.max(this.statistics.activeConnections, this.trafficBaselines.connectionRate.max || 0),
        avg: this.calculateAverageConnectionRate()
      };
      
      // 更新带宽使用基线
      this.trafficBaselines.bandwidthUsage = {
        min: Math.min(this.statistics.bandwidth.total, this.trafficBaselines.bandwidthUsage.min || Infinity),
        max: Math.max(this.statistics.bandwidth.total, this.trafficBaselines.bandwidthUsage.max || 0),
        avg: this.calculateAverageBandwidth()
      };
      
      // 更新最后更新时间
      this.trafficBaselines.lastUpdated = now;
      
    } catch (error) {
      this.logger.error('更新流量基线失败:', error);
    }
  }

  // 计算平均连接率
  calculateAverageConnectionRate() {
    // 简化实现，使用最近的连接数平均值
    const recentWindows = this.timeWindows['5m'].slice(-10);
    if (recentWindows.length === 0) return 0;
    
    const sum = recentWindows.reduce((acc, window) => acc + window.connections, 0);
    return sum / recentWindows.length;
  }

  // 计算平均带宽
  calculateAverageBandwidth() {
    // 简化实现，使用最近的带宽平均值
    const recentWindows = this.timeWindows['5m'].slice(-10);
    if (recentWindows.length === 0) return 0;
    
    const sum = recentWindows.reduce((acc, window) => acc + window.bytes, 0);
    return sum / recentWindows.length;
  }

  // 更新时间窗口数据
  updateTimeWindows() {
    const now = Date.now();
    
    // 清理过期数据
    for (const [window, data] of Object.entries(this.timeWindows)) {
      const maxAge = this.getTimeWindowMaxAge(window);
      this.timeWindows[window] = data.filter(item => now - item.timestamp < maxAge);
    }
  }

  // 添加数据到时间窗口
  addToTimeWindows(data) {
    for (const window of Object.keys(this.timeWindows)) {
      this.timeWindows[window].push({ ...data });
    }
  }

  // 获取时间窗口最大年龄
  getTimeWindowMaxAge(window) {
    const maxAges = {
      '1m': 60 * 1000,      // 1分钟
      '5m': 5 * 60 * 1000,  // 5分钟
      '15m': 15 * 60 * 1000, // 15分钟
      '1h': 60 * 60 * 1000  // 1小时
    };
    
    return maxAges[window] || 60000;
  }

  // 清理资源
  cleanupResources() {
    this.activeConnections.clear();
    this.flowTable.clear();
    this.recentPackets = [];
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
      'potentialSynScan',
      'potentialPortScan',
      'pathTraversalAttempt',
      'potentialSqlInjection',
      'potentialXss',
      'suspiciousIpActivity',
      'bandwidthAnomaly',
      'flowDataSkew',
      'largeFlowDetected',
      'suspiciousHttpMethod',
      'abnormalTtl'
    ];
    
    return securityEvents.includes(event);
  }

  // 向入侵检测器报告
  reportToInvasionDetector(event, data) {
    try {
      if (window.invasionDetector) {
        window.invasionDetector.reportNetworkEvent({
          eventType: event,
          source: 'network_monitor',
          timestamp: new Date(),
          data: data
        });
      }
    } catch (error) {
      this.logger.error('向入侵检测器报告事件失败:', error);
    }
  }

  // 模拟捕获（用于演示和测试）
  startMockCapture() {
    if (this.mockCaptureInterval) {
      clearInterval(this.mockCaptureInterval);
    }
    
    // 模拟每100ms接收一个数据包
    this.mockCaptureInterval = setInterval(() => {
      if (this.isRunning) {
        this.handlePacket(this.generateMockPacket());
      }
    }, 100);
  }

  // 停止模拟捕获
  stopMockCapture() {
    if (this.mockCaptureInterval) {
      clearInterval(this.mockCaptureInterval);
      this.mockCaptureInterval = null;
    }
  }

  // 生成模拟数据包
  generateMockPacket() {
    // 在真实环境中，这里会是实际的数据包
    return { mock: true, timestamp: Date.now() };
  }

  // 生成随机IP地址
  generateRandomIp() {
    // 生成私有IP地址范围
    const ranges = [
      { start: 10, end: 10 },        // 10.0.0.0/8
      { start: 172, end: 172 },      // 172.16.0.0/12
      { start: 192, end: 192 }       // 192.168.0.0/16
    ];
    
    const range = ranges[Math.floor(Math.random() * ranges.length)];
    const octet1 = range.start + Math.floor(Math.random() * (range.end - range.start + 1));
    
    let octet2, octet3;
    if (octet1 === 10) {
      octet2 = Math.floor(Math.random() * 256);
      octet3 = Math.floor(Math.random() * 256);
    } else if (octet1 === 172) {
      octet2 = 16 + Math.floor(Math.random() * 16); // 172.16-31.x.x
      octet3 = Math.floor(Math.random() * 256);
    } else { // 192.168.x.x
      octet2 = 168;
      octet3 = Math.floor(Math.random() * 256);
    }
    
    const octet4 = Math.floor(Math.random() * 256);
    
    return `${octet1}.${octet2}.${octet3}.${octet4}`;
  }

  // 获取随机协议
  getRandomProtocol() {
    const protocols = ['TCP', 'UDP', 'ICMP'];
    const weights = [0.7, 0.25, 0.05]; // TCP占70%，UDP占25%，ICMP占5%
    
    let sum = 0;
    const r = Math.random();
    
    for (let i = 0; i < weights.length; i++) {
      sum += weights[i];
      if (r <= sum) {
        return protocols[i];
      }
    }
    
    return 'TCP'; // 默认返回TCP
  }

  // 获取随机端口
  getRandomPort() {
    // 常见端口出现概率更高
    const commonPorts = [22, 23, 25, 53, 80, 443, 3306, 5432];
    
    if (Math.random() < 0.3) { // 30%概率返回常见端口
      return commonPorts[Math.floor(Math.random() * commonPorts.length)];
    }
    
    // 随机端口
    return Math.floor(Math.random() * 65535) + 1;
  }

  // 获取随机TCP标志
  getRandomTcpFlags() {
    const flags = ['SYN', 'ACK', 'SYN-ACK', 'PSH-ACK', 'FIN-ACK', 'RST'];
    const weights = [0.1, 0.6, 0.1, 0.15, 0.03, 0.02];
    
    let sum = 0;
    const r = Math.random();
    
    for (let i = 0; i < weights.length; i++) {
      sum += weights[i];
      if (r <= sum) {
        return flags[i];
      }
    }
    
    return 'ACK'; // 默认返回ACK
  }

  // 生成随机HTTP数据
  generateRandomHttpData() {
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD'];
    const paths = ['/api/users', '/login', '/dashboard', '/products', '/search?q=test'];
    const userAgents = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
      'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36'
    ];
    
    return {
      method: methods[Math.floor(Math.random() * methods.length)],
      uri: paths[Math.floor(Math.random() * paths.length)],
      headers: {
        'User-Agent': userAgents[Math.floor(Math.random() * userAgents.length)],
        'Accept': 'text/html,application/json',
        'Connection': 'keep-alive'
      },
      body: Math.random() > 0.5 ? '{"username":"test","password":"test123"}' : null
    };
  }

  // 获取监控器状态
  getStatus() {
    return {
      isRunning: this.isRunning,
      captureEnabled: this.config.captureEnabled,
      captureStartTime: this.captureStartTime,
      uptime: this.isRunning ? new Date() - this.captureStartTime : 0,
      statistics: this.getStatistics()
    };
  }

  // 获取统计信息
  getStatistics() {
    // 返回统计信息的副本
    return {
      ...this.statistics,
      ipAddresses: {
        sources: Array.from(this.statistics.ipAddresses.sources.entries()),
        destinations: Array.from(this.statistics.ipAddresses.destinations.entries())
      },
      ports: {
        sources: Array.from(this.statistics.ports.sources.entries()),
        destinations: Array.from(this.statistics.ports.destinations.entries())
      }
    };
  }

  // 获取活动连接
  getActiveConnections() {
    return Array.from(this.activeConnections.values());
  }

  // 获取流量流表
  getFlowTable() {
    return Array.from(this.flowTable.values());
  }

  // 获取最近的数据包
  getRecentPackets(limit = 100) {
    return this.recentPackets.slice(-limit).reverse();
  }

  // 获取流量基线
  getTrafficBaselines() {
    return { ...this.trafficBaselines };
  }

  // 获取时间窗口数据
  getTimeWindowData(window) {
    return this.timeWindows[window] || [];
  }

  // 更新配置
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    
    // 如果捕获引擎正在运行，重新应用过滤器
    if (this.isRunning) {
      this.applyCaptureFilters();
    }
    
    return this.config;
  }

  // 获取配置
  getConfig() {
    return { ...this.config };
  }

  // 导出数据
  exportData(format = 'json') {
    const exportData = {
      timestamp: new Date(),
      statistics: this.getStatistics(),
      activeConnections: this.getActiveConnections(),
      flowTable: this.getFlowTable(),
      recentPackets: this.getRecentPackets(1000),
      trafficBaselines: this.getTrafficBaselines()
    };
    
    if (format === 'json') {
      return JSON.stringify(exportData, null, 2);
    }
    
    return exportData;
  }

  // 导入配置
  importConfig(configData) {
    try {
      this.config = { ...this.config, ...configData };
      return true;
    } catch (error) {
      this.logger.error('导入配置失败:', error);
      return false;
    }
  }

  // 重置监控器
  reset() {
    this.stop();
    
    // 重置所有状态
    this.statistics = this.initializeStatistics();
    this.trafficBaselines = this.initializeBaselines();
    this.activeConnections.clear();
    this.flowTable.clear();
    this.recentPackets = [];
    
    // 重置时间窗口
    for (const window of Object.keys(this.timeWindows)) {
      this.timeWindows[window] = [];
    }
    
    this.logger.info('网络流量监控器已重置');
    return true;
  }

  // 关闭监控器
  shutdown() {
    this.stop();
    
    // 清理全局引用
    if (window.networkTrafficMonitor === this) {
      delete window.networkTrafficMonitor;
    }
    
    this.logger.info('网络流量监控器已关闭');
    return true;
  }
}

export default NetworkTrafficMonitor;

// 创建默认实例
let defaultMonitor = null;

export function getNetworkTrafficMonitor() {
  if (!defaultMonitor) {
    defaultMonitor = new NetworkTrafficMonitor();
  }
  return defaultMonitor;
}