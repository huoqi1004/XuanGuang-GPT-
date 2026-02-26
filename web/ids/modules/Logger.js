/**
 * 入侵检测系统 - 高级日志模块
 * 提供多级别日志记录、文件轮转、格式化输出和日志分析功能
 */

class Logger {
  constructor(config = {}) {
    this.config = {
      // 日志级别: debug < info < warn < error < critical
      level: 'info',
      // 输出目标
      targets: ['console'], // console, file, database, http
      // 文件配置
      file: {
        path: './logs/ids.log',
        maxSize: 50 * 1024 * 1024, // 50MB
        maxFiles: 10,
        encoding: 'utf8'
      },
      // 日志格式
      format: 'json', // json, text, pretty
      // 日期格式
      dateFormat: 'YYYY-MM-DD HH:mm:ss.SSS',
      // 是否包含进程信息
      includeProcessInfo: true,
      // 是否包含堆栈跟踪
      includeStack: true,
      // 采样率（0-1）
      sampleRate: 1,
      // 缓冲设置
      buffer: {
        enabled: false,
        size: 1024,
        flushInterval: 1000
      },
      // 扩展配置
      ...config
    };

    // 日志级别映射
    this.levelMap = {
      debug: 0,
      info: 1,
      warn: 2,
      error: 3,
      critical: 4
    };

    // 当前日志级别数值
    this.currentLevel = this.levelMap[this.config.level] || this.levelMap.info;

    // 日志计数器
    this.counters = {
      debug: 0,
      info: 0,
      warn: 0,
      error: 0,
      critical: 0,
      total: 0
    };

    // 日志缓存
    this.logBuffer = [];

    // 初始化日志目标
    this.targets = this.initializeTargets();

    // 初始化缓冲区
    if (this.config.buffer.enabled) {
      this.startBufferFlusher();
    }

    // 记录初始化
    this.info('日志系统已初始化', {
      level: this.config.level,
      targets: this.config.targets
    });
  }

  /**
   * 初始化日志目标
   */
  initializeTargets() {
    const targets = {};
    
    this.config.targets.forEach(target => {
      switch (target) {
        case 'console':
          targets.console = this.createConsoleTarget();
          break;
        case 'file':
          targets.file = this.createFileTarget();
          break;
        case 'database':
          targets.database = this.createDatabaseTarget();
          break;
        case 'http':
          targets.http = this.createHttpTarget();
          break;
      }
    });
    
    return targets;
  }

  /**
   * 创建控制台日志目标
   */
  createConsoleTarget() {
    return {
      write: (logEntry) => {
        const formatted = this.formatLogEntry(logEntry);
        
        switch (logEntry.level) {
          case 'debug':
            if (console.debug) console.debug(formatted);
            else console.log(formatted);
            break;
          case 'info':
            console.info(formatted);
            break;
          case 'warn':
            console.warn(formatted);
            break;
          case 'error':
          case 'critical':
            console.error(formatted);
            break;
          default:
            console.log(formatted);
        }
      }
    };
  }

  /**
   * 创建文件日志目标
   */
  createFileTarget() {
    let fileStream = null;
    let currentSize = 0;
    let fileCount = 0;
    
    // 仅在Node.js环境下启用文件日志
    if (typeof window === 'undefined') {
      try {
        const fs = require('fs');
        const path = require('path');
        
        // 确保日志目录存在
        const logDir = path.dirname(this.config.file.path);
        if (!fs.existsSync(logDir)) {
          fs.mkdirSync(logDir, { recursive: true });
        }
        
        // 检查当前文件大小
        if (fs.existsSync(this.config.file.path)) {
          currentSize = fs.statSync(this.config.file.path).size;
        }
        
        // 创建文件流
        fileStream = fs.createWriteStream(this.config.file.path, {
          flags: 'a',
          encoding: this.config.file.encoding
        });
        
        console.log(`文件日志已启用: ${this.config.file.path}`);
      } catch (error) {
        console.error('创建文件日志失败:', error.message);
      }
    }
    
    return {
      write: (logEntry) => {
        if (!fileStream) return;
        
        const formatted = this.formatLogEntry(logEntry) + '\n';
        
        try {
          // 检查是否需要轮转
          if (currentSize + formatted.length > this.config.file.maxSize) {
            this.rotateLogFile();
            currentSize = 0;
          }
          
          fileStream.write(formatted);
          currentSize += formatted.length;
        } catch (error) {
          console.error('写入日志文件失败:', error.message);
        }
      },
      
      rotate: () => this.rotateLogFile()
    };
  }

  /**
   * 轮转日志文件
   */
  rotateLogFile() {
    if (typeof window !== 'undefined') return;
    
    try {
      const fs = require('fs');
      const path = require('path');
      const logPath = this.config.file.path;
      
      // 关闭当前文件流
      if (this.targets.file && this.targets.file.stream) {
        this.targets.file.stream.close();
      }
      
      // 计算新文件名
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const ext = path.extname(logPath);
      const baseName = path.basename(logPath, ext);
      const dirName = path.dirname(logPath);
      const newLogName = `${baseName}-${timestamp}${ext}`;
      const newLogPath = path.join(dirName, newLogName);
      
      // 重命名当前日志文件
      if (fs.existsSync(logPath)) {
        fs.renameSync(logPath, newLogPath);
      }
      
      // 创建新的日志文件
      this.targets.file.stream = fs.createWriteStream(logPath, {
        flags: 'w',
        encoding: this.config.file.encoding
      });
      
      // 清理旧文件
      this.cleanupOldLogFiles();
      
      this.info('日志文件已轮转', { newPath: newLogName });
    } catch (error) {
      console.error('轮转日志文件失败:', error.message);
    }
  }

  /**
   * 清理旧日志文件
   */
  cleanupOldLogFiles() {
    if (typeof window !== 'undefined') return;
    
    try {
      const fs = require('fs');
      const path = require('path');
      const logDir = path.dirname(this.config.file.path);
      const baseName = path.basename(this.config.file.path, path.extname(this.config.file.path));
      
      // 读取目录中的所有文件
      const files = fs.readdirSync(logDir)
        .filter(file => file.startsWith(baseName) && file !== path.basename(this.config.file.path))
        .map(file => ({
          name: file,
          path: path.join(logDir, file),
          stat: fs.statSync(path.join(logDir, file))
        }))
        .sort((a, b) => a.stat.mtime.getTime() - b.stat.mtime.getTime());
      
      // 删除超出数量限制的旧文件
      while (files.length > this.config.file.maxFiles - 1) {
        const oldest = files.shift();
        fs.unlinkSync(oldest.path);
      }
    } catch (error) {
      console.error('清理旧日志文件失败:', error.message);
    }
  }

  /**
   * 创建数据库日志目标
   */
  createDatabaseTarget() {
    // 模拟数据库日志目标
    // 实际环境中应连接到真实数据库
    return {
      write: (logEntry) => {
        // 模拟数据库写入
        console.log('[数据库日志] 记录日志:', logEntry.level, logEntry.message);
      }
    };
  }

  /**
   * 创建HTTP日志目标
   */
  createHttpTarget() {
    // 模拟HTTP日志目标
    // 实际环境中应发送到远程日志服务器
    return {
      write: (logEntry) => {
        // 模拟HTTP请求
        console.log('[HTTP日志] 发送日志到远程服务器');
      }
    };
  }

  /**
   * 格式化日志条目
   */
  formatLogEntry(logEntry) {
    const timestamp = this.formatDate(new Date(logEntry.timestamp));
    
    switch (this.config.format) {
      case 'json':
        return JSON.stringify({
          timestamp,
          level: logEntry.level,
          message: logEntry.message,
          ...logEntry.meta,
          ...(this.config.includeProcessInfo && this.getProcessInfo()),
          ...(logEntry.stack && { stack: logEntry.stack })
        });
        
      case 'pretty':
        const processInfo = this.config.includeProcessInfo ? ` [${this.getProcessInfoString()}]` : '';
        let formatted = `${timestamp} [${logEntry.level.toUpperCase()}]${processInfo} ${logEntry.message}`;
        
        if (Object.keys(logEntry.meta).length > 0) {
          formatted += ' ' + JSON.stringify(logEntry.meta);
        }
        
        if (logEntry.stack && this.config.includeStack) {
          formatted += '\n' + logEntry.stack;
        }
        
        return formatted;
        
      case 'text':
      default:
        return `${timestamp} [${logEntry.level}] ${logEntry.message}`;
    }
  }

  /**
   * 格式化日期
   */
  formatDate(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    const milliseconds = String(date.getMilliseconds()).padStart(3, '0');
    
    return this.config.dateFormat
      .replace('YYYY', year)
      .replace('MM', month)
      .replace('DD', day)
      .replace('HH', hours)
      .replace('mm', minutes)
      .replace('ss', seconds)
      .replace('SSS', milliseconds);
  }

  /**
   * 获取进程信息
   */
  getProcessInfo() {
    if (typeof window !== 'undefined') {
      return {
        userAgent: navigator.userAgent,
        url: window.location.href
      };
    }
    
    try {
      const process = require('process');
      return {
        pid: process.pid,
        ppid: process.ppid,
        hostname: require('os').hostname(),
        nodeVersion: process.version
      };
    } catch (error) {
      return {};
    }
  }

  /**
   * 获取进程信息字符串
   */
  getProcessInfoString() {
    const info = this.getProcessInfo();
    if (info.pid) {
      return `PID:${info.pid}`;
    }
    return '';
  }

  /**
   * 启动缓冲区刷新器
   */
  startBufferFlusher() {
    this.bufferInterval = setInterval(() => {
      this.flushBuffer();
    }, this.config.buffer.flushInterval);
  }

  /**
   * 刷新日志缓冲区
   */
  flushBuffer() {
    if (this.logBuffer.length === 0) return;
    
    const entries = [...this.logBuffer];
    this.logBuffer = [];
    
    entries.forEach(entry => {
      this.writeToTargets(entry);
    });
  }

  /**
   * 写入日志到所有目标
   */
  writeToTargets(logEntry) {
    Object.values(this.targets).forEach(target => {
      try {
        target.write(logEntry);
      } catch (error) {
        console.error(`写入日志到目标失败:`, error.message);
      }
    });
  }

  /**
   * 检查是否应该记录该级别的日志
   */
  shouldLog(level) {
    // 检查采样率
    if (Math.random() > this.config.sampleRate) {
      return false;
    }
    
    return this.levelMap[level] >= this.currentLevel;
  }

  /**
   * 创建日志条目
   */
  createLogEntry(level, message, meta = {}) {
    // 增加计数器
    this.counters[level]++;
    this.counters.total++;
    
    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      message: String(message),
      meta: meta || {}
    };
    
    // 添加堆栈跟踪（错误级别以上）
    if ((level === 'error' || level === 'critical') && this.config.includeStack) {
      const stack = new Error().stack;
      // 移除当前函数调用
      logEntry.stack = stack ? stack.split('\n').slice(2).join('\n') : '';
    }
    
    return logEntry;
  }

  /**
   * 记录调试日志
   */
  debug(message, meta = {}) {
    if (!this.shouldLog('debug')) return;
    
    const logEntry = this.createLogEntry('debug', message, meta);
    
    if (this.config.buffer.enabled) {
      this.logBuffer.push(logEntry);
      // 检查缓冲区大小
      if (this.logBuffer.length >= this.config.buffer.size) {
        this.flushBuffer();
      }
    } else {
      this.writeToTargets(logEntry);
    }
    
    return logEntry;
  }

  /**
   * 记录信息日志
   */
  info(message, meta = {}) {
    if (!this.shouldLog('info')) return;
    
    const logEntry = this.createLogEntry('info', message, meta);
    
    if (this.config.buffer.enabled) {
      this.logBuffer.push(logEntry);
      if (this.logBuffer.length >= this.config.buffer.size) {
        this.flushBuffer();
      }
    } else {
      this.writeToTargets(logEntry);
    }
    
    return logEntry;
  }

  /**
   * 记录警告日志
   */
  warn(message, meta = {}) {
    if (!this.shouldLog('warn')) return;
    
    const logEntry = this.createLogEntry('warn', message, meta);
    
    if (this.config.buffer.enabled) {
      this.logBuffer.push(logEntry);
      if (this.logBuffer.length >= this.config.buffer.size) {
        this.flushBuffer();
      }
    } else {
      this.writeToTargets(logEntry);
    }
    
    return logEntry;
  }

  /**
   * 记录错误日志
   */
  error(message, meta = {}) {
    if (!this.shouldLog('error')) return;
    
    // 如果message是Error对象，提取错误信息
    if (message instanceof Error) {
      meta = {
        ...meta,
        error: message.message,
        originalStack: message.stack
      };
      message = message.message;
    }
    
    const logEntry = this.createLogEntry('error', message, meta);
    
    if (this.config.buffer.enabled) {
      this.logBuffer.push(logEntry);
      // 错误日志立即刷新
      this.flushBuffer();
    } else {
      this.writeToTargets(logEntry);
    }
    
    return logEntry;
  }

  /**
   * 记录严重日志
   */
  critical(message, meta = {}) {
    if (!this.shouldLog('critical')) return;
    
    // 如果message是Error对象，提取错误信息
    if (message instanceof Error) {
      meta = {
        ...meta,
        error: message.message,
        originalStack: message.stack
      };
      message = message.message;
    }
    
    const logEntry = this.createLogEntry('critical', message, meta);
    
    // 严重日志立即写入，不经过缓冲区
    this.writeToTargets(logEntry);
    
    return logEntry;
  }

  /**
   * 设置日志级别
   */
  setLevel(level) {
    if (this.levelMap[level] !== undefined) {
      this.currentLevel = this.levelMap[level];
      this.config.level = level;
      this.info(`日志级别已更改为: ${level}`);
      return true;
    }
    
    this.warn(`无效的日志级别: ${level}`);
    return false;
  }

  /**
   * 获取日志统计信息
   */
  getStats() {
    return { ...this.counters };
  }

  /**
   * 重置日志统计信息
   */
  resetStats() {
    this.counters = {
      debug: 0,
      info: 0,
      warn: 0,
      error: 0,
      critical: 0,
      total: 0
    };
  }

  /**
   * 轮转日志（手动触发）
   */
  rotate() {
    if (this.targets.file && this.targets.file.rotate) {
      this.targets.file.rotate();
      return true;
    }
    return false;
  }

  /**
   * 更新配置
   */
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    
    // 更新日志级别
    if (newConfig.level) {
      this.setLevel(newConfig.level);
    }
    
    // 重新初始化目标（如果目标配置改变）
    if (newConfig.targets) {
      this.targets = this.initializeTargets();
    }
    
    this.info('日志配置已更新');
  }

  /**
   * 关闭日志系统
   */
  close() {
    // 停止缓冲区刷新器
    if (this.bufferInterval) {
      clearInterval(this.bufferInterval);
    }
    
    // 刷新缓冲区
    this.flushBuffer();
    
    // 关闭所有目标
    Object.values(this.targets).forEach(target => {
      if (target.close) {
        try {
          target.close();
        } catch (error) {
          console.error('关闭日志目标失败:', error.message);
        }
      }
    });
    
    console.log('日志系统已关闭');
  }

  /**
   * 创建日志记录器实例
   */
  static create(config = {}) {
    return new Logger(config);
  }
}

// 创建默认日志记录器实例
const defaultLogger = new Logger();

// 导出Logger类和默认实例
if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
  module.exports = {
    Logger,
    default: defaultLogger
  };
} else if (typeof window !== 'undefined') {
  window.Logger = Logger;
  window.logger = defaultLogger;
}
