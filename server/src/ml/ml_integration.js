const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs').promises;

/**
 * 机器学习模型集成模块
 * 用于连接Node.js后端和Python机器学习模型
 */
class MLIntegration {
  constructor() {
    this.pythonProcess = null;
    this.modelReady = false;
    this.callbacks = new Map();
    this.callbackIdCounter = 0;
    this.modelPath = path.resolve(__dirname, '../../../ml/models/security_model.pth');
    this.pythonScriptPath = path.resolve(__dirname, '../../../ml/src/integration.py');
    
    // 启动Python进程
    this.startPythonProcess();
  }

  /**
   * 启动Python进程
   */
  startPythonProcess() {
    try {
      // 启动Python子进程
      this.pythonProcess = spawn('python', [this.pythonScriptPath], {
        stdio: ['pipe', 'pipe', 'pipe', 'ipc'], // 使用IPC通信
        env: { ...process.env, PYTHONIOENCODING: 'utf-8' }
      });

      // 处理Python输出
      this.pythonProcess.stdout.on('data', (data) => {
        const output = data.toString().trim();
        console.log('[ML] Python output:', output);
        
        // 检查模型是否准备就绪
        if (output.includes('MODEL_READY')) {
          this.modelReady = true;
          console.log('[ML] Model is ready for inference');
        }
        
        // 处理推理结果
        try {
          const result = JSON.parse(output);
          if (result.callbackId && this.callbacks.has(result.callbackId)) {
            const callback = this.callbacks.get(result.callbackId);
            this.callbacks.delete(result.callbackId);
            callback(null, result);
          }
        } catch (e) {
          // 非JSON输出，忽略
        }
      });

      // 处理Python错误
      this.pythonProcess.stderr.on('data', (data) => {
        console.error('[ML] Python error:', data.toString());
      });

      // 处理进程退出
      this.pythonProcess.on('exit', (code) => {
        console.error(`[ML] Python process exited with code ${code}`);
        this.modelReady = false;
        
        // 通知所有等待的回调
        this.callbacks.forEach(callback => {
          callback(new Error('Python process exited unexpectedly'));
        });
        this.callbacks.clear();
        
        // 尝试重启进程
        setTimeout(() => this.startPythonProcess(), 5000);
      });

      // 处理进程错误
      this.pythonProcess.on('error', (err) => {
        console.error('[ML] Failed to start Python process:', err);
        this.modelReady = false;
      });

    } catch (error) {
      console.error('[ML] Error starting Python process:', error);
    }
  }

  /**
   * 等待模型准备就绪
   */
  async waitForModelReady() {
    if (this.modelReady) return;
    
    return new Promise((resolve) => {
      const checkInterval = setInterval(() => {
        if (this.modelReady) {
          clearInterval(checkInterval);
          resolve();
        }
      }, 100);
    });
  }

  /**
   * 向Python进程发送消息
   */
  sendMessage(message) {
    return new Promise((resolve, reject) => {
      if (!this.pythonProcess || !this.modelReady) {
        reject(new Error('Python process not ready'));
        return;
      }

      const callbackId = `cb_${++this.callbackIdCounter}`;
      this.callbacks.set(callbackId, (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });

      const payload = {
        ...message,
        callbackId
      };

      try {
        this.pythonProcess.stdin.write(JSON.stringify(payload) + '\n');
      } catch (error) {
        reject(new Error('Failed to send message to Python process'));
      }
    });
  }

  /**
   * 执行文件分析
   * @param {Object} fileInfo - 文件信息对象
   * @returns {Promise<Object>} - 分析结果
   */
  async analyzeFile(fileInfo) {
    await this.waitForModelReady();
    
    try {
      const result = await this.sendMessage({
        action: 'analyze_file',
        data: fileInfo
      });
      return result;
    } catch (error) {
      console.error('[ML] File analysis error:', error);
      throw error;
    }
  }

  /**
   * 执行网络扫描分析
   * @param {Object} scanResult - 扫描结果对象
   * @returns {Promise<Object>} - 分析结果
   */
  async analyzeScan(scanResult) {
    await this.waitForModelReady();
    
    try {
      const result = await this.sendMessage({
        action: 'analyze_scan',
        data: scanResult
      });
      return result;
    } catch (error) {
      console.error('[ML] Scan analysis error:', error);
      throw error;
    }
  }

  /**
   * 协同分析（结合DeepSeek和本地模型）
   * @param {Object} data - 要分析的数据
   * @param {string} dataType - 数据类型 ('file' 或 'scan')
   * @returns {Promise<Object>} - 协同分析结果
   */
  async cooperativeAnalysis(data, dataType) {
    await this.waitForModelReady();
    
    try {
      const result = await this.sendMessage({
        action: 'cooperative_analysis',
        dataType,
        data
      });
      return result;
    } catch (error) {
      console.error('[ML] Cooperative analysis error:', error);
      throw error;
    }
  }

  /**
   * 关闭Python进程
   */
  close() {
    if (this.pythonProcess) {
      this.pythonProcess.kill('SIGTERM');
      this.pythonProcess = null;
    }
    this.modelReady = false;
    this.callbacks.clear();
  }
}

// 导出单例
module.exports = new MLIntegration();
