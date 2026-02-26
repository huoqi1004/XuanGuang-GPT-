# 安全检测模型训练与使用指南

## 目录

1. [项目概述](#项目概述)
2. [环境准备](#环境准备)
3. [数据准备](#数据准备)
4. [模型训练](#模型训练)
5. [模型评估](#模型评估)
6. [与DeepSeek协同使用](#与deepseek协同使用)
7. [模型集成](#模型集成)
8. [常见问题](#常见问题)

## 项目概述

本项目实现了一个安全检测机器学习框架，该框架可以：

- 训练本地模型检测恶意文件和网络威胁
- 与DeepSeek大语言模型协同工作，提供更精准的检测能力
- 集成到现有的安全检测系统中
- 支持增量学习和模型更新

## 环境准备

### 系统要求

- Python 3.8+
- PyTorch 1.10+
- Node.js 14+
- 足够的磁盘空间存储数据集和模型

### Python依赖安装

```bash
# 进入ml目录
cd e:\玄光安全GPT\ml

# 创建并激活虚拟环境（推荐）
python -m venv venv
venv\Scripts\activate

# 安装依赖
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118  # 根据你的CUDA版本选择
pip install numpy pandas scikit-learn matplotlib seaborn requests tqdm
```

### 配置文件设置

编辑 `ml/config.json` 文件，配置以下参数：

```json
{
  "data_paths": {
    "training_data": "ml/data/training",
    "validation_data": "ml/data/validation",
    "testing_data": "ml/data/testing",
    "raw_data": "ml/data/raw"
  },
  "model_params": {
    "input_dim": 64,
    "hidden_dims": [32, 16],
    "output_dim": 1,
    "dropout_rate": 0.3,
    "learning_rate": 0.001
  },
  "training_config": {
    "batch_size": 32,
    "epochs": 50,
    "early_stopping_patience": 10,
    "save_interval": 5,
    "log_dir": "ml/logs",
    "model_save_path": "ml/models"
  },
  "cooperative_supervision": {
    "deepseek_integration": true,
    "confidence_threshold": 0.85,
    "feedback_collection": true,
    "retrain_on_feedback": true
  }
}
```

## 数据准备

### 数据集结构

训练数据集需要按照以下结构组织：

```
ml/data/
├── training/           # 训练数据集
│   ├── files/          # 文件分析样本
│   ├── scans/          # 网络扫描样本
│   └── metadata.json   # 训练数据元信息
├── validation/         # 验证数据集
└── testing/            # 测试数据集
```

### 生成示例数据

可以使用提供的脚本生成示例数据：

```bash
cd e:\玄光安全GPT\ml\data
python generate_sample_data.py --num-training 100 --num-validation 30 --num-testing 20
```

### 自定义数据准备

如果要使用自己的数据集，请确保遵循以下格式：

#### 文件分析样本格式 (files/*.json)

```json
{
  "file_id": "unique_file_identifier",
  "file_name": "sample.exe",
  "file_size": 10240,
  "file_hash": "a1b2c3d4e5f6...",
  "file_extension": ".exe",
  "created_time": 1640995200000,
  "modified_time": 1640995200000,
  "features": [0.1, 0.2, ..., 0.0],  # 64维特征向量
  "label": 1,  # 1表示恶意，0表示良性
  "source": "malware_sample",
  "metadata": {
    "signatures": ["trojan.agent", "ransomware"],
    "severity": "high",
    "vt_detections": 24,
    "vt_total": 60
  }
}
```

#### 网络扫描样本格式 (scans/*.json)

```json
{
  "scan_id": "unique_scan_identifier",
  "target": "192.168.1.0/24",
  "scan_time": 1640995200000,
  "scan_duration": 120,
  "scan_type": "comprehensive",
  "features": [0.0, 0.1, ..., 0.3],  # 64维特征向量
  "label": 0,  # 1表示存在威胁，0表示安全
  "source": "internal_scan",
  "metadata": {
    "open_ports": [80, 443, 22],
    "vulnerabilities": ["CVE-2021-44228", "CVE-2020-0796"],
    "severity": "medium",
    "asset_count": 25
  }
}
```

## 模型训练

### 训练脚本

创建一个训练脚本 `train.py`：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模型训练脚本
"""

import os
import sys
import json
import torch

# 添加src目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from data_processor import DataProcessor
from model import SecurityMLP
from trainer import ModelTrainer

def main():
    # 加载配置
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    # 初始化数据处理器
    data_processor = DataProcessor(config)
    
    # 加载数据
    print("加载训练数据...")
    train_loader, val_loader = data_processor.prepare_dataloaders()
    
    # 初始化模型
    model = SecurityMLP(
        input_dim=config['model_params']['input_dim'],
        hidden_dims=config['model_params']['hidden_dims'],
        output_dim=config['model_params']['output_dim'],
        dropout_rate=config['model_params']['dropout_rate']
    )
    
    # 初始化训练器
    trainer = ModelTrainer(model, config)
    
    # 开始训练
    print("开始训练模型...")
    history = trainer.train(train_loader, val_loader)
    
    # 保存最终模型
    model_save_path = os.path.join(config['training_config']['model_save_path'], 'security_model_final.pt')
    trainer.save_model(model_save_path)
    print(f"模型已保存到: {model_save_path}")
    
    # 训练完成
    print("训练完成！")

if __name__ == "__main__":
    main()
```

### 运行训练

```bash
cd e:\玄光安全GPT\ml
python train.py
```

### 训练参数调整

- **批量大小 (batch_size)**: 影响内存使用和训练稳定性
- **学习率 (learning_rate)**: 控制参数更新幅度
- **训练轮数 (epochs)**: 整个数据集的训练次数
- **早停机制 (early_stopping_patience)**: 防止过拟合
- **隐藏层维度 (hidden_dims)**: 模型复杂度
- **Dropout率 (dropout_rate)**: 防止过拟合

## 模型评估

### 评估脚本

创建评估脚本 `evaluate.py`：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模型评估脚本
"""

import os
import sys
import json
import torch
import matplotlib.pyplot as plt
import numpy as np

# 添加src目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from data_processor import DataProcessor
from model import SecurityMLP
from trainer import ModelTrainer

def main():
    # 加载配置
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    # 初始化数据处理器
    data_processor = DataProcessor(config)
    
    # 加载测试数据
    print("加载测试数据...")
    test_loader = data_processor.prepare_test_dataloader()
    
    # 加载模型
    model_path = os.path.join(config['training_config']['model_save_path'], 'security_model_final.pt')
    model = SecurityMLP(
        input_dim=config['model_params']['input_dim'],
        hidden_dims=config['model_params']['hidden_dims'],
        output_dim=config['model_params']['output_dim'],
        dropout_rate=config['model_params']['dropout_rate']
    )
    model.load_state_dict(torch.load(model_path))
    
    # 初始化训练器
    trainer = ModelTrainer(model, config)
    
    # 评估模型
    print("评估模型性能...")
    metrics = trainer.evaluate(test_loader)
    
    # 打印评估结果
    print("\n评估结果:")
    print(f"准确率: {metrics['accuracy']:.4f}")
    print(f"精确率: {metrics['precision']:.4f}")
    print(f"召回率: {metrics['recall']:.4f}")
    print(f"F1分数: {metrics['f1_score']:.4f}")
    print(f"AUC-ROC: {metrics['auc_roc']:.4f}")
    
    # 保存评估报告
    os.makedirs('ml/reports', exist_ok=True)
    report_path = os.path.join('ml/reports', 'evaluation_report.json')
    with open(report_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    print(f"\n评估报告已保存到: {report_path}")
    
    # 生成并保存可视化结果
    trainer.plot_roc_curve(test_loader, save_path='ml/reports/roc_curve.png')
    trainer.plot_confusion_matrix(test_loader, save_path='ml/reports/confusion_matrix.png')
    print("\n可视化结果已保存到: ml/reports/")

if __name__ == "__main__":
    main()
```

### 运行评估

```bash
cd e:\玄光安全GPT\ml
python evaluate.py
```

## 与DeepSeek协同使用

### 配置DeepSeek API

1. 确保在配置文件中设置DeepSeek API密钥：

```json
{
  "cooperative_supervision": {
    "deepseek_api_key": "your_api_key_here",
    "deepseek_api_base": "https://api.deepseek.com",
    "confidence_threshold": 0.85
  }
}
```

### 使用协同监督

协同监督系统会在以下情况下触发：

1. 本地模型置信度低于阈值
2. 检测结果不确定
3. 需要深度分析的高风险样本

## 模型集成

### 与Node.js后端集成

已创建的 `ml_integration.js` 模块提供了与Node.js后端的集成接口：

```javascript
// 在Node.js应用中使用
const ml = require('./server/src/ml/ml_integration');

// 分析文件
async function analyzeFileExample() {
  try {
    const fileInfo = {
      path: 'path/to/file.exe',
      name: 'file.exe',
      size: 10240,
      hash: 'file_hash',
      extension: '.exe'
    };
    
    const result = await ml.analyzeFile(fileInfo);
    console.log('分析结果:', result);
  } catch (error) {
    console.error('分析失败:', error);
  }
}

// 分析扫描结果
async function analyzeScanExample() {
  try {
    const scanResult = {
      target: '192.168.1.0/24',
      scan_time: Date.now(),
      open_ports: [80, 443, 22],
      vulnerabilities: []
    };
    
    const result = await ml.analyzeScan(scanResult);
    console.log('扫描分析结果:', result);
  } catch (error) {
    console.error('扫描分析失败:', error);
  }
}
```

### 使用集成API

```javascript
// 在server/src/av.js中已添加的新API
const { scanFileWithML, analyzeNetworkScan } = require('./av');

// 扫描文件
const fileScanResult = await scanFileWithML('path/to/file');

// 分析网络扫描
const networkScanResult = await analyzeNetworkScan(scanData);
```

## 常见问题

### 训练过程中的常见问题

1. **内存不足错误**
   - 减小批量大小
   - 减少模型复杂度（减少隐藏层维度）
   - 使用梯度累积

2. **过拟合问题**
   - 增加Dropout率
   - 增加正则化强度
   - 使用早停机制
   - 增加训练数据量

3. **训练速度慢**
   - 使用GPU加速（确保正确安装了CUDA版本的PyTorch）
   - 增加批量大小
   - 优化数据加载过程

### 集成问题

1. **Python模块加载失败**
   - 确保Python虚拟环境正确配置
   - 检查Python路径和依赖安装

2. **IPC通信错误**
   - 检查Node.js和Python进程间通信配置
   - 确保端口没有被占用

3. **DeepSeek API连接错误**
   - 检查API密钥是否正确
   - 确认网络连接和防火墙设置

### 性能优化建议

1. **模型优化**
   - 使用模型量化（如PyTorch的量化工具）
   - 考虑模型剪枝
   - 使用更高效的网络架构

2. **推理加速**
   - 使用ONNX Runtime进行推理加速
   - 考虑批处理请求
   - 使用多线程或异步处理

3. **协同系统优化**
   - 调整置信度阈值
   - 优化API调用频率
   - 实现缓存机制减少重复分析