# 玄光安全GPT - 机器学习模块

这是玄光安全GPT的机器学习模块，用于训练和部署安全检测模型，与DeepSeek大语言模型协同工作，提高安全威胁检测的准确性和及时性。

## 功能特性

- **本地模型训练**：支持训练自定义的安全检测模型
- **多类型检测**：支持文件分析和网络扫描两种主要场景
- **DeepSeek协同**：与DeepSeek大语言模型构建协同监督体系
- **高度集成**：无缝集成到现有Node.js后端系统
- **完整评估**：提供详细的模型评估和可视化报告

## 目录结构

```
ml/
├── config.json               # 配置文件
├── README.md                 # 本文件
├── data/                     # 数据集目录
│   ├── README.md             # 数据格式说明
│   ├── generate_sample_data.py  # 示例数据生成脚本
│   ├── training/             # 训练数据集
│   ├── validation/           # 验证数据集
│   └── testing/              # 测试数据集
├── docs/                     # 文档
│   └── TRAINING_GUIDE.md     # 详细训练指南
├── models/                   # 模型存储目录
├── src/                      # 源代码
│   ├── data_processor.py     # 数据处理模块
│   ├── model.py              # 模型定义模块
│   ├── trainer.py            # 训练器模块
│   ├── cooperative_supervision.py  # 协同监督模块
│   └── integration.py        # 集成接口模块
├── train.py                  # 训练脚本（待创建）
└── evaluate.py               # 评估脚本（待创建）
```

## 快速开始

### 1. 环境准备

```bash
# 进入ml目录
cd e:\玄光安全GPT\ml

# 创建并激活虚拟环境
python -m venv venv
venv\Scripts\activate

# 安装依赖
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
pip install numpy pandas scikit-learn matplotlib seaborn requests tqdm
```

### 2. 生成示例数据

```bash
cd e:\玄光安全GPT\ml\data
python generate_sample_data.py --num-training 100 --num-validation 30 --num-testing 20
```

### 3. 训练模型

创建训练脚本并运行：

```bash
cd e:\玄光安全GPT\ml
python train.py
```

### 4. 评估模型

```bash
cd e:\玄光安全GPT\ml
python evaluate.py
```

### 5. 使用模型

模型训练完成后，系统会自动通过Node.js集成接口提供服务。

## 核心模块说明

- **data_processor.py**: 负责数据加载、预处理和特征提取
- **model.py**: 定义安全检测模型和协同模型架构
- **trainer.py**: 实现训练逻辑和模型评估功能
- **cooperative_supervision.py**: 实现与DeepSeek的协同监督机制
- **integration.py**: 提供与外部系统的集成接口

## 集成到主系统

机器学习模型通过以下方式与主系统集成：

1. **Node.js包装器**: `server/src/ml/ml_integration.js` 提供了JavaScript接口
2. **文件扫描API**: `scanFileWithML` 函数增强了现有的病毒扫描功能
3. **网络分析API**: `analyzeNetworkScan` 函数提供了网络扫描结果分析

## 详细文档

请参阅以下文档获取更多信息：

- [详细训练指南](docs/TRAINING_GUIDE.md) - 完整的训练、评估和使用说明
- [数据格式说明](data/README.md) - 训练数据的详细格式规范

## 注意事项

1. **安全问题**：处理实际恶意样本时请确保安全隔离
2. **性能优化**：生产环境使用时请考虑模型量化和批处理
3. **API密钥**：使用DeepSeek API时需配置有效的API密钥
4. **定期更新**：建议定期更新训练数据以提高模型性能

## 许可证

保留所有权利。仅供内部使用。