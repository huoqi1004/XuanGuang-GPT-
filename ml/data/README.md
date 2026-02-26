# 安全检测模型训练数据集

本目录用于存储安全检测模型的训练、验证和测试数据集。

## 目录结构

```
ml/data/
├── training/           # 训练数据集
│   ├── files/          # 文件分析样本
│   ├── scans/          # 网络扫描样本
│   └── metadata.json   # 训练数据元信息
├── validation/         # 验证数据集
│   ├── files/          # 文件分析样本
│   ├── scans/          # 网络扫描样本
│   └── metadata.json   # 验证数据元信息
├── testing/            # 测试数据集
│   ├── files/          # 文件分析样本
│   ├── scans/          # 网络扫描样本
│   └── metadata.json   # 测试数据元信息
├── raw/                # 原始数据存储
│   ├── malware/        # 恶意样本（仅用于参考）
│   └── benign/         # 良性样本
└── generate_sample_data.py  # 示例数据生成脚本
```

## 数据格式

### 文件分析数据格式 (files/*.json)

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

### 网络扫描数据格式 (scans/*.json)

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

## 数据准备指南

1. 所有训练数据必须符合上述JSON格式
2. 确保数据集中包含足够的恶意和良性样本（建议平衡分布）
3. 特征向量必须标准化，范围在[0, 1]之间
4. 敏感信息必须脱敏处理
5. 对于文件分析，不存储实际恶意文件内容，仅存储特征和哈希值

## 示例数据生成

使用`generate_sample_data.py`脚本可以生成示例训练数据：

```bash
python generate_sample_data.py --num-training 100 --num-validation 30 --num-testing 20
```

## 数据来源

- 公开数据集：VirusTotal, CICIDS2017, NSL-KDD
- 内部收集：安全扫描日志、威胁情报数据
- 合成数据：使用脚本生成的模拟数据

## 注意事项

- **安全警告**：实际恶意样本必须严格隔离存储，仅供授权人员访问
- **法律合规**：确保获取和使用训练数据的过程符合相关法律法规
- **数据更新**：定期更新训练数据以提高模型检测新型威胁的能力