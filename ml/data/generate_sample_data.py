#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
示例数据生成脚本
用于生成符合格式要求的训练、验证和测试数据集
"""

import os
import json
import random
import argparse
from datetime import datetime, timedelta

# 确保中文显示正常
import sys
sys.stdout.reconfigure(encoding='utf-8')

# 配置
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILE_TYPES = ['.exe', '.dll', '.js', '.ps1', '.sh', '.py', '.doc', '.pdf', '.zip', '.rar']
MALWARE_FAMILIES = [
    'trojan.agent', 'ransomware', 'backdoor', 'worm', 'virus', 'spyware',
    'adware', 'rootkit', 'keylogger', 'exploit', 'loader', 'dropper'
]
VULNERABILITIES = [
    'CVE-2021-44228', 'CVE-2020-0796', 'CVE-2022-22965', 'CVE-2022-22947',
    'CVE-2021-34527', 'CVE-2017-0144', 'CVE-2019-0708', 'CVE-2018-12896'
]
PORT_RANGES = [(20, 22), (80, 80), (443, 443), (3306, 3306), (5432, 5432), (8080, 8080)]


def generate_file_hash():
    """生成随机文件哈希值"""
    return ''.join(random.choices('0123456789abcdef', k=64))


def generate_timestamp(start_year=2022, end_year=2024):
    """生成随机时间戳"""
    start = datetime(start_year, 1, 1)
    end = datetime(end_year, 12, 31)
    return int((start + timedelta(seconds=random.randint(0, int((end - start).total_seconds())))).timestamp() * 1000)


def generate_random_vector(size=64, min_val=0.0, max_val=1.0):
    """生成随机特征向量"""
    return [round(random.uniform(min_val, max_val), 6) for _ in range(size)]


def generate_unique_id(prefix):
    """生成唯一ID"""
    return f"{prefix}_{int(datetime.now().timestamp())}_{random.randint(1000, 9999)}"


def generate_file_sample(index, is_malicious):
    """生成文件分析样本"""
    file_ext = random.choice(FILE_TYPES)
    file_name = f"sample_{index}{file_ext}"
    file_size = random.randint(1024, 1048576)  # 1KB到1MB
    
    sample = {
        "file_id": generate_unique_id("file"),
        "file_name": file_name,
        "file_size": file_size,
        "file_hash": generate_file_hash(),
        "file_extension": file_ext,
        "created_time": generate_timestamp(),
        "modified_time": generate_timestamp(),
        "features": generate_random_vector(),
        "label": 1 if is_malicious else 0,
        "source": "malware_sample" if is_malicious else "benign_sample",
        "metadata": {
            "signatures": [],
            "severity": "low",
            "vt_detections": 0,
            "vt_total": 60
        }
    }
    
    # 如果是恶意样本，添加恶意软件特征
    if is_malicious:
        num_signatures = random.randint(1, 3)
        sample["metadata"]["signatures"] = random.sample(MALWARE_FAMILIES, num_signatures)
        sample["metadata"]["severity"] = random.choice(["medium", "high"])
        sample["metadata"]["vt_detections"] = random.randint(10, 60)
    
    return sample


def generate_scan_sample(index, has_threats):
    """生成网络扫描样本"""
    # 生成随机CIDR
    network = f"192.168.{random.randint(0, 255)}.0/24"
    
    # 生成随机开放端口
    open_ports = []
    for start, end in PORT_RANGES:
        if random.random() < 0.3:  # 30%概率开放这个端口范围
            open_ports.extend(list(range(start, end + 1)))
    
    sample = {
        "scan_id": generate_unique_id("scan"),
        "target": network,
        "scan_time": generate_timestamp(),
        "scan_duration": random.randint(60, 300),  # 1-5分钟
        "scan_type": random.choice(["comprehensive", "quick", "port_scan", "vulnerability"]),
        "features": generate_random_vector(),
        "label": 1 if has_threats else 0,
        "source": "internal_scan",
        "metadata": {
            "open_ports": open_ports,
            "vulnerabilities": [],
            "severity": "low",
            "asset_count": random.randint(5, 50)
        }
    }
    
    # 如果存在威胁，添加漏洞信息
    if has_threats:
        num_vulns = random.randint(1, 3)
        sample["metadata"]["vulnerabilities"] = random.sample(VULNERABILITIES, num_vulns)
        sample["metadata"]["severity"] = random.choice(["medium", "high"])
    
    return sample


def create_directory_structure(base_dir, dataset_type):
    """创建数据集目录结构"""
    dataset_dir = os.path.join(base_dir, dataset_type)
    files_dir = os.path.join(dataset_dir, "files")
    scans_dir = os.path.join(dataset_dir, "scans")
    
    os.makedirs(files_dir, exist_ok=True)
    os.makedirs(scans_dir, exist_ok=True)
    
    return dataset_dir, files_dir, scans_dir


def generate_metadata(num_files_malicious, num_files_benign, num_scans_threats, num_scans_safe, dataset_type):
    """生成数据集元数据"""
    return {
        "dataset_type": dataset_type,
        "generated_at": datetime.now().isoformat(),
        "total_files": num_files_malicious + num_files_benign,
        "malicious_files": num_files_malicious,
        "benign_files": num_files_benign,
        "total_scans": num_scans_threats + num_scans_safe,
        "threat_scans": num_scans_threats,
        "safe_scans": num_scans_safe,
        "description": f"{dataset_type.capitalize()} dataset for security ML model"
    }


def generate_dataset(base_dir, dataset_type, num_samples):
    """生成数据集"""
    dataset_dir, files_dir, scans_dir = create_directory_structure(base_dir, dataset_type)
    
    # 计算恶意和良性样本的数量（50%的比例）
    half = num_samples // 2
    num_files_malicious = half // 2
    num_files_benign = half - num_files_malicious
    num_scans_threats = (num_samples - half) // 2
    num_scans_safe = (num_samples - half) - num_scans_threats
    
    # 生成文件分析样本
    for i in range(num_files_malicious):
        sample = generate_file_sample(i, True)
        with open(os.path.join(files_dir, f"malicious_{i}.json"), 'w', encoding='utf-8') as f:
            json.dump(sample, f, ensure_ascii=False, indent=2)
    
    for i in range(num_files_benign):
        sample = generate_file_sample(i, False)
        with open(os.path.join(files_dir, f"benign_{i}.json"), 'w', encoding='utf-8') as f:
            json.dump(sample, f, ensure_ascii=False, indent=2)
    
    # 生成网络扫描样本
    for i in range(num_scans_threats):
        sample = generate_scan_sample(i, True)
        with open(os.path.join(scans_dir, f"threat_{i}.json"), 'w', encoding='utf-8') as f:
            json.dump(sample, f, ensure_ascii=False, indent=2)
    
    for i in range(num_scans_safe):
        sample = generate_scan_sample(i, False)
        with open(os.path.join(scans_dir, f"safe_{i}.json"), 'w', encoding='utf-8') as f:
            json.dump(sample, f, ensure_ascii=False, indent=2)
    
    # 生成元数据
    metadata = generate_metadata(
        num_files_malicious, num_files_benign,
        num_scans_threats, num_scans_safe,
        dataset_type
    )
    
    with open(os.path.join(dataset_dir, "metadata.json"), 'w', encoding='utf-8') as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)
    
    return metadata


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='生成安全模型训练数据')
    parser.add_argument('--num-training', type=int, default=100, help='训练集样本数量')
    parser.add_argument('--num-validation', type=int, default=30, help='验证集样本数量')
    parser.add_argument('--num-testing', type=int, default=20, help='测试集样本数量')
    
    args = parser.parse_args()
    
    print("开始生成数据集...")
    
    # 生成训练集
    print(f"生成训练集 ({args.num_training} 样本)...")
    training_meta = generate_dataset(BASE_DIR, "training", args.num_training)
    
    # 生成验证集
    print(f"生成验证集 ({args.num_validation} 样本)...")
    validation_meta = generate_dataset(BASE_DIR, "validation", args.num_validation)
    
    # 生成测试集
    print(f"生成测试集 ({args.num_testing} 样本)...")
    testing_meta = generate_dataset(BASE_DIR, "testing", args.num_testing)
    
    print("\n数据集生成完成！")
    print(f"训练集: {training_meta['total_files']}个文件样本, {training_meta['total_scans']}个扫描样本")
    print(f"验证集: {validation_meta['total_files']}个文件样本, {validation_meta['total_scans']}个扫描样本")
    print(f"测试集: {testing_meta['total_files']}个文件样本, {testing_meta['total_scans']}个扫描样本")


if __name__ == "__main__":
    main()