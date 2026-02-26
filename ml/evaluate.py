#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模型评估脚本
评估安全检测模型在测试集上的性能
"""

import os
import sys
import json
import torch
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc, classification_report
)
import seaborn as sns
from datetime import datetime

# 添加src目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from data_processor import DataProcessor
from model import SecurityMLP

def setup_logging():
    """设置日志和输出目录"""
    log_dir = os.path.join(os.path.dirname(__file__), 'logs')
    results_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(results_dir, exist_ok=True)
    return log_dir, results_dir

def load_config():
    """加载配置文件"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    with open(config_path, 'r') as f:
        config = json.load(f)
    return config

def load_model(config, model_path=None):
    """加载训练好的模型"""
    # 如果没有指定模型路径，尝试加载最佳模型
    if model_path is None:
        model_path = os.path.join(config['training_config']['model_save_path'], 'security_model_best.pt')
    
    # 检查模型文件是否存在
    if not os.path.exists(model_path):
        # 尝试查找最新的模型文件
        model_dir = config['training_config']['model_save_path']
        model_files = [f for f in os.listdir(model_dir) if f.startswith('security_model_') and f.endswith('.pt')]
        if not model_files:
            raise FileNotFoundError("找不到模型文件")
        # 按时间排序，取最新的
        model_files.sort(reverse=True)
        model_path = os.path.join(model_dir, model_files[0])
    
    print(f"正在加载模型: {model_path}")
    
    # 初始化模型
    model = SecurityMLP(
        input_dim=config['model_params']['input_dim'],
        hidden_dims=config['model_params']['hidden_dims'],
        output_dim=config['model_params']['output_dim'],
        dropout_rate=config['model_params']['dropout_rate']
    )
    
    # 加载模型权重
    model.load_state_dict(torch.load(model_path, map_location=torch.device('cpu')))
    
    # 设置为评估模式
    model.eval()
    
    return model, model_path

def prepare_test_data(config):
    """准备测试数据"""
    data_processor = DataProcessor(config)
    test_loader = data_processor.prepare_test_dataloader()
    print(f"测试集批次数量: {len(test_loader)}")
    return test_loader

def evaluate_model(model, test_loader, results_dir):
    """评估模型性能"""
    print("\n开始评估模型性能...")
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    
    all_preds = []
    all_labels = []
    all_probs = []
    
    with torch.no_grad():
        for features, labels in test_loader:
            features, labels = features.to(device), labels.to(device)
            
            # 获取模型预测
            outputs = model(features)
            probs = torch.sigmoid(outputs).cpu().numpy()
            preds = (probs > 0.5).astype(int)
            
            all_preds.extend(preds.flatten())
            all_labels.extend(labels.cpu().numpy().flatten())
            all_probs.extend(probs.flatten())
    
    # 计算性能指标
    accuracy = accuracy_score(all_labels, all_preds)
    precision = precision_score(all_labels, all_preds)
    recall = recall_score(all_labels, all_preds)
    f1 = f1_score(all_labels, all_preds)
    
    print(f"\n===== 模型性能指标 =====")
    print(f"准确率 (Accuracy): {accuracy:.4f}")
    print(f"精确率 (Precision): {precision:.4f}")
    print(f"召回率 (Recall): {recall:.4f}")
    print(f"F1分数: {f1:.4f}")
    
    # 保存详细分类报告
    report = classification_report(all_labels, all_preds, output_dict=True)
    report_path = os.path.join(results_dir, f'classification_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"详细分类报告已保存到: {report_path}")
    
    # 绘制混淆矩阵
    plot_confusion_matrix(all_labels, all_preds, results_dir)
    
    # 绘制ROC曲线
    plot_roc_curve(all_labels, all_probs, results_dir)
    
    # 保存评估结果
    metrics = {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    metrics_path = os.path.join(results_dir, f'evaluation_metrics_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    
    return metrics

def plot_confusion_matrix(y_true, y_pred, results_dir):
    """绘制混淆矩阵"""
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(8, 6))
    
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['良性', '恶意'],
                yticklabels=['良性', '恶意'])
    
    plt.xlabel('预测类别')
    plt.ylabel('真实类别')
    plt.title('混淆矩阵')
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    plt.savefig(os.path.join(results_dir, f'confusion_matrix_{timestamp}.png'))
    plt.close()
    
    print(f"混淆矩阵已保存")

def plot_roc_curve(y_true, y_score, results_dir):
    """绘制ROC曲线"""
    fpr, tpr, _ = roc_curve(y_true, y_score)
    roc_auc = auc(fpr, tpr)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2,
             label=f'ROC曲线 (AUC = {roc_auc:.4f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('假阳性率 (FPR)')
    plt.ylabel('真阳性率 (TPR)')
    plt.title('接收器操作特征 (ROC) 曲线')
    plt.legend(loc="lower right")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    plt.savefig(os.path.join(results_dir, f'roc_curve_{timestamp}.png'))
    plt.close()
    
    print(f"ROC曲线已保存 (AUC: {roc_auc:.4f})")

def generate_enterprise_evaluation_report(metrics, model_path, results_dir):
    """生成企业级评估报告"""
    report = {
        "report_title": "安全检测模型企业级评估报告",
        "report_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "model_info": {
            "model_path": model_path,
            "evaluation_time": metrics["timestamp"]
        },
        "performance_metrics": metrics,
        "business_impact": {
            "accuracy_impact": "高准确率意味着更少的误报，降低了安全团队的工作量",
            "precision_impact": f"{metrics['precision']:.4f} 的精确率表明模型能够准确识别恶意样本，减少误判",
            "recall_impact": f"{metrics['recall']:.4f} 的召回率表明模型能够捕获大部分恶意威胁",
            "f1_impact": f"{metrics['f1_score']:.4f} 的F1分数综合衡量了模型的整体性能"
        },
        "enterprise_readiness": {
            "status": "企业级就绪" if metrics['f1_score'] >= 0.9 else "需要进一步优化",
            "recommendations": []
        }
    }
    
    # 根据性能添加建议
    if metrics['recall'] < 0.9:
        report['enterprise_readiness']['recommendations'].append(
            "提高召回率：增加恶意样本的训练数据，考虑使用数据增强技术"
        )
    if metrics['precision'] < 0.9:
        report['enterprise_readiness']['recommendations'].append(
            "提高精确率：优化模型参数，调整决策阈值，增加特征工程"
        )
    if metrics['f1_score'] >= 0.95:
        report['enterprise_readiness']['recommendations'].append(
            "模型性能优秀，建议部署到生产环境并持续监控"
        )
    
    # 保存报告
    report_path = os.path.join(results_dir, f'enterprise_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\n企业级评估报告已生成: {report_path}")
    return report

def main():
    print("===== 安全检测模型评估流程 =====")
    
    # 设置日志和结果目录
    log_dir, results_dir = setup_logging()
    
    # 加载配置
    config = load_config()
    
    # 加载模型
    try:
        model, model_path = load_model(config)
    except Exception as e:
        print(f"加载模型失败: {e}")
        print("请先运行 train.py 训练模型")
        return
    
    # 准备测试数据
    test_loader = prepare_test_data(config)
    
    # 评估模型
    metrics = evaluate_model(model, test_loader, results_dir)
    
    # 生成企业级报告
    report = generate_enterprise_evaluation_report(metrics, model_path, results_dir)
    
    print("\n===== 评估完成 =====")
    print(f"企业就绪状态: {report['enterprise_readiness']['status']}")
    
    if report['enterprise_readiness']['recommendations']:
        print("\n建议:")
        for rec in report['enterprise_readiness']['recommendations']:
            print(f"- {rec}")

if __name__ == "__main__":
    main()