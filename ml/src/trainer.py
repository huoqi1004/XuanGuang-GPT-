import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
import os
import json
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
import seaborn as sns

from model import SecurityMLP
from data_processor import DataProcessor

class ModelTrainer:
    def __init__(self, config_path):
        # 加载配置
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
        # 初始化数据处理器
        self.data_processor = DataProcessor(self.config['data_paths'])
        
        # 设置训练参数
        self.batch_size = self.config['training']['batch_size']
        self.epochs = self.config['training']['epochs']
        self.learning_rate = self.config['training']['learning_rate']
        self.early_stopping_patience = self.config['training']['early_stopping_patience']
        self.validation_split = self.config['training']['validation_split']
        
        # 设置模型参数
        self.model_params = self.config['model_params']
        
        # 创建模型
        self.model = SecurityMLP(
            input_dim=self.model_params['input_dim'],
            hidden_dims=self.model_params['hidden_dims'],
            output_dim=self.model_params['output_dim'],
            dropout_rate=self.model_params['dropout_rate']
        )
        
        # 设置损失函数和优化器
        self.criterion = nn.CrossEntropyLoss()
        self.optimizer = optim.Adam(
            self.model.parameters(),
            lr=self.learning_rate,
            weight_decay=self.config['training']['weight_decay']
        )
        
        # 设置学习率调度器
        if self.config['training']['use_lr_scheduler']:
            self.scheduler = optim.lr_scheduler.ReduceLROnPlateau(
                self.optimizer,
                mode='min',
                factor=0.1,
                patience=5,
                verbose=True
            )
        else:
            self.scheduler = None
        
        # 存储训练历史
        self.history = {
            'train_loss': [],
            'val_loss': [],
            'train_acc': [],
            'val_acc': []
        }
        
    def prepare_data(self, data_path=None):
        """
        准备训练数据
        """
        if data_path:
            # 处理自定义数据路径
            X, y = self.data_processor.process_data(data_path)
        else:
            # 使用配置中的路径
            X, y = self.data_processor.load_and_preprocess()
        
        # 分割训练集和验证集
        split_idx = int(len(X) * (1 - self.validation_split))
        X_train, X_val = X[:split_idx], X[split_idx:]
        y_train, y_val = y[:split_idx], y[split_idx:]
        
        # 创建数据集和数据加载器
        train_dataset = TensorDataset(
            torch.tensor(X_train, dtype=torch.float32),
            torch.tensor(y_train, dtype=torch.long)
        )
        val_dataset = TensorDataset(
            torch.tensor(X_val, dtype=torch.float32),
            torch.tensor(y_val, dtype=torch.long)
        )
        
        self.train_loader = DataLoader(
            train_dataset,
            batch_size=self.batch_size,
            shuffle=True
        )
        self.val_loader = DataLoader(
            val_dataset,
            batch_size=self.batch_size,
            shuffle=False
        )
        
        print(f"训练集大小: {len(train_dataset)}, 验证集大小: {len(val_dataset)}")
        return self.train_loader, self.val_loader
    
    def train_epoch(self):
        """
        训练一个epoch
        """
        self.model.train()
        running_loss = 0.0
        correct = 0
        total = 0
        
        for inputs, targets in self.train_loader:
            # 清零梯度
            self.optimizer.zero_grad()
            
            # 前向传播
            outputs = self.model(inputs)
            loss = self.criterion(outputs, targets)
            
            # 反向传播和优化
            loss.backward()
            self.optimizer.step()
            
            # 统计损失和准确率
            running_loss += loss.item() * inputs.size(0)
            _, predicted = outputs.max(1)
            total += targets.size(0)
            correct += predicted.eq(targets).sum().item()
        
        epoch_loss = running_loss / total
        epoch_acc = correct / total
        
        return epoch_loss, epoch_acc
    
    def validate(self):
        """
        验证模型性能
        """
        self.model.eval()
        running_loss = 0.0
        correct = 0
        total = 0
        
        with torch.no_grad():
            for inputs, targets in self.val_loader:
                outputs = self.model(inputs)
                loss = self.criterion(outputs, targets)
                
                running_loss += loss.item() * inputs.size(0)
                _, predicted = outputs.max(1)
                total += targets.size(0)
                correct += predicted.eq(targets).sum().item()
        
        val_loss = running_loss / total
        val_acc = correct / total
        
        return val_loss, val_acc
    
    def train(self):
        """
        完整的训练过程
        """
        print("开始训练模型...")
        
        # 准备数据
        self.prepare_data()
        
        # 早停机制
        best_val_loss = float('inf')
        patience = 0
        
        for epoch in range(self.epochs):
            # 训练
            train_loss, train_acc = self.train_epoch()
            
            # 验证
            val_loss, val_acc = self.validate()
            
            # 更新历史记录
            self.history['train_loss'].append(train_loss)
            self.history['val_loss'].append(val_loss)
            self.history['train_acc'].append(train_acc)
            self.history['val_acc'].append(val_acc)
            
            # 学习率调度
            if self.scheduler:
                self.scheduler.step(val_loss)
            
            # 打印进度
            print(f'Epoch {epoch+1}/{self.epochs}, '
                  f'Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f}, '
                  f'Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}')
            
            # 早停检查
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience = 0
                # 保存最佳模型
                os.makedirs(self.config['model_paths']['checkpoint_dir'], exist_ok=True)
                best_model_path = os.path.join(self.config['model_paths']['checkpoint_dir'], 'best_model.pt')
                self.model.save(best_model_path)
            else:
                patience += 1
                if patience >= self.early_stopping_patience:
                    print(f"早停触发，在 epoch {epoch+1} 停止训练")
                    break
        
        # 保存最终模型
        final_model_path = self.config['model_paths']['final_model_path']
        self.model.save(final_model_path)
        
        # 保存训练历史
        history_path = os.path.join(self.config['model_paths']['checkpoint_dir'], 'training_history.json')
        with open(history_path, 'w', encoding='utf-8') as f:
            json.dump(self.history, f, indent=2)
        
        print(f"训练完成，最终模型保存到: {final_model_path}")
        return self.model
    
    def evaluate(self, test_data_path=None):
        """
        评估模型性能
        """
        # 加载最佳模型
        best_model_path = os.path.join(self.config['model_paths']['checkpoint_dir'], 'best_model.pt')
        if os.path.exists(best_model_path):
            self.model = SecurityMLP.load(best_model_path)
        
        # 准备测试数据
        if test_data_path:
            X_test, y_test = self.data_processor.process_data(test_data_path)
        else:
            # 使用全部验证集作为测试集
            X_test = next(iter(self.val_loader))[0].numpy()
            y_test = next(iter(self.val_loader))[1].numpy()
        
        # 进行预测
        self.model.eval()
        with torch.no_grad():
            test_input = torch.tensor(X_test, dtype=torch.float32)
            outputs = self.model(test_input)
            _, predictions = outputs.max(1)
            
            # 获取概率
            probs = nn.functional.softmax(outputs, dim=1).numpy()
        
        predictions = predictions.numpy()
        
        # 计算性能指标
        print("\n分类报告:")
        print(classification_report(y_test, predictions))
        
        # 计算混淆矩阵
        cm = confusion_matrix(y_test, predictions)
        print("\n混淆矩阵:")
        print(cm)
        
        # 计算AUC
        auc = roc_auc_score(y_test, probs[:, 1])
        print(f"\nAUC 分数: {auc:.4f}")
        
        # 保存评估结果
        results = {
            'classification_report': classification_report(y_test, predictions, output_dict=True),
            'confusion_matrix': cm.tolist(),
            'auc_score': float(auc)
        }
        
        results_path = os.path.join(self.config['model_paths']['checkpoint_dir'], 'evaluation_results.json')
        with open(results_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        
        # 可视化结果
        self._visualize_results(y_test, predictions, probs)
        
        return results
    
    def _visualize_results(self, y_true, y_pred, y_prob):
        """
        可视化评估结果
        """
        # 创建可视化目录
        viz_dir = os.path.join(self.config['model_paths']['checkpoint_dir'], 'visualizations')
        os.makedirs(viz_dir, exist_ok=True)
        
        # 1. 绘制混淆矩阵
        plt.figure(figsize=(10, 8))
        sns.heatmap(confusion_matrix(y_true, y_pred), annot=True, fmt='d', cmap='Blues')
        plt.title('混淆矩阵')
        plt.xlabel('预测标签')
        plt.ylabel('真实标签')
        plt.savefig(os.path.join(viz_dir, 'confusion_matrix.png'))
        plt.close()
        
        # 2. 绘制ROC曲线
        plt.figure(figsize=(10, 8))
        fpr, tpr, _ = roc_curve(y_true, y_prob[:, 1])
        auc_score = roc_auc_score(y_true, y_prob[:, 1])
        plt.plot(fpr, tpr, label=f'ROC 曲线 (AUC = {auc_score:.3f})')
        plt.plot([0, 1], [0, 1], 'k--', label='随机分类器')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('假正例率')
        plt.ylabel('真正例率')
        plt.title('ROC 曲线')
        plt.legend(loc="lower right")
        plt.savefig(os.path.join(viz_dir, 'roc_curve.png'))
        plt.close()
        
        # 3. 绘制训练历史
        plt.figure(figsize=(12, 5))
        
        plt.subplot(1, 2, 1)
        plt.plot(self.history['train_loss'], label='训练损失')
        plt.plot(self.history['val_loss'], label='验证损失')
        plt.title('损失曲线')
        plt.xlabel('Epoch')
        plt.ylabel('损失')
        plt.legend()
        
        plt.subplot(1, 2, 2)
        plt.plot(self.history['train_acc'], label='训练准确率')
        plt.plot(self.history['val_acc'], label='验证准确率')
        plt.title('准确率曲线')
        plt.xlabel('Epoch')
        plt.ylabel('准确率')
        plt.legend()
        
        plt.tight_layout()
        plt.savefig(os.path.join(viz_dir, 'training_history.png'))
        plt.close()

if __name__ == "__main__":
    # 示例用法
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
    trainer = ModelTrainer(config_path)
    
    # 训练模型
    trainer.train()
    
    # 评估模型
    trainer.evaluate()