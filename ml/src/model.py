import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import os
import json

class SecurityMLP(nn.Module):
    def __init__(self, input_dim=64, hidden_dims=None, output_dim=2, dropout_rate=0.3):
        super(SecurityMLP, self).__init__()
        
        if hidden_dims is None:
            hidden_dims = [32, 16]
        
        # 构建网络层
        layers = []
        prev_dim = input_dim
        
        for hidden_dim in hidden_dims:
            layers.append(nn.Linear(prev_dim, hidden_dim))
            layers.append(nn.BatchNorm1d(hidden_dim))
            layers.append(nn.ReLU())
            layers.append(nn.Dropout(dropout_rate))
            prev_dim = hidden_dim
        
        # 输出层
        layers.append(nn.Linear(prev_dim, output_dim))
        
        self.model = nn.Sequential(*layers)
        
    def forward(self, x):
        if isinstance(x, np.ndarray):
            x = torch.tensor(x, dtype=torch.float32)
        return self.model(x)
    
    def predict(self, x, return_prob=False):
        """
        进行预测
        return_prob: 是否返回概率值
        """
        self.eval()
        with torch.no_grad():
            outputs = self.forward(x)
            if return_prob:
                return F.softmax(outputs, dim=1).numpy()
            else:
                return torch.argmax(outputs, dim=1).numpy()
    
    def save(self, save_path):
        """
        保存模型
        """
        # 确保目录存在
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        # 保存模型状态和架构信息
        torch.save({
            'model_state_dict': self.state_dict(),
            'input_dim': self.model[0].in_features,
            'hidden_dims': [layer.out_features for i, layer in enumerate(self.model) if i % 4 == 0 and i < len(self.model) - 1],
            'output_dim': self.model[-1].out_features
        }, save_path)
        
        print(f"模型已保存到: {save_path}")
    
    @classmethod
    def load(cls, load_path):
        """
        加载模型
        """
        checkpoint = torch.load(load_path, map_location=torch.device('cpu'))
        
        model = cls(
            input_dim=checkpoint['input_dim'],
            hidden_dims=checkpoint['hidden_dims'],
            output_dim=checkpoint['output_dim']
        )
        
        model.load_state_dict(checkpoint['model_state_dict'])
        model.eval()
        
        print(f"模型已从 {load_path} 加载")
        return model

class CooperativeModel:
    """
    协同监督模型，结合本地模型和DeepSeek API
    """
    def __init__(self, local_model_path, config_path):
        # 加载配置
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
        # 加载本地模型
        self.local_model = SecurityMLP.load(local_model_path)
        
        # 协同监督配置
        self.confidence_threshold = self.config['cooperative_supervision']['confidence_threshold']
        self.deepseek_integration = self.config['cooperative_supervision']['deepseek_integration']
        
    def predict(self, features, deepseek_result=None):
        """
        协同预测
        features: 输入特征向量
        deepseek_result: DeepSeek API的预测结果（可选）
        """
        # 本地模型预测
        local_probs = self.local_model.predict(features, return_prob=True)
        local_confidence = np.max(local_probs, axis=1)
        local_pred = np.argmax(local_probs, axis=1)
        
        # 如果启用了DeepSeek集成且本地置信度低于阈值
        if self.deepseek_integration and deepseek_result and local_confidence < self.confidence_threshold:
            # 使用DeepSeek结果进行修正
            return self._combine_results(local_pred, deepseek_result)
        
        return local_pred
    
    def _combine_results(self, local_pred, deepseek_result):
        """
        结合本地模型和DeepSeek的预测结果
        """
        # 这里实现结果融合逻辑
        # 示例：简单规则融合
        if isinstance(deepseek_result, dict) and 'risk' in deepseek_result:
            risk_level = deepseek_result['risk']
            if risk_level in ['高', 'high']:
                # 如果DeepSeek认为高风险，倾向于预测为恶意
                return np.ones_like(local_pred)
            elif risk_level in ['低', 'low']:
                # 如果DeepSeek认为低风险，倾向于预测为安全
                return np.zeros_like(local_pred)
        
        # 默认返回本地预测
        return local_pred
    
    def feedback(self, features, true_label, deepseek_result=None):
        """
        反馈机制，用于收集数据以更新模型
        """
        # 预测
        pred = self.predict(features, deepseek_result)
        
        # 计算准确率
        correct = (pred == true_label).sum()
        total = len(pred)
        accuracy = correct / total if total > 0 else 0
        
        # 记录结果用于后续模型更新
        feedback_data = {
            'features': features.tolist(),
            'true_label': true_label.tolist(),
            'prediction': pred.tolist(),
            'accuracy': float(accuracy),
            'confidence': float(np.max(self.local_model.predict(features, return_prob=True), axis=1).mean()),
            'deepseek_used': float(accuracy < self.confidence_threshold)
        }
        
        if deepseek_result:
            feedback_data['deepseek_result'] = deepseek_result
        
        return feedback_data

if __name__ == "__main__":
    # 测试模型
    model = SecurityMLP()
    test_input = torch.randn(10, 64)
    output = model(test_input)
    print(f"模型输出形状: {output.shape}")
    
    # 测试预测功能
    test_np_input = np.random.randn(5, 64)
    predictions = model.predict(test_np_input)
    print(f"预测结果: {predictions}")
    
    probs = model.predict(test_np_input, return_prob=True)
    print(f"概率结果形状: {probs.shape}")