import json
import os
import requests
import numpy as np
import logging
from typing import Dict, List, Any, Optional, Tuple

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cooperative_supervision.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("CooperativeSupervision")

class DeepSeekClient:
    """
    DeepSeek API 客户端，用于与DeepSeek进行交互
    """
    def __init__(self, config_path: str):
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
        self.api_base_url = self.config['deepseek']['api_base_url']
        self.api_key = self.config['deepseek']['api_key']
        self.model_name = self.config['deepseek']['model_name']
        
    def _build_request_headers(self) -> Dict[str, str]:
        """构建API请求头"""
        return {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        }
    
    def analyze_security_data(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        向DeepSeek发送安全数据进行分析
        
        Args:
            security_data: 安全数据字典，包含扫描结果、文件信息等
            
        Returns:
            DeepSeek的分析结果
        """
        try:
            # 构建提示词
            prompt = self._build_security_analysis_prompt(security_data)
            
            # 构建请求体
            payload = {
                "model": self.model_name,
                "messages": [
                    {"role": "system", "content": "你是一位专业的网络安全分析师，擅长分析各类安全威胁数据。"},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.1,
                "max_tokens": 1000
            }
            
            # 发送请求
            response = requests.post(
                self.api_base_url,
                headers=self._build_request_headers(),
                json=payload
            )
            
            if response.status_code == 200:
                result = response.json()
                # 解析DeepSeek的回答
                return self._parse_deepseek_response(result)
            else:
                logger.error(f"DeepSeek API请求失败: {response.status_code}, {response.text}")
                return {"error": f"API请求失败: {response.status_code}", "risk": "unknown"}
                
        except Exception as e:
            logger.error(f"调用DeepSeek API时发生异常: {str(e)}")
            return {"error": str(e), "risk": "unknown"}
    
    def _build_security_analysis_prompt(self, security_data: Dict[str, Any]) -> str:
        """
        构建安全分析提示词
        """
        # 根据不同类型的数据构建不同的提示词
        if 'scan_result' in security_data:
            return self._build_scan_analysis_prompt(security_data)
        elif 'file_info' in security_data:
            return self._build_file_analysis_prompt(security_data)
        else:
            return f"请分析以下安全数据并提供威胁评估:\n{json.dumps(security_data, ensure_ascii=False, indent=2)}"
    
    def _build_scan_analysis_prompt(self, scan_data: Dict[str, Any]) -> str:
        """
        构建扫描结果分析提示词
        """
        return f"""请分析以下网络扫描结果，识别潜在的安全威胁，并提供风险评估：

扫描结果: {json.dumps(scan_data['scan_result'], ensure_ascii=False)}

请以JSON格式返回以下信息：
1. risk_level: 风险等级，取值为'高'、'中'或'低'
2. detected_threats: 检测到的威胁列表
3. vulnerability_details: 漏洞详情
4. recommended_actions: 推荐的安全措施
5. confidence: 评估置信度 (0-1)
"""
    
    def _build_file_analysis_prompt(self, file_data: Dict[str, Any]) -> str:
        """
        构建文件分析提示词
        """
        return f"""请分析以下文件信息，判断是否为恶意软件，并提供详细的分析：

文件信息: {json.dumps(file_data['file_info'], ensure_ascii=False)}

请以JSON格式返回以下信息：
1. is_malicious: 是否为恶意软件 (true/false)
2. threat_type: 威胁类型
3. confidence: 检测置信度 (0-1)
4. behavior_analysis: 行为分析
5. ioc: 威胁指标
6. recommended_actions: 推荐的处理措施
"""
    
    def _parse_deepseek_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        解析DeepSeek的API响应
        """
        try:
            # 提取内容
            content = response.get('choices', [{}])[0].get('message', {}).get('content', '')
            
            # 尝试解析JSON格式的响应
            if content.startswith('{') and content.endswith('}'):
                return json.loads(content)
            else:
                # 如果不是标准JSON，提取关键信息
                result = {
                    'raw_content': content,
                    'risk': self._extract_risk_level(content)
                }
                return result
        except Exception as e:
            logger.error(f"解析DeepSeek响应时出错: {str(e)}")
            return {"error": str(e), "raw_content": response, "risk": "unknown"}
    
    def _extract_risk_level(self, content: str) -> str:
        """
        从文本中提取风险等级
        """
        if any(keyword in content for keyword in ['高风险', '严重', '高危', 'critical', 'high']):
            return '高'
        elif any(keyword in content for keyword in ['中风险', '中等', '中危', 'medium']):
            return '中'
        elif any(keyword in content for keyword in ['低风险', '轻微', '低危', 'low']):
            return '低'
        else:
            return 'unknown'

class CooperativeSupervisionSystem:
    """
    协同监督系统，结合本地模型和DeepSeek进行安全检测
    """
    def __init__(self, config_path: str, local_model_path: Optional[str] = None):
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
        # 初始化DeepSeek客户端
        self.deepseek_client = DeepSeekClient(config_path)
        
        # 协同参数
        self.confidence_threshold = self.config['cooperative_supervision']['confidence_threshold']
        self.fallback_to_deepseek = self.config['cooperative_supervision']['fallback_to_deepseek']
        self.feedback_collection = self.config['cooperative_supervision']['feedback_collection']
        
        # 本地模型
        self.local_model = None
        if local_model_path:
            self._load_local_model(local_model_path)
        
        # 反馈数据存储
        self.feedback_data = []
        self.feedback_file = self.config['cooperative_supervision']['feedback_file']
    
    def _load_local_model(self, model_path: str) -> None:
        """
        加载本地模型
        """
        try:
            # 延迟导入以避免循环依赖
            from model import SecurityMLP
            self.local_model = SecurityMLP.load(model_path)
            logger.info(f"成功加载本地模型: {model_path}")
        except Exception as e:
            logger.error(f"加载本地模型失败: {str(e)}")
    
    def detect(self, data: Dict[str, Any], features: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """
        协同检测流程
        
        Args:
            data: 原始安全数据
            features: 提取的特征向量（可选）
            
        Returns:
            综合检测结果
        """
        result = {
            'timestamp': self._get_current_timestamp(),
            'detection_mode': '',
            'local_result': None,
            'deepseek_result': None,
            'final_decision': None,
            'confidence': 0.0
        }
        
        # 1. 本地模型检测（如果有特征向量和本地模型）
        use_deepseek = False
        
        if features is not None and self.local_model is not None:
            try:
                # 本地模型预测
                local_probs = self.local_model.predict(features, return_prob=True)
                local_confidence = np.max(local_probs, axis=1)[0]
                local_pred = np.argmax(local_probs, axis=1)[0]
                
                result['local_result'] = {
                    'prediction': int(local_pred),
                    'confidence': float(local_confidence),
                    'probabilities': local_probs.tolist()
                }
                
                # 根据置信度决定是否使用DeepSeek
                if local_confidence < self.confidence_threshold:
                    use_deepseek = True
                    result['detection_mode'] = 'hybrid'
                else:
                    result['final_decision'] = {
                        'is_malicious': bool(local_pred),
                        'confidence': float(local_confidence)
                    }
                    result['detection_mode'] = 'local_only'
                    result['confidence'] = float(local_confidence)
            except Exception as e:
                logger.error(f"本地模型检测失败: {str(e)}")
                use_deepseek = True
        else:
            # 没有特征向量或本地模型，直接使用DeepSeek
            use_deepseek = True
        
        # 2. DeepSeek检测
        if use_deepseek or self.fallback_to_deepseek:
            try:
                deepseek_result = self.deepseek_client.analyze_security_data(data)
                result['deepseek_result'] = deepseek_result
                result['detection_mode'] = 'deepseek_only' if result['detection_mode'] == '' else 'hybrid'
                
                # 综合决策
                final_decision = self._combine_decisions(result)
                result['final_decision'] = final_decision
                result['confidence'] = final_decision.get('confidence', 0.0)
                
            except Exception as e:
                logger.error(f"DeepSeek检测失败: {str(e)}")
                
                # 如果只有本地结果，使用本地结果作为最终决策
                if result['local_result']:
                    result['final_decision'] = {
                        'is_malicious': bool(result['local_result']['prediction']),
                        'confidence': result['local_result']['confidence']
                    }
                else:
                    result['final_decision'] = {
                        'is_malicious': False,
                        'confidence': 0.0,
                        'error': '所有检测方法均失败'
                    }
        
        # 3. 收集反馈（如果启用）
        if self.feedback_collection:
            self._collect_feedback(result)
        
        return result
    
    def _combine_decisions(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        结合本地模型和DeepSeek的决策结果
        """
        # 提取两种模型的结果
        local_result = result.get('local_result')
        deepseek_result = result.get('deepseek_result')
        
        # 初始化最终决策
        final_decision = {
            'is_malicious': False,
            'confidence': 0.0
        }
        
        # 简单融合策略
        if deepseek_result:
            # 从DeepSeek结果中提取恶意性信息
            if 'is_malicious' in deepseek_result:
                is_malicious = deepseek_result['is_malicious']
            elif 'risk' in deepseek_result:
                # 根据风险等级判断
                is_malicious = deepseek_result['risk'] in ['高', '中']
            else:
                is_malicious = False
            
            # 置信度
            confidence = deepseek_result.get('confidence', 0.7)  # 默认置信度
            
            if local_result:
                # 混合模式：加权融合
                # 本地模型置信度较低时，增加DeepSeek的权重
                local_weight = min(local_result['confidence'], self.confidence_threshold)
                deepseek_weight = 1.0 - local_weight
                
                weighted_prediction = (local_result['prediction'] * local_weight + 
                                     is_malicious * deepseek_weight)
                
                final_decision['is_malicious'] = weighted_prediction >= 0.5
                final_decision['confidence'] = local_result['confidence'] + (confidence - local_result['confidence']) * 0.5
                
                # 添加决策依据
                final_decision['decision_basis'] = {
                    'local_contribution': float(local_weight),
                    'deepseek_contribution': float(deepseek_weight),
                    'local_prediction': local_result['prediction'],
                    'deepseek_prediction': bool(is_malicious)
                }
            else:
                # 仅DeepSeek
                final_decision['is_malicious'] = is_malicious
                final_decision['confidence'] = float(confidence)
        elif local_result:
            # 仅本地模型
            final_decision['is_malicious'] = bool(local_result['prediction'])
            final_decision['confidence'] = local_result['confidence']
        
        return final_decision
    
    def _collect_feedback(self, detection_result: Dict[str, Any]) -> None:
        """
        收集检测反馈数据用于模型更新
        """
        # 添加到内存中的反馈列表
        self.feedback_data.append(detection_result)
        
        # 定期保存到文件
        if len(self.feedback_data) >= self.config['cooperative_supervision']['feedback_batch_size']:
            self._save_feedback_data()
    
    def _save_feedback_data(self) -> None:
        """
        保存反馈数据到文件
        """
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(self.feedback_file), exist_ok=True)
            
            # 加载现有数据
            existing_data = []
            if os.path.exists(self.feedback_file):
                with open(self.feedback_file, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
            
            # 合并并去重
            existing_data.extend(self.feedback_data)
            
            # 保存
            with open(self.feedback_file, 'w', encoding='utf-8') as f:
                json.dump(existing_data, f, indent=2, ensure_ascii=False)
            
            # 清空内存中的反馈数据
            self.feedback_data = []
            
            logger.info(f"已保存 {len(existing_data)} 条反馈数据")
            
        except Exception as e:
            logger.error(f"保存反馈数据失败: {str(e)}")
    
    def update_local_model(self, model_path: str) -> None:
        """
        更新本地模型
        """
        self._load_local_model(model_path)
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        获取协同系统性能指标
        """
        # 加载反馈数据
        feedback_data = []
        if os.path.exists(self.feedback_file):
            with open(self.feedback_file, 'r', encoding='utf-8') as f:
                feedback_data = json.load(f)
        
        # 计算指标
        metrics = {
            'total_detections': len(feedback_data),
            'detection_modes': {},
            'avg_confidence': 0.0,
            'hybrid_usage_rate': 0.0
        }
        
        if feedback_data:
            # 统计检测模式
            mode_counts = {}
            total_confidence = 0.0
            hybrid_count = 0
            
            for feedback in feedback_data:
                mode = feedback.get('detection_mode', 'unknown')
                mode_counts[mode] = mode_counts.get(mode, 0) + 1
                
                confidence = feedback.get('confidence', 0.0)
                total_confidence += confidence
                
                if mode == 'hybrid':
                    hybrid_count += 1
            
            metrics['detection_modes'] = mode_counts
            metrics['avg_confidence'] = total_confidence / len(feedback_data)
            metrics['hybrid_usage_rate'] = hybrid_count / len(feedback_data)
        
        return metrics
    
    @staticmethod
    def _get_current_timestamp() -> str:
        """
        获取当前时间戳
        """
        import datetime
        return datetime.datetime.now().isoformat()

if __name__ == "__main__":
    # 示例用法
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
    
    # 创建协同监督系统
    system = CooperativeSupervisionSystem(config_path)
    
    # 示例安全数据
    sample_data = {
        'scan_result': {
            'ip': '192.168.1.1',
            'ports': [22, 80, 443],
            'open_ports': [22, 80],
            'vulnerabilities': [
                {'type': 'SSH弱密码', 'severity': 'high'},
                {'type': 'HTTP未加密传输', 'severity': 'medium'}
            ]
        }
    }
    
    # 执行检测
    result = system.detect(sample_data)
    print(json.dumps(result, indent=2, ensure_ascii=False))