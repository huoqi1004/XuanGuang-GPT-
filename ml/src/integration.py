import os
import sys
import json
import logging
import numpy as np
import subprocess
from typing import Dict, List, Any, Optional

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("MLIntegration")

# 将项目根目录添加到Python路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

class MLIntegration:
    """
    机器学习模型与现有安全检测系统的集成接口
    """
    def __init__(self, config_path: str):
        # 加载配置
        self.config_path = config_path
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
        # 模型和协同系统路径
        self.ml_root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.server_root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        # 延迟导入以避免循环依赖
        self._load_components()
        
    def _load_components(self):
        """
        动态加载必要的组件
        """
        try:
            # 导入本地模型和协同监督系统
            from model import SecurityMLP, CooperativeModel
            from cooperative_supervision import CooperativeSupervisionSystem
            
            self.SecurityMLP = SecurityMLP
            self.CooperativeModel = CooperativeModel
            self.CooperativeSupervisionSystem = CooperativeSupervisionSystem
            
            # 加载默认模型
            self.local_model = None
            self.cooperative_system = None
            
            if os.path.exists(self.config['model_paths']['final_model_path']):
                self.local_model = self.SecurityMLP.load(self.config['model_paths']['final_model_path'])
                logger.info(f"成功加载默认本地模型")
            
            # 初始化协同监督系统
            self.cooperative_system = self.CooperativeSupervisionSystem(
                self.config_path,
                self.config['model_paths']['final_model_path'] if os.path.exists(self.config['model_paths']['final_model_path']) else None
            )
            
        except Exception as e:
            logger.error(f"加载ML组件失败: {str(e)}")
    
    def extract_features_from_scan(self, scan_data: Dict[str, Any]) -> np.ndarray:
        """
        从扫描数据中提取特征向量
        
        Args:
            scan_data: 扫描结果数据
            
        Returns:
            64维特征向量
        """
        try:
            # 延迟导入数据处理器
            from data_processor import DataProcessor
            processor = DataProcessor(self.config['data_paths'])
            
            # 提取特征
            features = processor.extract_features_from_scan(scan_data)
            return features
        except Exception as e:
            logger.error(f"从扫描数据提取特征失败: {str(e)}")
            # 返回默认特征向量
            return np.zeros((1, 64))
    
    def extract_features_from_file(self, file_info: Dict[str, Any]) -> np.ndarray:
        """
        从文件信息中提取特征向量
        
        Args:
            file_info: 文件信息数据
            
        Returns:
            64维特征向量
        """
        try:
            # 延迟导入数据处理器
            from data_processor import DataProcessor
            processor = DataProcessor(self.config['data_paths'])
            
            # 提取特征
            features = processor.extract_features_from_file(file_info)
            return features
        except Exception as e:
            logger.error(f"从文件信息提取特征失败: {str(e)}")
            # 返回默认特征向量
            return np.zeros((1, 64))
    
    def detect_with_ml(self, data: Dict[str, Any], data_type: str = 'scan') -> Dict[str, Any]:
        """
        使用机器学习模型进行安全检测
        
        Args:
            data: 安全数据
            data_type: 数据类型 ('scan' 或 'file')
            
        Returns:
            检测结果
        """
        try:
            # 提取特征
            if data_type == 'scan':
                features = self.extract_features_from_scan(data)
                security_data = {'scan_result': data}
            elif data_type == 'file':
                features = self.extract_features_from_file(data)
                security_data = {'file_info': data}
            else:
                raise ValueError(f"不支持的数据类型: {data_type}")
            
            # 使用协同监督系统进行检测
            result = self.cooperative_system.detect(security_data, features)
            
            # 添加元数据
            result['data_type'] = data_type
            
            return result
        except Exception as e:
            logger.error(f"ML检测失败: {str(e)}")
            return {
                'error': str(e),
                'success': False,
                'data_type': data_type
            }
    
    def integrate_with_av_system(self, file_path: str) -> Dict[str, Any]:
        """
        与现有杀毒系统集成
        
        Args:
            file_path: 文件路径
            
        Returns:
            增强的检测结果
        """
        try:
            # 1. 生成文件信息
            file_info = self._generate_file_info(file_path)
            
            # 2. 获取现有AV系统的结果
            av_result = self._call_existing_av_system(file_path)
            
            # 3. 使用ML模型进行检测
            ml_result = self.detect_with_ml(file_info, data_type='file')
            
            # 4. 合并结果
            enhanced_result = {
                'file_path': file_path,
                'file_info': file_info,
                'av_result': av_result,
                'ml_result': ml_result,
                'integrated_decision': self._combine_decisions(av_result, ml_result),
                'timestamp': ml_result.get('timestamp', '')
            }
            
            return enhanced_result
        except Exception as e:
            logger.error(f"与AV系统集成失败: {str(e)}")
            return {
                'error': str(e),
                'success': False,
                'file_path': file_path
            }
    
    def integrate_with_scanner(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        与现有扫描器系统集成
        
        Args:
            scan_data: 扫描结果数据
            
        Returns:
            增强的扫描结果
        """
        try:
            # 1. 使用ML模型进行检测
            ml_result = self.detect_with_ml(scan_data, data_type='scan')
            
            # 2. 合并结果
            enhanced_result = {
                'scan_data': scan_data,
                'ml_result': ml_result,
                'integrated_vulnerability_assessment': self._enhance_vulnerability_assessment(scan_data, ml_result),
                'timestamp': ml_result.get('timestamp', '')
            }
            
            return enhanced_result
        except Exception as e:
            logger.error(f"与扫描器集成失败: {str(e)}")
            return {
                'error': str(e),
                'success': False
            }
    
    def _generate_file_info(self, file_path: str) -> Dict[str, Any]:
        """
        生成文件信息
        """
        try:
            # 获取文件基本信息
            stat_info = os.stat(file_path)
            
            # 计算文件哈希（如果文件存在）
            file_hash = self._calculate_file_hash(file_path)
            
            file_info = {
                'path': file_path,
                'size': stat_info.st_size,
                'modified_time': stat_info.st_mtime,
                'created_time': stat_info.st_ctime,
                'hash': file_hash,
                'name': os.path.basename(file_path),
                'extension': os.path.splitext(file_path)[1].lower()
            }
            
            return file_info
        except Exception as e:
            logger.error(f"生成文件信息失败: {str(e)}")
            return {
                'path': file_path,
                'error': str(e)
            }
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """
        计算文件SHA256哈希
        """
        import hashlib
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                # 分块读取文件
                for byte_block in iter(lambda: f.read(4096), b""
):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"计算文件哈希失败: {str(e)}")
            return ""
    
    def _call_existing_av_system(self, file_path: str) -> Dict[str, Any]:
        """
        调用现有的杀毒系统
        这里是一个模拟实现，实际使用时需要根据现有的AV系统进行调整
        """
        try:
            # 假设现有的AV系统在server/src/av.js中
            # 由于是Python调用JavaScript，这里使用Node.js执行脚本
            av_script_path = os.path.join(self.server_root_dir, 'server', 'src', 'av.js')
            
            # 创建一个临时的调用脚本
            temp_script = os.path.join(self.ml_root_dir, 'utils', 'call_av.js')
            
            with open(temp_script, 'w', encoding='utf-8') as f:
                f.write(f'''
                const fs = require('fs');
                const path = require('path');
                
                // 模拟AV系统的结果
                const fileInfo = {{
                    path: "{file_path}",
                    scanTime: new Date().toISOString()
                }};
                
                // 输出JSON格式的结果
                console.log(JSON.stringify({{
                    success: true,
                    fileInfo: fileInfo,
                    scanResult: "simulated_result",
                    isMalicious: false
                }}));
                ''')
            
            # 执行脚本
            result = subprocess.run(
                ['node', temp_script],
                capture_output=True,
                text=True
            )
            
            # 解析结果
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                logger.error(f"调用AV系统失败: {result.stderr}")
                return {
                    'success': False,
                    'error': result.stderr
                }
                
        except Exception as e:
            logger.error(f"调用AV系统时发生异常: {str(e)}")
            # 返回模拟结果
            return {
                'success': True,
                'fileInfo': self._generate_file_info(file_path),
                'scanResult': 'simulated_result',
                'isMalicious': False
            }
    
    def _combine_decisions(self, av_result: Dict[str, Any], ml_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        合并AV系统和ML模型的决策结果
        """
        # 获取各自的决策
        av_malicious = av_result.get('isMalicious', False)
        ml_decision = ml_result.get('final_decision', {})
        ml_malicious = ml_decision.get('is_malicious', False)
        ml_confidence = ml_decision.get('confidence', 0.0)
        
        # 集成决策逻辑
        # 1. 如果任何一方认为是恶意的，则最终决策倾向于恶意
        # 2. 根据置信度调整决策权重
        integrated_malicious = av_malicious or (ml_malicious and ml_confidence > 0.5)
        
        # 计算综合置信度
        confidence_factors = []
        if av_result.get('success', False):
            confidence_factors.append(0.5)  # AV系统默认权重
        if ml_confidence > 0:
            confidence_factors.append(ml_confidence)
        
        integrated_confidence = sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.0
        
        return {
            'is_malicious': integrated_malicious,
            'confidence': float(integrated_confidence),
            'decision_factors': {
                'av_malicious': av_malicious,
                'ml_malicious': ml_malicious,
                'ml_confidence': float(ml_confidence)
            }
        }
    
    def _enhance_vulnerability_assessment(self, scan_data: Dict[str, Any], ml_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        增强漏洞评估
        """
        # 获取原始漏洞列表
        original_vulnerabilities = scan_data.get('vulnerabilities', [])
        
        # 获取ML模型的决策
        ml_decision = ml_result.get('final_decision', {})
        ml_malicious = ml_decision.get('is_malicious', False)
        
        # 增强每个漏洞的评估
        enhanced_vulnerabilities = []
        for vuln in original_vulnerabilities:
            # 添加ML模型的风险评估
            enhanced_vuln = vuln.copy()
            
            # 根据ML模型的结果调整漏洞风险等级
            if ml_malicious:
                # 如果ML模型认为有风险，可能需要提高风险等级
                if vuln.get('severity') == 'medium':
                    enhanced_vuln['adjusted_severity'] = 'high'
                    enhanced_vuln['severity_adjustment_reason'] = 'ML模型风险评估增强'
            
            enhanced_vulnerabilities.append(enhanced_vuln)
        
        return enhanced_vulnerabilities
    
    def create_nodejs_integration_wrapper(self) -> str:
        """
        创建Node.js集成包装器
        
        Returns:
            生成的包装器文件路径
        """
        try:
            # 生成Node.js包装器代码
            wrapper_code = '''
            const { spawn } = require('child_process');
            const path = require('path');
            const fs = require('fs');
            
            /**
             * ML集成模块
             * 用于调用Python实现的机器学习安全检测功能
             */
            class MLIntegration {
                constructor() {
                    this.pythonScriptPath = path.join(__dirname, '../../ml/src/integration_wrapper.py');
                    this.configPath = path.join(__dirname, '../../ml/config.json');
                }
                
                /**
                 * 使用机器学习模型进行安全检测
                 * @param {Object} data - 安全数据
                 * @param {string} dataType - 数据类型 ('scan' 或 'file')
                 * @returns {Promise<Object>} 检测结果
                 */
                async detectWithML(data, dataType = 'scan') {
                    return this._callPythonService({
                        action: 'detect_with_ml',
                        data: data,
                        data_type: dataType
                    });
                }
                
                /**
                 * 与杀毒系统集成
                 * @param {string} filePath - 文件路径
                 * @returns {Promise<Object>} 增强的检测结果
                 */
                async integrateWithAVSystem(filePath) {
                    return this._callPythonService({
                        action: 'integrate_with_av_system',
                        file_path: filePath
                    });
                }
                
                /**
                 * 与扫描器集成
                 * @param {Object} scanData - 扫描结果数据
                 * @returns {Promise<Object>} 增强的扫描结果
                 */
                async integrateWithScanner(scanData) {
                    return this._callPythonService({
                        action: 'integrate_with_scanner',
                        scan_data: scanData
                    });
                }
                
                /**
                 * 调用Python服务
                 * @param {Object} request - 请求数据
                 * @returns {Promise<Object>} 响应结果
                 */
                _callPythonService(request) {
                    return new Promise((resolve, reject) => {
                        const pythonProcess = spawn('python', [
                            this.pythonScriptPath,
                            this.configPath
                        ]);
                        
                        let output = '';
                        let error = '';
                        
                        // 发送请求数据
                        pythonProcess.stdin.write(JSON.stringify(request));
                        pythonProcess.stdin.end();
                        
                        // 收集输出
                        pythonProcess.stdout.on('data', (data) => {
                            output += data.toString();
                        });
                        
                        pythonProcess.stderr.on('data', (data) => {
                            error += data.toString();
                        });
                        
                        // 处理完成
                        pythonProcess.on('close', (code) => {
                            if (code === 0) {
                                try {
                                    resolve(JSON.parse(output));
                                } catch (e) {
                                    reject(new Error(`解析Python输出失败: ${e.message}\n原始输出: ${output}`));
                                }
                            } else {
                                reject(new Error(`Python进程异常退出 (代码: ${code}): ${error}`));
                            }
                        });
                    });
                }
            }
            
            // 导出模块
            module.exports = MLIntegration;
            '''
            
            # 写入包装器文件
            wrapper_path = os.path.join(self.server_root_dir, 'server', 'src', 'ml_integration.js')
            with open(wrapper_path, 'w', encoding='utf-8') as f:
                f.write(wrapper_code)
            
            # 生成Python包装器脚本
            python_wrapper_code = '''
            import sys
            import json
            import os
            
            # 添加ML目录到路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            
            from ml.src.integration import MLIntegration
            
            def main():
                try:
                    # 读取配置路径和请求数据
                    config_path = sys.argv[1]
                    request_data = json.loads(sys.stdin.read())
                    
                    # 初始化集成模块
                    integration = MLIntegration(config_path)
                    
                    # 根据action执行相应操作
                    action = request_data.get('action')
                    
                    if action == 'detect_with_ml':
                        result = integration.detect_with_ml(
                            request_data.get('data'),
                            request_data.get('data_type', 'scan')
                        )
                    elif action == 'integrate_with_av_system':
                        result = integration.integrate_with_av_system(
                            request_data.get('file_path')
                        )
                    elif action == 'integrate_with_scanner':
                        result = integration.integrate_with_scanner(
                            request_data.get('scan_data')
                        )
                    else:
                        result = {"error": f"未知操作: {action}", "success": False}
                    
                    # 添加成功标志
                    if 'success' not in result:
                        result['success'] = True
                    
                    # 输出结果
                    print(json.dumps(result, ensure_ascii=False))
                    
                except Exception as e:
                    # 输出错误信息
                    print(json.dumps({
                        "error": str(e),
                        "success": False
                    }, ensure_ascii=False))
                    sys.exit(1)
            
            if __name__ == "__main__":
                main()
            '''
            
            # 写入Python包装器文件
            python_wrapper_path = os.path.join(self.ml_root_dir, 'src', 'integration_wrapper.py')
            with open(python_wrapper_path, 'w', encoding='utf-8') as f:
                f.write(python_wrapper_code)
            
            logger.info(f"已创建Node.js集成包装器: {wrapper_path}")
            logger.info(f"已创建Python集成包装器: {python_wrapper_path}")
            
            return wrapper_path
        
        except Exception as e:
            logger.error(f"创建集成包装器失败: {str(e)}")
            raise
    
    def update_data_processor_for_edge(self):
        """
        更新边缘设备的特征提取逻辑，使其与数据处理器保持一致
        """
        try:
            # 读取现有的edge/agent.py文件
            agent_path = os.path.join(self.server_root_dir, 'edge', 'agent.py')
            
            if os.path.exists(agent_path):
                with open(agent_path, 'r', encoding='utf-8') as f:
                    agent_code = f.read()
                
                # 在agent.py中添加特征提取函数
                feature_extraction_code = '''

# 特征提取函数，与中央ML系统保持一致
def extract_features(data):
    """
    从数据中提取特征向量
    该函数与中央ML系统的数据处理器保持一致
    """
    import hashlib
    import numpy as np
    
    # 初始化特征向量
    features = np.zeros(64)
    
    # 1. 如果是文件数据
    if isinstance(data, dict) and 'path' in data:
        # 使用路径哈希作为特征
        path_hash = hashlib.sha256(data['path'].encode()).hexdigest()
        for i in range(min(32, len(path_hash))):
            features[i] = int(path_hash[i], 16) / 15.0  # 归一化到[0,1]
        
        # 文件大小特征
        if 'size' in data:
            size = float(data['size'])
            # 使用对数缩放并归一化
            size_log = np.log(size + 1) / 30.0  # 假设最大文件大小在e^30左右
            features[32] = min(size_log, 1.0)
        
        # 文件扩展名特征
        if 'extension' in data:
            ext_hash = hashlib.md5(data['extension'].encode()).hexdigest()
            for i in range(min(16, len(ext_hash))):
                features[33 + i] = int(ext_hash[i], 16) / 15.0
        
        # 文件修改时间特征
        if 'modified_time' in data:
            mod_time = float(data['modified_time'])
            # 使用时间戳的哈希部分
            time_hash = hashlib.md5(str(mod_time).encode()).hexdigest()
            for i in range(min(16, len(time_hash))):
                features[49 + i] = int(time_hash[i], 16) / 15.0
    
    # 2. 如果是扫描数据
    elif isinstance(data, dict) and ('ip' in data or 'ports' in data):
        # IP地址特征
        if 'ip' in data:
            ip_hash = hashlib.sha256(data['ip'].encode()).hexdigest()
            for i in range(min(32, len(ip_hash))):
                features[i] = int(ip_hash[i], 16) / 15.0
        
        # 开放端口特征
        if 'open_ports' in data:
            ports = data['open_ports']
            # 计算端口的统计特征
            if ports:
                port_hash = hashlib.md5(str(sorted(ports)).encode()).hexdigest()
                for i in range(min(32, len(port_hash))):
                    features[32 + i] = int(port_hash[i], 16) / 15.0
        
        # 漏洞特征
        if 'vulnerabilities' in data:
            vulns = data['vulnerabilities']
            if vulns:
                # 使用漏洞数量和类型作为特征
                vuln_count = min(len(vulns), 10)  # 限制最大值
                features[63] = vuln_count / 10.0  # 归一化到[0,1]
    
    return features.tolist()
'''               
                
                # 检查是否已经包含extract_features函数
                if 'def extract_features(' not in agent_code:
                    # 在适当位置添加特征提取函数
                    # 查找Net类定义之后的位置
                    if 'class Net:' in agent_code:
                        lines = agent_code.split('\n')
                        net_class_index = -1
                        
                        for i, line in enumerate(lines):
                            if 'class Net:' in line:
                                net_class_index = i
                                break
                        
                        if net_class_index >= 0:
                            # 查找Net类的结束位置
                            indent_level = 0
                            net_end_index = net_class_index
                            
                            for i in range(net_class_index + 1, len(lines)):
                                stripped = lines[i].lstrip()
                                if stripped and stripped[0] == 'd' and stripped.startswith('def ') and lines[i].startswith('    '):
                                    indent_level = len(lines[i]) - len(stripped)
                                    break
                                elif stripped and stripped[0] != ' ':
                                    net_end_index = i
                                    break
                            
                            # 在Net类之后插入特征提取函数
                            new_lines = lines[:net_end_index] + [feature_extraction_code] + lines[net_end_index:]
                            updated_code = '\n'.join(new_lines)
                            
                            # 写回文件
                            with open(agent_path, 'w', encoding='utf-8') as f:
                                f.write(updated_code)
                            
                            logger.info(f"已更新边缘设备的特征提取逻辑: {agent_path}")
                        else:
                            logger.warning(f"在agent.py中未找到Net类定义")
                else:
                    logger.info(f"agent.py中已包含extract_features函数")
            else:
                logger.warning(f"未找到边缘设备代理文件: {agent_path}")
        
        except Exception as e:
            logger.error(f"更新边缘设备特征提取逻辑失败: {str(e)}")
    
    def setup_complete_integration(self):
        """
        设置完整的集成，包括创建包装器和更新边缘设备
        """
        try:
            # 创建Node.js集成包装器
            self.create_nodejs_integration_wrapper()
            
            # 更新边缘设备特征提取逻辑
            self.update_data_processor_for_edge()
            
            logger.info("ML集成设置完成")
            
            return {
                'success': True,
                'message': 'ML集成设置完成'
            }
        except Exception as e:
            logger.error(f"设置ML集成失败: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

# 使用示例
if __name__ == "__main__":
    # 假设配置文件在当前目录
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.json')
    
    # 初始化集成模块
    integration = MLIntegration(config_path)
    
    # 设置完整集成
    result = integration.setup_complete_integration()
    print(json.dumps(result, indent=2, ensure_ascii=False))