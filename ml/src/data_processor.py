import os
import json
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import torch
from torch.utils.data import DataLoader, TensorDataset

class DataProcessor:
    def __init__(self, config):
        self.config = config
        
        self.scaler = StandardScaler()
        # 直接定义标签映射，不再从配置加载
        self.label_map = {
            '安全': 0,
            '不安全': 1
        }
    
    def save_label_map(self):
        """保存标签映射（已更新，不再依赖配置文件路径）"""
        pass
    
    def extract_features(self, scan_data):
        """
        从扫描数据中提取特征向量
        scan_data: 扫描结果数据（字典格式）
        返回: 64维特征向量
        """
        # 根据数据类型选择不同的特征提取方法
        if 'scan_result' in scan_data:
            return self.extract_features_from_scan(scan_data['scan_result'])
        elif 'file_info' in scan_data:
            return self.extract_features_from_file(scan_data['file_info'])
        else:
            # 原始的基础特征提取逻辑
            return self._extract_basic_features(scan_data)
    
    def _extract_basic_features(self, scan_data):
        """
        原始的基础特征提取逻辑
        """
        # 基础特征提取
        features = []
        
        # 提取IP相关特征
        if 'assets' in scan_data:
            assets = scan_data['assets']
            # 资产数量
            features.append(len(assets))
            
            # 端口相关特征
            all_ports = []
            for asset in assets:
                all_ports.extend(asset.get('openPorts', []))
            
            # 开放端口数量统计
            features.append(len(all_ports))
            
            # 常用危险端口检测
            dangerous_ports = [21, 22, 23, 25, 110, 135, 139, 445, 3306, 3389]
            dangerous_count = sum(1 for port in all_ports if port in dangerous_ports)
            features.append(dangerous_count)
            
            # 端口分布统计
            port_ranges = [(0, 1024), (1025, 65535)]
            for start, end in port_ranges:
                count = sum(1 for port in all_ports if start <= port <= end)
                features.append(count)
        
        # 填充到64维
        while len(features) < 64:
            features.append(0)
        
        return np.array(features[:64], dtype=np.float32)
    
    def extract_features_from_scan(self, scan_data):
        """
        从扫描结果数据中提取特征向量
        """
        import hashlib
        features = np.zeros(64, dtype=np.float32)
        
        # 1. IP地址特征
        if 'ip' in scan_data:
            ip_hash = hashlib.sha256(scan_data['ip'].encode()).hexdigest()
            for i in range(min(32, len(ip_hash))):
                features[i] = int(ip_hash[i], 16) / 15.0
        
        # 2. 端口扫描特征
        # 开放端口特征
        if 'open_ports' in scan_data:
            ports = scan_data['open_ports']
            if ports:
                # 计算端口的统计特征
                port_hash = hashlib.md5(str(sorted(ports)).encode()).hexdigest()
                for i in range(min(32, len(port_hash))):
                    features[32 + i] = int(port_hash[i], 16) / 15.0
        elif 'ports' in scan_data:
            # 如果只有端口列表
            ports = scan_data['ports']
            port_hash = hashlib.md5(str(sorted(ports)).encode()).hexdigest()
            for i in range(min(32, len(port_hash))):
                features[32 + i] = int(port_hash[i], 16) / 15.0
        
        # 3. 漏洞特征
        if 'vulnerabilities' in scan_data:
            vulns = scan_data['vulnerabilities']
            if vulns:
                # 使用漏洞数量和类型作为特征
                vuln_count = min(len(vulns), 10)  # 限制最大值
                features[63] = vuln_count / 10.0  # 归一化到[0,1]
                
                # 漏洞类型特征
                vuln_types = []
                for vuln in vulns:
                    if isinstance(vuln, dict) and 'type' in vuln:
                        vuln_types.append(vuln['type'])
                    elif isinstance(vuln, str):
                        vuln_types.append(vuln)
                
                if vuln_types:
                    vuln_hash = hashlib.md5(str(sorted(vuln_types)).encode()).hexdigest()
                    # 使用漏洞哈希覆盖部分特征
                    for i in range(min(16, len(vuln_hash))):
                        features[48 + i] = int(vuln_hash[i], 16) / 15.0
        
        # 4. 服务特征
        if 'services' in scan_data:
            services = scan_data['services']
            if services:
                service_hash = hashlib.md5(str(sorted(services)).encode()).hexdigest()
                for i in range(min(8, len(service_hash))):
                    features[56 + i] = int(service_hash[i], 16) / 15.0
        
        return features
    
    def extract_features_from_file(self, file_info):
        """
        从文件信息数据中提取特征向量
        """
        import hashlib
        features = np.zeros(64, dtype=np.float32)
        
        # 1. 文件路径特征
        if 'path' in file_info:
            path_hash = hashlib.sha256(file_info['path'].encode()).hexdigest()
            for i in range(min(32, len(path_hash))):
                features[i] = int(path_hash[i], 16) / 15.0  # 归一化到[0,1]
        elif 'name' in file_info:
            # 如果只有文件名
            name_hash = hashlib.sha256(file_info['name'].encode()).hexdigest()
            for i in range(min(32, len(name_hash))):
                features[i] = int(name_hash[i], 16) / 15.0
        
        # 2. 文件大小特征
        if 'size' in file_info:
            size = float(file_info['size'])
            # 使用对数缩放并归一化
            size_log = np.log(size + 1) / 30.0  # 假设最大文件大小在e^30左右
            features[32] = min(size_log, 1.0)
        
        # 3. 文件扩展名特征
        if 'extension' in file_info:
            ext_hash = hashlib.md5(file_info['extension'].encode()).hexdigest()
            for i in range(min(16, len(ext_hash))):
                features[33 + i] = int(ext_hash[i], 16) / 15.0
        elif 'name' in file_info:
            # 从文件名提取扩展名
            _, ext = os.path.splitext(file_info['name'])
            if ext:
                ext_hash = hashlib.md5(ext.encode()).hexdigest()
                for i in range(min(16, len(ext_hash))):
                    features[33 + i] = int(ext_hash[i], 16) / 15.0
        
        # 4. 文件时间特征
        # 修改时间特征
        if 'modified_time' in file_info:
            mod_time = float(file_info['modified_time'])
            time_hash = hashlib.md5(str(mod_time).encode()).hexdigest()
            for i in range(min(8, len(time_hash))):
                features[49 + i] = int(time_hash[i], 16) / 15.0
        
        # 创建时间特征
        if 'created_time' in file_info:
            create_time = float(file_info['created_time'])
            time_hash = hashlib.md5(str(create_time).encode()).hexdigest()
            for i in range(min(8, len(time_hash))):
                features[57 + i] = int(time_hash[i], 16) / 15.0
        
        # 5. 文件哈希特征
        if 'hash' in file_info:
            file_hash = file_info['hash']
            for i in range(min(8, len(file_hash))):
                # 使用十六进制值
                try:
                    features[56 + i] = int(file_hash[i], 16) / 15.0
                except ValueError:
                    # 如果不是有效的十六进制，使用ASCII值
                    features[56 + i] = ord(file_hash[i]) / 255.0
        
        # 6. 恶意软件签名特征（如果有）
        if 'signatures' in file_info:
            signatures = file_info['signatures']
            if signatures:
                sig_hash = hashlib.md5(str(signatures).encode()).hexdigest()
                for i in range(min(8, len(sig_hash))):
                    features[60 + i] = int(sig_hash[i], 16) / 15.0
        
        return features
    
    def load_data(self, data_dir):
        """
        加载数据目录中的所有数据文件
        """
        X = []
        y = []
        
        for filename in os.listdir(data_dir):
            if filename.endswith('.json'):
                file_path = os.path.join(data_dir, filename)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    # 提取特征和标签
                    features = self.extract_features(data.get('scan', {}))
                    label = self.label_map.get(data.get('label', 'safe'), 0)
                    
                    X.append(features)
                    y.append(label)
                except Exception as e:
                    print(f"Error processing file {filename}: {e}")
        
        if not X:
            return np.array([]), np.array([])
        
        return np.array(X), np.array(y)
    
    def preprocess(self, X):
        """
        预处理特征数据
        """
        if len(X) == 0:
            return X
        return self.scaler.transform(X)
    
    def fit_scaler(self, X_train):
        """
        拟合数据标准化器
        """
        if len(X_train) > 0:
            self.scaler.fit(X_train)
    
    def prepare_training_data(self):
        """
        准备训练、验证和测试数据
        """
        # 加载训练数据
        train_dir = self.config['data_paths']['training_data']
        if os.path.exists(train_dir):
            X_train, y_train = self.load_data(train_dir)
        else:
            # 如果训练目录不存在，尝试从原始数据创建
            return self._create_train_val_test_from_raw()
        
        # 加载验证数据
        val_dir = self.config['data_paths']['validation_data']
        if os.path.exists(val_dir):
            X_val, y_val = self.load_data(val_dir)
        else:
            # 从训练数据中分割验证集
            X_train, X_val, y_train, y_val = train_test_split(
                X_train, y_train, test_size=self.config['training']['validation_split'], random_state=42
            )
        
        # 加载测试数据
        test_dir = self.config['data_paths']['test_data']
        X_test, y_test = self.load_data(test_dir) if os.path.exists(test_dir) else (np.array([]), np.array([]))
        
        # 标准化数据
        self.fit_scaler(X_train)
        X_train = self.preprocess(X_train)
        X_val = self.preprocess(X_val)
        X_test = self.preprocess(X_test)
        
        return {
            'X_train': X_train,
            'y_train': y_train,
            'X_val': X_val,
            'y_val': y_val,
            'X_test': X_test,
            'y_test': y_test
        }
    
    def _create_train_val_test_from_raw(self):
        """
        从原始数据创建训练、验证和测试数据集
        """
        raw_dir = self.config['data_paths']['raw_data']
        if not os.path.exists(raw_dir):
            raise ValueError(f"原始数据目录不存在: {raw_dir}")
        
        # 加载所有原始数据
        X_all, y_all = self.load_data(raw_dir)
        
        if len(X_all) == 0:
            raise ValueError("原始数据目录中没有可用的数据文件")
        
        # 分割数据集
        X_train_val, X_test, y_train_val, y_test = train_test_split(
            X_all, y_all, test_size=0.2, random_state=42
        )
        
        X_train, X_val, y_train, y_val = train_test_split(
            X_train_val, y_train_val, test_size=0.25, random_state=42  # 0.25 * 0.8 = 0.2
        )
        
        # 标准化数据
        self.fit_scaler(X_train)
        X_train = self.preprocess(X_train)
        X_val = self.preprocess(X_val)
        X_test = self.preprocess(X_test)
        
        return {
            'X_train': X_train,
            'y_train': y_train,
            'X_val': X_val,
            'y_val': y_val,
            'X_test': X_test,
            'y_test': y_test
        }
    
    def save_processed_data(self, data_dict, output_dir):
        """
        保存处理后的数据
        """
        os.makedirs(output_dir, exist_ok=True)
        
        for key, value in data_dict.items():
            if len(value) > 0:
                file_path = os.path.join(output_dir, f"{key}.npy")
                np.save(file_path, value)
                print(f"已保存 {key} 到 {file_path}")
    
    def prepare_dataloaders(self):
        """
        准备训练和验证数据加载器
        """
        # 先准备训练数据
        data_dict = self.prepare_training_data()
        
        # 转换为PyTorch张量
        train_tensor_dataset = TensorDataset(
            torch.tensor(data_dict['X_train'], dtype=torch.float32),
            torch.tensor(data_dict['y_train'], dtype=torch.float32).unsqueeze(1)
        )
        
        val_tensor_dataset = TensorDataset(
            torch.tensor(data_dict['X_val'], dtype=torch.float32),
            torch.tensor(data_dict['y_val'], dtype=torch.float32).unsqueeze(1)
        )
        
        # 创建数据加载器
        batch_size = self.config.get('training', {}).get('batch_size', 32)
        train_loader = DataLoader(train_tensor_dataset, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_tensor_dataset, batch_size=batch_size, shuffle=False)
        
        return train_loader, val_loader
    
    def prepare_test_dataloader(self):
        """
        准备测试数据加载器
        """
        # 加载测试数据
        test_dir = self.config['data_paths']['test_data']
        if not os.path.exists(test_dir):
            return None
            
        X_test, y_test = self.load_data(test_dir)
        
        if len(X_test) == 0:
            return None
            
        # 预处理数据
        X_test = self.preprocess(X_test)
        
        # 转换为PyTorch张量
        test_tensor_dataset = TensorDataset(
            torch.tensor(X_test, dtype=torch.float32),
            torch.tensor(y_test, dtype=torch.float32).unsqueeze(1)
        )
        
        # 创建数据加载器
        batch_size = self.config.get('training', {}).get('batch_size', 32)
        test_loader = DataLoader(test_tensor_dataset, batch_size=batch_size, shuffle=False)
        
        return test_loader
    
    def preprocess_data(self, data, fit_scaler=True):
        """
        预处理数据的别名方法，保持向后兼容性
        """
        if fit_scaler:
            self.fit_scaler(data)
        return self.preprocess(data)

if __name__ == "__main__":
    processor = DataProcessor("../config.json")
    try:
        data = processor.prepare_training_data()
        processor.save_processed_data(data, "../data/processed")
        print("数据处理完成!")
    except Exception as e:
        print(f"数据处理失败: {e}")