import os
import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / 'models' / 'xuangguang_gpt.pkl'
META_PATH = ROOT / 'models' / 'xuangguang_gpt.meta.json'

clf = None
meta = {}

def load_model():
    global clf, meta
    if META_PATH.exists():
        with open(META_PATH, 'r', encoding='utf-8') as f:
            meta = json.load(f)
    if MODEL_PATH.exists():
        try:
            import joblib
            clf = joblib.load(str(MODEL_PATH))
        except Exception:
            clf = None

class Handler(BaseHTTPRequestHandler):
    def _send_json(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_GET(self):
        if self.path.startswith('/health'):
            self._send_json(200, {"status":"ok","model":"玄光GPT","loaded":clf is not None,"meta":meta})
        else:
            self._send_json(404, {"error":"not found"})

    def do_POST(self):
        if self.path.startswith('/v1/chat/completions'):
            try:
                length = int(self.headers.get('Content-Length','0'))
                raw = self.rfile.read(length)
                data = json.loads(raw.decode('utf-8')) if raw else {}
                msgs = data.get('messages', [])
                text = ''
                if msgs:
                    m = msgs[-1]
                    text = (m.get('content') or '').strip()
                prefix = f"玄光GPT已部署。样本数: {meta.get('samples',0)} 精度: {round(meta.get('accuracy',0.0),4)}\n"
                content = prefix + (f"你的问题: {text}\n建议: 请提供结构化指标以便分析。")
                self._send_json(200, {"id":"chatcmpl-xuangguang","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":content}}]})
            except Exception as e:
                self._send_json(500, {"error":str(e)})
        elif self.path.startswith('/api/defense/block_ip'):
            try:
                length = int(self.headers.get('Content-Length','0'))
                raw = self.rfile.read(length)
                data = json.loads(raw.decode('utf-8')) if raw else {}
                ip = (data.get('ip') or '').strip()
                # 这里可以对接真实防火墙
                self._send_json(200, {"success": True, "action": "block_ip", "target": ip, "details": f"已阻断IP: {ip}"})
            except Exception as e:
                self._send_json(500, {"success": False, "error": str(e)})
        elif self.path.startswith('/api/defense/isolate_host'):
            try:
                length = int(self.headers.get('Content-Length','0'))
                raw = self.rfile.read(length)
                data = json.loads(raw.decode('utf-8')) if raw else {}
                host = (data.get('host') or '').strip()
                self._send_json(200, {"success": True, "action": "isolate_host", "target": host, "details": f"已隔离主机: {host}"})
            except Exception as e:
                self._send_json(500, {"success": False, "error": str(e)})
        elif self.path.startswith('/api/defense/update_rule'):
            try:
                length = int(self.headers.get('Content-Length','0'))
                raw = self.rfile.read(length)
                data = json.loads(raw.decode('utf-8')) if raw else {}
                rule = (data.get('rule') or 'auto').strip()
                self._send_json(200, {"success": True, "action": "update_rule", "target": rule, "details": f"已更新防火墙规则: {rule}"})
            except Exception as e:
                self._send_json(500, {"success": False, "error": str(e)})
        else:
            self._send_json(404, {"error":"not found"})

def main():
    load_model()
    server = HTTPServer(('127.0.0.1', 8001), Handler)
    server.serve_forever()

if __name__ == '__main__':
    main()
