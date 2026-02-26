import os
import json
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)

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
        import joblib
        clf = joblib.load(str(MODEL_PATH))

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status":"ok","model":"玄光GPT","loaded":clf is not None,"meta":meta})

@app.route('/v1/chat/completions', methods=['POST'])
def chat():
    try:
        data = request.get_json(force=True)
        msgs = data.get('messages', [])
        text = ''
        if msgs:
            m = msgs[-1]
            text = (m.get('content') or '').strip()
        if clf is None:
            load_model()
        prefix = f"玄光GPT已部署。样本数: {meta.get('samples',0)} 精度: {round(meta.get('accuracy',0.0),4)}\n"
        content = prefix + (f"你的问题: {text}\n建议: 请提供结构化指标以便分析。")
        return jsonify({
            "id":"chatcmpl-xuangguang",
            "object":"chat.completion",
            "choices":[{"index":0,"message":{"role":"assistant","content":content}}]
        })
    except Exception as e:
        return jsonify({"error":str(e)}), 500

if __name__ == '__main__':
    load_model()
    app.run(host='127.0.0.1', port=8001)
