import os
import sys
import json
import time
import hashlib
import socket
import argparse
import requests

try:
    import mindspore as ms
    from mindspore import nn, Tensor
    ms.set_context(mode=ms.PYNATIVE_MODE)
except Exception:
    ms = None
    nn = None
    Tensor = None

class Net(nn.Cell if nn else object):
    def __init__(self):
        if nn:
            super().__init__()
            self.fc1 = nn.Dense(64, 32)
            self.fc2 = nn.Dense(32, 2)
        else:
            pass
    def construct(self, x):
        if nn:
            x = self.fc1(x)
            x = self.fc2(x)
            return x
        return x

def sha256_bytes(b):
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def register(server, secret, info):
    try:
        r = requests.post(f"{server}/api/edge/register", headers={"x-edge-secret": secret}, json=info, timeout=10)
        return r.ok
    except Exception:
        return False

def send_telemetry(server, secret, doc):
    try:
        r = requests.post(f"{server}/api/edge/telemetry", headers={"x-edge-secret": secret}, json=doc, timeout=10)
        return r.ok
    except Exception:
        return False

def poll_tasks(server, secret, id):
    try:
        r = requests.get(f"{server}/api/edge/tasks", headers={"x-edge-secret": secret}, params={"id": id}, timeout=10)
        if not r.ok:
            return []
        return r.json().get("tasks", [])
    except Exception:
        return []

def post_result(server, secret, doc):
    try:
        r = requests.post(f"{server}/api/edge/taskresult", headers={"x-edge-secret": secret}, json=doc, timeout=10)
        return r.ok
    except Exception:
        return False

def run_inference(features):
    if ms and nn and Tensor:
        net = Net()
        x = Tensor(features, ms.float32)
        y = net(x)
        return str(y.asnumpy().tolist())
    return json.dumps({"ok": True, "features": features})

def analyze_file(path):
    try:
        with open(path, "rb") as f:
            buf = f.read()
        h = sha256_bytes(buf)
        return {"path": path, "sha256": h, "size": len(buf)}
    except Exception as e:
        return {"path": path, "error": str(e)}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--name", default="edge")
    p.add_argument("--board", default="OrangePi")
    p.add_argument("--arch", default=os.uname().machine if hasattr(os, "uname") else "")
    p.add_argument("--scan_dir", default="/tmp")
    args = p.parse_args()

    secret = os.environ.get("EDGE_SECRET", "")
    info = {"id": args.id, "name": args.name, "board": args.board, "arch": args.arch}
    register(args.server, secret, info)

    while True:
        ip = get_local_ip()
        files = []
        try:
            for root, _, names in os.walk(args.scan_dir):
                for n in names[:50]:
                    files.append(analyze_file(os.path.join(root, n)))
                break
        except Exception:
            pass
        telemetry = {"ip": ip, "files": files[:10], "ts": int(time.time())}
        send_telemetry(args.server, secret, {"id": args.id, "telemetry": telemetry})

        tasks = poll_tasks(args.server, secret, args.id)
        for t in tasks:
            if t.get("type") == "inference":
                res = run_inference(t.get("features", [0]*64))
                post_result(args.server, secret, {"id": args.id, "result": {"task": t, "res": res, "ts": int(time.time())}})
            elif t.get("type") == "hash":
                path = t.get("path", "")
                post_result(args.server, secret, {"id": args.id, "result": analyze_file(path)})
        time.sleep(5)

if __name__ == "__main__":
    main()
