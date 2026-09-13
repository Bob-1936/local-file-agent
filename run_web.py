# run_web.py
# -*- coding: utf-8 -*-

import os
import sys
import time
import socket
import webbrowser
import threading
import uvicorn

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """检测指定端口是否被占用"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def find_available_port(start_port: int = 8000, max_attempts: int = 50) -> int:
    """自动探测可用端口"""
    for port in range(start_port, start_port + max_attempts):
        if not is_port_in_use(port):
            return port
    raise RuntimeError(f"在端口区间 [{start_port}, {start_port + max_attempts}) 内未找到可用端口。")


def open_browser_delayed(url: str, delay: float = 1.2):
    """延迟拉起浏览器"""
    def _target():
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except Exception:
            pass
    threading.Thread(target=_target, daemon=True).start()


def main():
    if not os.path.exists(WEB_DIR):
        os.makedirs(WEB_DIR, exist_ok=True)

    index_html = os.path.join(WEB_DIR, "index.html")
    if not os.path.exists(index_html):
        print(f"[-] 警告: 未检测到前端静态入口文件: {index_html}", flush=True)

    host = "127.0.0.1"
    port = find_available_port(start_port=9000)
    url = f"http://{host}:{port}"

    print("=" * 60)
    print(" Local File Agent (2026 Web Edition) 服务启动中")
    print(f" 本地访问入口: {url}")
    print("=" * 60, flush=True)

    open_browser_delayed(url)

    # 启动 uvicorn 服务
    uvicorn.run(
        "server:app",
        host=host,
        port=port,
        reload=False,
        log_level="info"
    )


if __name__ == "__main__":
    main()