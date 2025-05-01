import sys
import json
import subprocess
import time
import urllib.request
from threading import Thread
from urllib.parse import urlparse, parse_qs
import socket
import os

from websocket import WebSocketApp
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtWebChannel import QWebChannel
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QUrl, pyqtSlot, QPoint


class PacketSignal(QObject):
    new_packet = pyqtSignal(dict)
    new_tcp_packet = pyqtSignal(dict)
    match_result = pyqtSignal(dict)
    update_tcp_port = pyqtSignal(object)
    toggle_sniffing = pyqtSignal(bool)


class JsBridge(QObject):
    def __init__(self, viewer):
        super().__init__()
        self.viewer = viewer

    @pyqtSlot(int)
    def setTcpPort(self, value):
        self.viewer.packet_signal.update_tcp_port.emit(value)

    @pyqtSlot(bool)
    def setSniffingEnabled(self, state):
        self.viewer.packet_signal.toggle_sniffing.emit(state)


class TrafficViewer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("📡 Network Traffic Viewer with Matching")
        self.resize(1200, 800)

        self.tcp_filter_port = None
        self.sniffing_enabled = True
        self.http_counter = 1
        self.tcp_counter = 1

        self.packet_signal = PacketSignal()
        self.packet_signal.new_packet.connect(self.add_web_packet)
        self.packet_signal.new_tcp_packet.connect(self.add_tcp_packet)
        self.packet_signal.match_result.connect(self.send_match_result)
        self.packet_signal.update_tcp_port.connect(self.update_tcp_filter_port)
        self.packet_signal.toggle_sniffing.connect(self.set_sniffing_enabled)

        layout = QVBoxLayout(self)
        self.web_view = QWebEngineView()
        file_path = os.path.abspath("index.html")
        self.web_view.setUrl(QUrl.fromLocalFile(file_path))
        layout.addWidget(self.web_view)

        self.web_logs = []
        self.tcp_logs = []

    def update_tcp_filter_port(self, port):
        self.tcp_filter_port = port if isinstance(port, int) else None

    def set_sniffing_enabled(self, enabled):
        self.sniffing_enabled = enabled

    def add_web_packet(self, entry):
        parsed_url = urlparse(entry.get("url", ""))
        query_params = parse_qs(parsed_url.query)
        payload = {
            "query": query_params,
            "body": entry.get("body", "")
        }
        response_raw = entry.get("response", "")
        try:
            response_json = json.loads(response_raw)
            response = json.dumps(response_json, indent=2, ensure_ascii=False)
        except:
            response = response_raw

        message = {
            "id": self.http_counter,
            "type": "web",
            "method": entry.get("method"),
            "url": entry.get("url"),
            "headers": entry.get("headers", {}),
            "payload": payload,
            "status": entry.get("status"),
            "response": response,
            "timestamp": time.time()
        }
        self.http_counter += 1
        self.web_logs.append(message)
        self.web_view.page().runJavaScript(f'window.addPacket({json.dumps(message)});')
        self.match_packets()

    def add_tcp_packet(self, packet):
        packet["id"] = self.tcp_counter
        self.tcp_counter += 1
        self.tcp_logs.append(packet)
        self.web_view.page().runJavaScript(f'window.addTcpPacket({json.dumps(packet)});')
        self.match_packets()

    def match_packets(self):
        for w in self.web_logs[-10:]:
            w_key = w.get("url", "").split("?")[0]
            w_time = w.get("timestamp", time.time())
            for t in self.tcp_logs[-10:]:
                if abs(w_time - t["timestamp"]) < 3 and w_key in t["payload"]:
                    self.packet_signal.match_result.emit({
                        "url": w["url"],
                        "payload": t["payload"],
                        "timestamp": t["timestamp"]
                    })
                    break

    def send_match_result(self, result):
        self.web_view.page().runJavaScript(f'window.addMatchResult({json.dumps(result)});')

def start_chrome_and_cdp(viewer: TrafficViewer):
    subprocess.Popen([
        "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
        "--remote-debugging-port=9222",
        "--user-data-dir=C:/temp/chrome_profile",
        "--remote-allow-origins=*",
        "http://localhost:3099"
    ])
    time.sleep(2)

    with urllib.request.urlopen("http://localhost:9222/json") as response:
        data = json.loads(response.read().decode())
        ws_url = data[0]["webSocketDebuggerUrl"]

    request_map = {}
    response_requests = {}

    def on_message(ws, message):
        msg = json.loads(message)
        method = msg.get("method")

        if method == "Network.requestWillBeSent":
            if msg["params"].get("type") not in ("Fetch", "XHR"):
                return
            req_id = msg["params"]["requestId"]
            req = msg["params"]["request"]
            request_map[req_id] = {
                "method": req.get("method"),
                "url": req.get("url"),
                "headers": req.get("headers", {}),
                "body": req.get("postData", ""),
                "timestamp": time.time(),
                "logged": False
            }

        elif method == "Network.responseReceived":
            req_id = msg["params"]["requestId"]
            if req_id in request_map:
                request_map[req_id]["status"] = msg["params"]["response"]["status"]

        elif method == "Network.loadingFinished":
            req_id = msg["params"]["requestId"]
            if req_id in request_map:
                unique_id = hash(req_id) % 1000000
                response_requests[unique_id] = req_id
                ws.send(json.dumps({
                    "id": unique_id,
                    "method": "Network.getResponseBody",
                    "params": {"requestId": req_id}
                }))

        elif "id" in msg and "result" in msg:
            mapped_req_id = response_requests.pop(msg["id"], None)
            if mapped_req_id and mapped_req_id in request_map:
                entry = request_map[mapped_req_id]
                entry["response"] = msg["result"].get("body", "")
                entry["logged"] = True
                viewer.packet_signal.new_packet.emit(entry.copy())

    def on_open(ws):
        ws.send(json.dumps({"id": 1, "method": "Network.enable"}))

    def on_error(ws, error):
        print("[CDP 에러]", error)

    ws = WebSocketApp(ws_url, on_open=on_open, on_message=on_message, on_error=on_error)
    ws.run_forever()


def start_tcp_sniffer(viewer: TrafficViewer):
    def sniffer():
        last_emit_time = 0
        emit_interval = 0.01  # 10ms

        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP) as sniffer:
            sniffer.bind(("127.0.0.1", 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            while True:
                if not viewer.sniffing_enabled:
                    time.sleep(0.1)
                    continue

                raw_data, addr = sniffer.recvfrom(65535)
                ip_header = raw_data[0:20]
                tcp_header = raw_data[20:40]
                payload = raw_data[40:]
                protocol = ip_header[9]
                if protocol == 6:
                    src_port = int.from_bytes(tcp_header[0:2], "big")
                    dst_port = int.from_bytes(tcp_header[2:4], "big")
                    filter_port = viewer.tcp_filter_port
                    if filter_port is None or dst_port == filter_port:
                        if time.time() - last_emit_time >= emit_interval:
                            try:
                                viewer.packet_signal.new_tcp_packet.emit({
                                    "src": addr[0],
                                    "src_port": src_port,
                                    "dst_port": dst_port,
                                    "payload": payload[:200].decode(errors="ignore"),
                                    "hex": payload[:200].hex(),
                                    "timestamp": time.time()
                                })
                                last_emit_time = time.time()
                            except:
                                pass

    Thread(target=sniffer, daemon=True).start()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    viewer = TrafficViewer()
    viewer.show()

    channel = QWebChannel()
    bridge = JsBridge(viewer)
    channel.registerObject('qtBridge', bridge)
    viewer.web_view.page().setWebChannel(channel)

    Thread(target=start_chrome_and_cdp, args=(viewer,), daemon=True).start()
    Thread(target=start_tcp_sniffer, args=(viewer,), daemon=True).start()

    sys.exit(app.exec_())