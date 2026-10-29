# -*- coding: utf-8 -*-
"""
Flydigi 手柄固件回退工具 (OTA 本地劫持)
用途: 将刷了 1.0.5.8 的手柄回退到用户提供的备份固件 (自动检测本机 LocalState 备份或手动选择)
原理: 劫持 testapi/api.flydigi.com 到本机, 让官方应用把指定固件当作"新版"刷入手柄
"""
import base64
import ctypes
import glob
import json
import os
import queue
import re
import ssl
import subprocess
import sys
import threading
import http.server

import tkinter as tk
import tkinter.messagebox as tkmb
import tkinter.filedialog as tkfd
from tkinter import scrolledtext, ttk

import sv_ttk

APP_TITLE = "Flydigi 手柄固件回退工具 (1.0.5.8 -> 备份固件)"
HOSTS_PATH = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
MARK = "# FLYDIGI-ROLLBACK-TOOL"
DOMAINS = ["testapi.flydigi.com", "api.flydigi.com"]
FW_VERSION_DEFAULT = "9.9.9.9"
CERT_CN = "Flydigi Fake OTA"
FW_PORT_HTTP = 80
FW_PORT_HTTPS = 443
SELFTEST_PORTS = (18080, 18443)

LOGQ = queue.Queue()


def log(msg, tag=None):
    LOGQ.put((msg, tag))


# ---------------- 固件加载 ----------------
def res(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def parse_fw_info(data):
    """从 AOTA 容器中解析固件版本名"""
    try:
        m = re.search(rb"<version_name>(.*?)</version_name>", data, re.S)
        return m.group(1).decode("ascii", "replace") if m else "未知版本"
    except Exception:
        return "未知版本"


def load_fw_file(path):
    """加载用户指定的固件文件, 校验 AOTA 头"""
    global FW_DATA, FW_PATH, FW_INFO
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 0x400 or data[:4] != b"AOTA":
        raise ValueError("不是有效的飞智 OTA 固件文件 (缺少 AOTA 头)")
    FW_DATA = data
    FW_PATH = path
    FW_INFO = parse_fw_info(data)
    return FW_INFO


def detect_local_fw():
    """自动查找本机 Flydigi 应用 LocalState 里留存的 OTA 固件备份"""
    pats = [
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Packages",
                     "Flydigi.FlydigiSpaceStationForXbox*", "LocalState", "*.bin"),
        os.path.join(res(""), "ota_v1.0.0.6.bin"),
    ]
    hits = []
    for p in pats:
        if "*" in p:
            hits += glob.glob(p)
        elif os.path.exists(p):
            hits.append(p)
    return max(hits, key=os.path.getmtime) if hits else None


CERT_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "FlydigiRollbackTool")
PEM_FILE = os.path.join(CERT_DIR, "flydigi_fake.pem")
KEY_FILE = os.path.join(CERT_DIR, "flydigi_fake.key")
CER_FILE = os.path.join(CERT_DIR, "flydigi_fake.cer")


def ensure_cert():
    """每台机器首次运行时本地生成自签证书(私钥不出本机), 已存在则复用"""
    os.makedirs(CERT_DIR, exist_ok=True)
    if os.path.exists(PEM_FILE) and os.path.exists(KEY_FILE) and os.path.exists(CER_FILE):
        with open(CER_FILE, "rb") as f:
            cer = f.read()
        with open(PEM_FILE, "rb") as f:
            pem = f.read()
        with open(KEY_FILE, "rb") as f:
            key = f.read()
        return cer, pem, key

    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Flydigi Fake OTA (local)")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365 * 3))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("testapi.flydigi.com"), x509.DNSName("api.flydigi.com")]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(PEM_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(CER_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))
    with open(CER_FILE, "rb") as f:
        cer = f.read()
    with open(PEM_FILE, "rb") as f:
        pem = f.read()
    with open(KEY_FILE, "rb") as f:
        key_b = f.read()
    return cer, pem, key_b


FW_DATA = b""
FW_PATH = ""
FW_INFO = ""
CER, PEM, KEY = b"", b"", b""


# ---------------- 权限 ----------------
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate():
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    if "--elevated" not in params:
        params = (params + " --elevated").strip()
    ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    return ret > 32


# ---------------- 系统配置 ----------------
def run(cmd, check=False):
    p = subprocess.run(cmd, capture_output=True, text=True, shell=False)
    if p.returncode != 0 and check:
        raise RuntimeError(f"命令失败: {' '.join(cmd)}\n{p.stdout}\n{p.stderr}")
    return p


def get_flydigi_pfns():
    p = run(["powershell", "-NoProfile", "-Command",
             "Get-AppxPackage -Name *Flydigi* | Select-Object -ExpandProperty PackageFamilyName"])
    return [l.strip() for l in (p.stdout or "").splitlines() if l.strip()]


def hosts_lines():
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    except Exception:
        return []


def hosts_add():
    lines = hosts_lines()
    if any(MARK in l for l in lines):
        log("[hosts] 条目已存在, 跳过")
        return
    with open(HOSTS_PATH, "a", encoding="ascii") as f:
        f.write("\r\n")
        for d in DOMAINS:
            f.write(f"{MARK}\r\n127.0.0.1 {d}\r\n")
    log("[hosts] 已添加: " + ", ".join(DOMAINS))


def hosts_remove():
    kept = [l for l in hosts_lines()
            if MARK not in l and not (l.strip().startswith("127.0.0.1") and "flydigi.com" in l)]
    with open(HOSTS_PATH, "w", encoding="ascii") as f:
        f.write("\r\n".join(kept) + "\r\n")
    log("[hosts] 条目已清除")


def cert_install():
    p = run(["certutil", "-addstore", "-f", "Root", CER_FILE])
    ok = p.returncode == 0
    log("[证书] " + ("已安装到 受信任的根证书颁发机构" if ok else f"安装失败: {p.stdout} {p.stderr}"))
    return ok


def cert_remove():
    p = run(["certutil", "-delstore", "Root", CERT_CN])
    log("[证书] " + ("已从受信任根中删除" if p.returncode == 0 else "未找到(或已删除)"))


def loopback_config(pfns, add=True):
    if not pfns:
        log("[回环] 未找到已安装的 Flydigi 应用(跳过)")
        return
    for pfn in pfns:
        flag = "-a" if add else "-d"
        p = run(["checknetisolation", "loopbackexempt", flag, f"-n={pfn}"])
        log(f"[回环] {'豁免' if add else '移除'} {pfn} " + ("ok" if p.returncode == 0 else "失败"))


def firewall_config(add=True):
    name = "FlydigiRollbackTool"
    run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
    if add:
        p = run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
                 "dir=in", "action=allow", "protocol=TCP", "localport=80,443"])
        log("[防火墙] 放行 80/443 " + ("ok" if p.returncode == 0 else "失败"))
    else:
        log("[防火墙] 规则已移除")


def flush_dns():
    run(["ipconfig", "/flushdns"])


# ---------------- 本地 OTA 服务器 ----------------
class OtaHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    fw_version = FW_VERSION_DEFAULT

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def handle_one(self):
        path = self.path.split("?")[0].lower()
        host = self.headers.get("Host", "testapi.flydigi.com")
        log(f"  <- {self.command} {self.path} (Host: {host}, appversion: {self.headers.get('appversion')})")
        if "firmware" in path:
            url = f"https://{host}/fw_backup.bin"
            resp = {"code": 0, "message": "OK",
                    "data": {"device_code": "F5X",
                             "chip_list": {"main_chip": {
                                 "version": self.fw_version, "url": url,
                                 "info": "rollback to backup firmware",
                                 "min_app_version": "0", "is_push": 0}}}}
            log(f"  -> 返回固件版本 {self.fw_version} (诱导升级到备份固件)")
            self._send(200, json.dumps(resp).encode(), "application/json")
        elif path.endswith(".bin"):
            log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", "warn")
            log("  固件已下发! 手柄正在升级 — 刷写中切勿断开手柄/休眠电脑!", "warn")
            log(f"  (已发送 {len(FW_DATA)} 字节)", "warn")
            log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", "warn")
            self._send(200, FW_DATA, "application/octet-stream")
        else:
            self._send(404, b'{"code":404,"message":"not found","data":{}}', "application/json")

    def do_GET(self):
        self.handle_one()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n:
            self.rfile.read(n)
        self.handle_one()

    def log_message(self, fmt, *args):
        pass


SERVERS = []
DIAG_RESULT = [""]


def _bind(httpd_port, tls, addr):
    httpd = http.server.ThreadingHTTPServer((addr, httpd_port), OtaHandler)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(PEM_FILE, KEY_FILE)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    SERVERS.append(httpd)
    log(f"[服务器] {'HTTPS' if tls else 'HTTP '} 已监听 {addr}:{httpd_port}")
    return True


def start_servers(http_port, https_port):
    stop_servers()
    errs = []
    for port, tls in ((http_port, False), (https_port, True)):
        bound = False
        for addr in ("0.0.0.0", "127.0.0.1"):
            try:
                _bind(port, tls, addr)
                bound = True
                break
            except OSError as e:
                errs.append(f"{addr}:{port} -> WinError {e.winerror if hasattr(e,'winerror') else '?'} {e.strerror}")
        if not bound:
            log(f"[服务器] {'HTTPS' if tls else 'HTTP '} 端口 {port} 绑定失败: {errs[-1]}", "warn")
    if len(SERVERS) < 2:
        diagnose_ports()
        return False
    return True


def diagnose_ports():
    """端口绑定失败时自动诊断: 谁占用了 / 是否 winnat 保留"""
    DIAG_RESULT[0] = "unknown"
    log("[诊断] 正在检查端口占用来源...")
    p = run(["netstat", "-ano", "-p", "TCP"])
    owners = {}
    for line in (p.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[3] == "LISTENING":
            local = parts[1]
            for port in (80, 443):
                if local.endswith(f":{port}"):
                    owners.setdefault(port, set()).add(parts[4])
    p2 = run(["netsh", "interface", "ipv4", "show", "excludedportrange", "protocol=tcp"])
    excluded = []
    for line in (p2.stdout or "").splitlines():
        s = line.strip()
        if s and s[0].isdigit():
            try:
                lo, hi = s.split()[:2]
                if int(lo) <= 80 <= int(hi) or int(lo) <= 443 <= int(hi):
                    excluded.append(f"{lo}-{hi}")
            except Exception:
                pass

    pids = sorted({pid for s in owners.values() for pid in s})
    names = []
    for pid in pids:
        t = run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV"])
        first = (t.stdout or "").strip().splitlines()
        if len(first) > 1:
            names.append(first[1].split('","')[0].strip('"'))
    if names:
        DIAG_RESULT[0] = "process"
        log(f"[诊断] 发现占用进程: {', '.join(names)} (PID {','.join(pids)})", "warn")
        log("[诊断] 请退出这些程序(常见: Clash/V2Ray 等代理、IIS、其他服务器软件)后重试", "warn")
        return "process"
    if excluded:
        DIAG_RESULT[0] = "winnat"
        log(f"[诊断] 无进程占用, 但系统保留了端口段: {', '.join(excluded)}", "warn")
        log("[诊断] 这是 Hyper-V/WSL2/Docker(winnat) 的端口保留, 本工具可自动修复", "warn")
        return "winnat"
    log("[诊断] 未找到明确原因(可能是杀毒软件拦截), 请临时退出杀毒软件后重试", "warn")
    return "unknown"


def winnat_fix_and_bind(http_port, https_port):
    """临时停 winnat -> 抢绑端口 -> 恢复 winnat"""
    log("[修复] 临时停止 winnat (Windows NAT Driver)...")
    run(["net", "stop", "winnat"])
    try:
        ok = start_servers(http_port, https_port)
    finally:
        r = run(["net", "start", "winnat"])
        log("[修复] winnat 已恢复 " + ("ok" if r.returncode == 0 else "(恢复失败, 重启电脑也会自动恢复)"))
    return ok


def stop_servers():
    for s in SERVERS:
        try:
            s.shutdown()
        except Exception:
            pass
    SERVERS.clear()


# ---------------- 一键流程 ----------------
def do_start(version, allow_no_app):
    OtaHandler.fw_version = version or FW_VERSION_DEFAULT
    log("=== 开始配置 (需要管理员) ===")
    log(f"[固件] {os.path.basename(FW_PATH)} ({len(FW_DATA)} 字节, 版本 {FW_INFO})")
    pfns = get_flydigi_pfns()
    if pfns:
        log("[检测] 已安装 Flydigi 应用: " + ", ".join(pfns))
    else:
        log("[检测] 未找到 Flydigi 应用!", "warn")
        if not allow_no_app:
            log("[检测] 已中止。请先安装 Flydigi Space Station 再运行本工具", "warn")
            return False
        log("[检测] 按用户要求继续 (应用可能尚未安装)", "warn")
    hosts_add()
    cert_install()
    loopback_config(pfns, add=True)
    firewall_config(add=True)
    flush_dns()
    ok = start_servers(FW_PORT_HTTP, FW_PORT_HTTPS)
    if not ok:
        cause = DIAG_RESULT[0] if DIAG_RESULT[0] else "unknown"
        if cause == "winnat":
            ok = winnat_fix_and_bind(FW_PORT_HTTP, FW_PORT_HTTPS)
        else:
            log("[修复] 无法自动修复。常见处理: 退出代理/VPN软件后点 [① 一键启动劫持] 重试", "warn")
            return False
    if ok:
        log("")
        log("✅ 劫持已就绪! 现在去 Flydigi Space Station:", "ok")
        log("   设置 → 固件版本 页面应出现 9.9.9.9 的升级提示", "ok")
        log("   点确认升级, 刷写完成前勿断开手柄!", "ok")
        log("   完成后回到本工具点 [② 一键还原系统]", "ok")
    return ok


def do_restore():
    stop_servers()
    log("=== 还原系统配置 ===")
    try:
        hosts_remove()
    except Exception as e:
        log(f"[hosts] 清理失败: {e}", "warn")
    cert_remove()
    loopback_config(get_flydigi_pfns(), add=False)
    firewall_config(add=False)
    flush_dns()
    log("✅ 已全部还原, 可正常访问官方服务器", "ok")


# ---------------- UI ----------------
GUIDE = [
    ("第 1 步", "仅适用于飞智黑武士5s"),
    ("第 2 步", "程序会自动查找本机留存的固件备份 (Flydigi 应用升级时留下), 也可点 [选择固件] 手动指定 .bin 文件"),
    ("第 3 步", "手柄用 USB 线或 Xbox 无线接收器连接到这台电脑"),
    ("第 4 步", "确认这台电脑已安装 [Flydigi Space Station] 应用 (能正常打开它)"),
    ("第 5 步", "勾选下方\"我已阅读\"后点 [① 一键启动劫持], 等日志出现 \"劫持已就绪\""),
    ("第 6 步", "打开 Flydigi Space Station → 设置 → 固件版本, 页面会出现 9.9.9.9 的升级提示"),
    ("第 7 步", "点 [确认升级] — 之后什么都不要碰! 刷写中断开手柄可能导致手柄报废(变砖)"),
    ("第 8 步", "手柄重启后查看固件版本: 显示 1.0.5.4 即回退成功 (使用其他固件则显示对应版本)"),
    ("第 9 步", "无论成功与否, 回到本工具点 [② 一键还原系统], 否则 Flydigi 应用将无法联网!"),
]

DISCLAIMER = ("免责条款: 本工具仅供个人学习研究及自有设备固件维护使用, 严禁用于商业用途或转售。"
              "刷写固件存在变砖风险, 因使用本工具造成的设备损坏、数据丢失或任何其他损失, "
              "均由使用者自行承担, 作者概不负责。请谨慎操作。")


def set_dpi_awareness():
    """启用 per-monitor v2 DPI 感知, 保证不同分辨率/缩放下文字清晰"""
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # PER_MONITOR_AWARE_V2
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def apply_win11_window(root):
    """Win11 视觉: 深色标题栏 + 圆角窗口 (不支持的系统自动跳过)"""
    try:
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        # DWMWA_USE_IMMERSIVE_DARK_MODE = 20
        val = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(val), 4)
        # DWMWA_WINDOW_CORNER_PREFERENCE = 33, DWMWCP_ROUND = 2
        val2 = ctypes.c_int(2)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(val2), 4)
    except Exception:
        pass


def build_ui():
    root = tk.Tk()
    root.title(APP_TITLE)
    root.geometry("960x900")
    root.minsize(860, 780)
    root.resizable(False, False)  # 固定窗口尺寸, 避免 resize 重绘卡顿 (DPI 适配不受影响)
    root.configure(bg="#202020")

    sv_ttk.set_theme("dark")
    apply_win11_window(root)

    BG = "#202020"
    FG = "#e4e4e4"
    MUTED = "#9a9a9a"
    OK_FG = "#6ccb5f"
    WARN_FG = "#ff99a4"
    RED = "#ff5c5c"

    style = ttk.Style(root)
    CARD_BG = style.lookup("Card.TFrame", "background") or "#2b2b2b"
    style.configure("Title.TLabel", font=("Microsoft YaHei UI", 13, "bold"))
    style.configure("Step.TLabel", font=("Microsoft YaHei UI", 11))
    style.configure("StepTitle.TLabel", font=("Microsoft YaHei UI", 11, "bold"), foreground="#7cc7ff")
    style.configure("StepKey.TLabel", font=("Microsoft YaHei UI", 11, "bold"))
    style.configure("Small.TLabel", font=("Microsoft YaHei UI", 10), foreground=MUTED)

    # ---- 顶部标题 ----
    ttk.Label(root, text="Flydigi 手柄固件回退工具", style="Title.TLabel").pack(
        anchor="w", padx=24, pady=(16, 0))
    ttk.Label(root, text="1.0.5.8 → 1.0.5.4 备份固件 · 仅适用于黑武士5s", style="Small.TLabel").pack(
        anchor="w", padx=24, pady=(0, 8))

    # ---- 步骤卡片 ----
    frm_guide = ttk.Labelframe(root, text=" 操作步骤 — 请按顺序执行, 不要跳步 ", style="Card.TLabelframe")
    frm_guide.pack(fill="x", padx=20, pady=6)
    guide_labels = []
    for i, (step, desc) in enumerate(GUIDE):
        color = "#e4e4e4"
        bold = False
        if i == 6:
            color, bold = RED, True
        elif i == 8:
            color, bold = OK_FG, True
        elif i == 0:
            color, bold = "#ffd166", True
        row = ttk.Frame(frm_guide, style="Card.TFrame")
        row.pack(fill="x", padx=16, pady=3)
        st = ttk.Label(row, text=step, style="StepTitle.TLabel")
        st.pack(side="left", padx=(0, 10))
        lb = tk.Label(row, text=desc, anchor="w", foreground=color,
                      font=("Microsoft YaHei UI", 11, "bold") if bold else ("Microsoft YaHei UI", 11),
                      bg=CARD_BG, justify="left")
        lb.pack(side="left", fill="x", expand=True)
        guide_labels.append(lb)

    # ---- 阅读确认 ----
    acked = tk.BooleanVar(value=False)
    chk_ack = tk.Checkbutton(
        root, variable=acked, anchor="w", justify="left",
        text='我已阅读以上步骤与免责条款, 知道刷写中不能断开手柄/休眠, 知道本工具会临时修改 hosts/证书/防火墙(点"一键还原"可全部撤销)',
        font=("Microsoft YaHei UI", 11), bg=CARD_BG, fg=FG,
        activebackground=CARD_BG, activeforeground=FG,
        selectcolor="#3a3a3a", highlightthickness=0, bd=0)

    # ---- 操作卡片 ----
    frm_top = ttk.Labelframe(root, text=" 操作 ", style="Card.TLabelframe")
    frm_top.pack(fill="x", padx=20, pady=6)
    inner = ttk.Frame(frm_top, style="Card.TFrame")
    inner.pack(fill="x", padx=16, pady=10)
    chk_ack.pack(in_=inner, anchor="w", pady=(0, 8))

    ver_row = ttk.Frame(inner, style="Card.TFrame")
    ver_row.pack(fill="x")
    ttk.Label(ver_row, text="对外固件版本号(一般不用改):", style="Step.TLabel").pack(side="left")
    ver = tk.StringVar(value=FW_VERSION_DEFAULT)
    ttk.Entry(ver_row, textvariable=ver, width=10).pack(side="left", padx=8)

    # ---- 固件文件选择 ----
    fw_row = ttk.Frame(inner, style="Card.TFrame")
    fw_row.pack(fill="x", pady=(8, 0))
    ttk.Label(fw_row, text="回退固件文件:", style="Step.TLabel").pack(side="left")
    lbl_fw = tk.Label(fw_row, text="未加载", anchor="w", foreground=MUTED, bg=CARD_BG,
                      font=("Microsoft YaHei UI", 10))
    lbl_fw.pack(side="left", padx=8, fill="x", expand=True)

    def pick_fw():
        p = tkfd.askopenfilename(
            title="选择固件文件 (.bin)",
            filetypes=[("固件文件 (*.bin)", "*.bin"), ("所有文件", "*.*")])
        if not p:
            return
        try:
            info = load_fw_file(p)
            lbl_fw.config(text=f"{os.path.basename(p)}  ({len(FW_DATA):,} 字节, 版本 {info})", foreground=FG)
            log(f"[固件] 已加载: {p}")
            log(f"[固件] 版本 {info}, {len(FW_DATA):,} 字节")
        except Exception as e:
            tkmb.showerror("固件无效", f"无法加载该文件:\n{e}")

    btn_fw = ttk.Button(fw_row, text="选择固件...", command=pick_fw)
    btn_fw.pack(side="right")

    def ensure_fw():
        """启动前确保固件已加载: 自动检测 -> 手动选择"""
        if FW_DATA:
            return True
        auto = detect_local_fw()
        if auto:
            try:
                info = load_fw_file(auto)
                lbl_fw.config(text=f"{os.path.basename(auto)}  ({len(FW_DATA):,} 字节, 版本 {info})", foreground=FG)
                log(f"[固件] 自动找到本机备份: {auto}")
                log(f"[固件] 版本 {info}, {len(FW_DATA):,} 字节")
                return True
            except Exception:
                pass
        tkmb.showinfo(
            "需要固件文件",
            "未在本机找到固件备份。\n\n"
            "程序会查找 Flydigi 应用升级时留下的 LocalState 备份 (ota_*.bin),\n"
            "找不到时请手动选择固件 .bin 文件\n"
            "(可从项目仓库 firmware/ 下载测试固件, 或使用自己的备份)。")
        pick_fw()
        return bool(FW_DATA)

    def confirm_start_dialog():
        return tkmb.askyesno(
            "开始前最后确认",
            "适用机型: 飞智黑武士5s\n\n"
            "即将执行以下操作:\n\n"
            "  · 修改 hosts (testapi/api.flydigi.com -> 127.0.0.1)\n"
            "  · 安装自签证书到受信任的根证书颁发机构\n"
            "  · 为 Flydigi 应用添加 UWP 回环豁免\n"
            "  · 放行防火墙 80/443 并启动本地升级服务器\n\n"
            "确认手柄已连接, 且理解刷写中断可能变砖。\n"
            "因使用本工具造成的一切损失由使用者自行承担。\n\n"
            "确定开始吗?",
            icon="warning")

    def on_start():
        if not acked.get():
            return
        if not ensure_fw():
            return
        if not confirm_start_dialog():
            return
        btn_start.config(state="disabled")
        threading.Thread(target=lambda: (do_start(ver.get().strip(), allow_no_app=True),
                                         LOGQ.put(("__done__", None))), daemon=True).start()

    def on_restore():
        btn_restore.config(state="disabled")
        threading.Thread(target=lambda: (do_restore(),
                                         LOGQ.put(("__done__", None))), daemon=True).start()

    btn_row = ttk.Frame(inner, style="Card.TFrame")
    btn_row.pack(fill="x", pady=(8, 0))
    btn_start = ttk.Button(btn_row, text="① 一键启动劫持", command=on_start, state="disabled",
                           style="Accent.TButton")
    btn_start.pack(side="left", padx=(0, 12), ipadx=10, ipady=2)
    btn_restore = ttk.Button(btn_row, text="② 一键还原系统", command=on_restore)
    btn_restore.pack(side="left", ipadx=10, ipady=2)

    def ack_toggle():
        btn_start.config(state="normal" if acked.get() else "disabled")

    chk_ack.config(command=ack_toggle)

    # ---- 状态条 ----
    lbl_status = tk.Label(root, text="状态: 未启动 — 请先阅读上方步骤并勾选确认", anchor="w",
                          bg="#2b2b2b", fg=MUTED, font=("Microsoft YaHei UI", 12, "bold"),
                          padx=16, pady=8)
    lbl_status.pack(fill="x", padx=20, pady=6)

    # ---- 日志卡片 ----
    frm_log = ttk.Labelframe(root, text=" 日志 ", style="Card.TLabelframe")
    frm_log.pack(fill="both", expand=True, padx=20, pady=6)
    txt = scrolledtext.ScrolledText(frm_log, height=11, font=("Microsoft YaHei UI", 11),
                                    bg="#272727", fg=FG, insertbackground=FG,
                                    relief="flat", padx=10, pady=8, wrap="word")
    txt.pack(fill="both", expand=True, padx=10, pady=8)
    txt.tag_config("warn", foreground=WARN_FG, font=("Microsoft YaHei UI", 11, "bold"))
    txt.tag_config("ok", foreground=OK_FG, font=("Microsoft YaHei UI", 11, "bold"))

    # ---- 免责条款 ----
    lb_dis = tk.Label(root, text=DISCLAIMER, foreground=RED, bg=BG,
                      font=("Microsoft YaHei UI", 10), justify="left")
    lb_dis.pack(fill="x", padx=24, pady=(4, 12))

    # ---- 文字随窗口宽度自适应换行 (防抖: 拖动停止后才重排, 避免卡顿) ----
    _last_sizes = {"guide": 0, "ack": 0, "dis": 0}

    def apply_reflow(w):
        wg = max(480, w - 170)
        wa = max(420, w - 110)
        wd = max(420, w - 70)
        if _last_sizes["guide"] != wg:
            _last_sizes["guide"] = wg
            for lb in guide_labels:
                lb.configure(wraplength=wg)
        if _last_sizes["ack"] != wa:
            _last_sizes["ack"] = wa
            try:
                chk_ack.configure(wraplength=wa)
            except tk.TclError:
                pass
        if _last_sizes["dis"] != wd:
            _last_sizes["dis"] = wd
            try:
                lb_dis.configure(wraplength=wd)
            except tk.TclError:
                pass

    _reflow_job = [None]

    def schedule_reflow(event=None):
        if _reflow_job[0] is not None:
            try:
                root.after_cancel(_reflow_job[0])
            except Exception:
                pass
        _reflow_job[0] = root.after(100, lambda: apply_reflow(root.winfo_width()))

    root.bind("<Configure>", schedule_reflow)
    root.after(120, lambda: apply_reflow(root.winfo_width()))

    def poll():
        try:
            while True:
                m, tag = LOGQ.get_nowait()
                if m == "__done__":
                    btn_restore.config(state="normal")
                    continue
                txt.insert(tk.END, m + "\n", tag or ())
                txt.see(tk.END)
                if "劫持已就绪" in m:
                    lbl_status.config(text="状态: 劫持运行中 — 现在去 Flydigi 应用确认升级, 完成后回来点还原",
                                      bg="#123512", fg=OK_FG)
                elif "已全部还原" in m or "已中止" in m:
                    lbl_status.config(text="状态: 已还原/未运行", bg="#2b2b2b", fg=MUTED)
                elif "固件已下发" in m:
                    lbl_status.config(text="状态: 手柄升级中! 不要断开手柄!!", bg="#4a1216", fg=RED)
        except queue.Empty:
            pass
        root.after(150, poll)

    log(f"管理员权限: {'是' if is_admin() else '否(将尝试提权)'}")
    if FW_DATA:
        log(f"固件已就绪: {os.path.basename(FW_PATH)} ({len(FW_DATA):,} 字节, 版本 {FW_INFO})")
        lbl_fw.config(text=f"{os.path.basename(FW_PATH)}  ({len(FW_DATA):,} 字节, 版本 {FW_INFO})", foreground=FG)
    else:
        auto = detect_local_fw()
        if auto:
            log(f"检测到本机固件备份: {auto} (点击 ① 启动时自动加载)")
        else:
            log("未检测到固件文件 — 点击 ① 启动时可自动查找或手动选择")
    poll()
    root.mainloop()


# ---------------- 入口 ----------------
def selftest():
    global CER, PEM, KEY
    path = detect_local_fw()
    assert path, "selftest 未找到固件文件"
    info = load_fw_file(path)
    assert len(FW_DATA) > 0x400 and FW_DATA[:4] == b"AOTA", "固件数据异常"
    print("FW:", os.path.basename(path), info, len(FW_DATA), "bytes")
    CER, PEM, KEY = ensure_cert()
    assert b"BEGIN CERTIFICATE" in PEM and b"PRIVATE KEY" in KEY
    assert CER.startswith(b"0\x82"), "cer 格式异常"
    OtaHandler.fw_version = "9.9.9.9"
    start_servers(*SELFTEST_PORTS)
    import urllib.request
    r = urllib.request.urlopen(f"http://127.0.0.1:{SELFTEST_PORTS[0]}/pc/Update/firmware?x=1", timeout=5)
    j = json.loads(r.read())
    assert j["code"] == 0 and j["data"]["chip_list"]["main_chip"]["version"] == "9.9.9.9", j
    r2 = urllib.request.urlopen(f"https://127.0.0.1:{SELFTEST_PORTS[1]}/fw_backup.bin", timeout=5,
                                context=ssl._create_unverified_context())
    assert len(r2.read()) == len(FW_DATA)
    stop_servers()
    print("SELFTEST OK")


def main():
    global CER, PEM, KEY
    CER, PEM, KEY = ensure_cert()

    if "--selftest" in sys.argv:
        selftest()
        return

    import tkinter.messagebox as tkmb
    if not is_admin():
        if elevate():
            sys.exit(0)
        tkmb.showerror("权限不足", "需要管理员权限才能修改 hosts / 安装证书。\n请右键以管理员身份运行。")
        sys.exit(1)

    set_dpi_awareness()
    build_ui()


if __name__ == "__main__":
    main()
