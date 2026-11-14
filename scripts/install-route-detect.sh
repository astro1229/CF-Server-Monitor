#!/usr/bin/env bash
# route-detect 一键安装：NextTrace + route_detect.py + 配置 + cron + 试跑
# 用法：curl -sSL <安装脚本URL> | bash
# 全程只问两件事：选哪台机器、面板管理员密码。
set -euo pipefail

PANEL_URL="https://zozv.de"
ADMIN_USER="chy"
INSTALL_DIR="/opt/route-detect"
CONFIG_DIR="${HOME}/.config/route-detect"
CONFIG_FILE="${CONFIG_DIR}/config.json"
LOG_FILE="/var/log/route-detect.log"

# 从终端读输入（curl | bash 时 stdin 是脚本本身，必须走 /dev/tty）
prompt() {
  local var="$1" text="$2" secret="${3:-0}"
  local val=""
  if [ "$secret" = "1" ]; then
    read -rsp "$text" val < /dev/tty; echo >&2
  else
    read -rp "$text" val < /dev/tty
  fi
  printf -v "$var" '%s' "$val"
}

echo "== route-detect 一键安装 =="
if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行（或前面加 sudo）" >&2; exit 1
fi

# 1. NextTrace
if command -v nexttrace >/dev/null 2>&1; then
  echo "[1/5] NextTrace 已装：$(nexttrace --version 2>/dev/null | head -1 | tr -d '\0')"
else
  echo "[1/5] 安装 NextTrace v1.7.6 …"
  curl -Ls https://github.com/nxtrace/NTrace-core/releases/download/v1.7.6/nexttrace_linux_amd64 -o /usr/local/bin/nexttrace
  chmod +x /usr/local/bin/nexttrace
  echo "      已装：$(nexttrace --version 2>/dev/null | head -1 | tr -d '\0')"
fi

# 2. 脚本本体（内嵌）
echo "[2/5] 写入 ${INSTALL_DIR}/route_detect.py …"
mkdir -p "${INSTALL_DIR}"
cat > "${INSTALL_DIR}/route_detect.py" <<'ROUTE_DETECT_PY'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
探针三网回程线路自动探测脚本

用途：每小时在每台 VPS 上跑一次，测本机到四川电信 / 联通 / 移动的回程
线路，识别出线路类型后，把面板（CF-Server-Monitor）上本台服务器标签的
第一个改成线路名（例如 CN2GT），保留后面的手动标签（带宽、重置日等）。
线路没变就不写回，避免无意义调用管理接口。
同轮还测 IPv6 三网：目标是 TQ -v6 模式四川三网节点的字面 IPv6
（getNodes 下发，zstatic v6 域名没有 AAAA 记录，只能用字面 IP），
v6 线路标签以 "v6 "（空格）前缀作为第二个自动标签；本机无 IPv6 出口时
优雅跳过 v6、只出 v4 数据，不影响整轮。面板保存 tags 时会删掉冒号，
所以写出不用 "v6:"——"v6 " 的空格面板会保留。

探测工具：优先 NextTrace（命令 nexttrace），没有则回退 traceroute。
  注意：NextTrace 没有 --quiet 参数（-q 是 --queries 的简写），所以用
  --no-color + --table / -k 模式出简洁表格，再用正则解析每一跳的 IP/ASN。
线路分类：按 TcpQuality（ibsgss/TcpQuality runTcpQuality-core.sh
  classify()）的规则——59.43.* 直接算 CN2，59.43 之后转 163 即 CN2GT、
  否则 CN2GIA；AS58807=CMIN2、AS58453/AS9808/AS56040-48=CMI、
  AS9929=9929；任何运营商只要经过 59.43 整条就标 CN2。
面板管理接口：POST <panel_url>/admin/api，JSON body {"action": ...}。
  login → Bearer token；list → 全量服务器；edit → 全量回写（缺失字段会
  被默认值覆盖，所以必须先 list 拿到整台机器的当前对象，只改 tags）。

配置：~/.config/route-detect/config.json（见 config.example.json），
  或环境变量 ROUTE_DETECT_CONFIG 指定路径；面板地址/账号/密码/server_id
  也可用 ROUTE_DETECT_PANEL_URL 等环境变量覆盖配置文件。
  配置文件权限要求 600，过宽会警告。

依赖：纯 Python 3 标准库 + 系统上的 nexttrace（或 traceroute）。
退出码：0 成功或线路未变；1 探测/登录/面板调用失败；2 配置问题；
  3 三个运营商都没识别出线路（不写标签，直接退出）。
"""

import argparse
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

# 面板域名可能有 IPv6 解析但 VPS 上 v6 出网不稳时卡 TLS，强制走 IPv4
# （与 ~/workspace/nodeseek-checkin/checkin.py 同款做法）
_orig_getaddrinfo = socket.getaddrinfo


def _ipv4_only(host, port, family=0, type=0, proto=0, flags=0):
    return _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)


socket.getaddrinfo = _ipv4_only

TZ = ZoneInfo("Asia/Shanghai")
TRACE_TIMEOUT = 120          # 单次 traceroute 超时（秒）
API_TIMEOUT = 30             # 面板接口超时（秒）

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "route-detect" / "config.json"
ENV_CONFIG_PATH = "ROUTE_DETECT_CONFIG"
ENV_OVERRIDES = {
    "panel_url": "ROUTE_DETECT_PANEL_URL",
    "admin_username": "ROUTE_DETECT_ADMIN_USERNAME",
    "admin_password": "ROUTE_DETECT_ADMIN_PASSWORD",
    "server_id": "ROUTE_DETECT_SERVER_ID",
}

# 默认探测目标：面板里现成的三网自定义节点域名（四川三网）
DEFAULT_TARGETS = {
    "ct": "sc-ct-v4.ip.zstaticcdn.com",   # 四川电信
    "cu": "sc-cu-v4.ip.zstaticcdn.com",   # 四川联通
    "cm": "sc-cm-v4.ip.zstaticcdn.com",   # 四川移动
}
# 默认 IPv6 探测目标：TQ -v6 模式四川三网节点的字面 IPv6（getNodes 下发，
# https://tcpquality.ibsgss.uk/getNodes，2026-11-12 生成；ASN 与 TCP
# 可达已逐个验证：电信 AS4134、联通 AS4837、移动 AS139080（四川移动），
# 三个地址 80/443 端口均能 TCP 建连）。
# 注意 sc-*-v6.ip.zstaticcdn.com 没有 AAAA 记录（dig 验证为空），
# 不能用域名，只能用这里的字面 IP——TQ -v6 也是用 getNodes 的固定 IP 直连。
# 三家公开 IPv6 DNS 是备用目标（ASN 与 TCP 53 均已验证可达）：
#   电信 240e:96:8000::1（AS4134）、联通 2408:8000::1（AS4837）、
#   移动 2409:8080::1（AS9808）。
# 如 TQ 节点 IP 失效，在配置里用 targets_v6 覆盖为对应运营商的 DNS 地址即可。
DEFAULT_TARGETS_V6 = {
    "ct": "240e:974:ecff:20:8000:0:b00:96",   # 四川电信
    "cu": "2408:8766:0:1002:8000:0:b00:3",    # 四川联通
    "cm": "2409:8c62:e10:32:8000:0:b00:79",   # 四川移动
}
V6_FALLBACK_TARGETS = {
    "ct": "240e:96:8000::1",   # 电信公开 IPv6 DNS
    "cu": "2408:8000::1",      # 联通公开 IPv6 DNS
    "cm": "2409:8080::1",      # 移动公开 IPv6 DNS
}
CARRIER_NAMES = {"ct": "电信", "cu": "联通", "cm": "移动"}

# 线路优先级（单台机器只出一个标签，取三个运营商里优先级最高的那条线）
PRIORITY = {"CN2GIA": 5, "CTGGIA": 5, "9929": 4, "10099": 4, "CMIN2": 3, "CN2GT": 2, "163": 1, "CMI": 1, "CMNET": 1, "4837": 1, "4808": 1, "CERNET2": 1, "CERNET": 1, "CSTNET": 1, "10099->9929": 4, "10099->4837": 4, "CMIN2->9929": 4, "CMIN2->4837": 3, "CMI->9929": 4, "CMI->4837": 1, "163->9929": 4, "163->4837": 1, "CMIN2->CMI": 3}

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# IPv6 地址：完整形（240e:974:ecff:20:8000:0:b00:96）、压缩形
# （2409:8080::1、fe80::1）、全零压缩（::1）、尾部压缩（2001:db8::）
# 与 v4 映射形（::ffff:1.2.3.4）。
# 分支顺序有讲究：带尾段的压缩形必须排在纯尾部 "::" 之前，否则
# "2409:8080::1" 会先被 "(xxxx:){1,7}:" 截成 "2409:8080::"。
# 注意 "10:00:00" 这类时间也会被分支误 match，但跳行里没有时间戳，
# 表头行又被跳号检查挡掉，所以只在跳行里用。
IPV6_RE = re.compile(
    r"(?:[0-9a-fA-F]{1,4}:){0,6}::ffff:(?:\d{1,3}\.){3}\d{1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:)+:(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}")
ASN_RE = re.compile(r"\bAS(\d+)\b", re.IGNORECASE)
# 每跳的第一个 RTT，如 "8.30ms"（NextTrace 每跳打 3 个 RTT，取第一个）。
RTT_RE = re.compile(r"(\d+(?:\.\d+)?)\s*ms")
# 地理位置文字里的 [...] 标签（如 [CN2-BackBone]），解析 geo 时去掉。
GEO_TAG_RE = re.compile(r"\[[^\]]*\]")


def now_str():
    return datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S")


def log(msg):
    print(f"[{now_str()}] {msg}", flush=True)


def fail(msg, code=1):
    log(f"错误：{msg}")
    return code


# ---------------------------------------------------------------- 配置

def load_config(path, dry_run):
    """读配置文件；dry-run 时没有配置文件也可以跑（只用默认目标）。"""
    cfg = {}
    if path.exists():
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            log(f"警告：配置文件 {path} 权限为 {oct(mode)}，过宽，"
                f"请执行 chmod 600 {path}（里面有管理员密码）")
        try:
            cfg = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"配置文件 {path} 解析失败：{e}")
        if not isinstance(cfg, dict):
            raise ValueError(f"配置文件 {path} 顶层必须是 JSON 对象")
    elif not dry_run:
        raise ValueError(
            f"找不到配置文件 {path}，请按 config.example.json 复制一份并填好，"
            f"或用环境变量 {ENV_CONFIG_PATH} 指定路径")
    else:
        log(f"dry-run：找不到配置文件 {path}，使用默认探测目标")

    # 环境变量覆盖配置文件里的同名项
    for key, env_name in ENV_OVERRIDES.items():
        val = os.environ.get(env_name, "").strip()
        if val:
            cfg[key] = val

    targets = dict(DEFAULT_TARGETS)
    file_targets = cfg.get("targets") or {}
    if not isinstance(file_targets, dict):
        raise ValueError("配置里的 targets 必须是对象，如 "
                         '{"ct": "...", "cu": "...", "cm": "..."}')
    for k, v in file_targets.items():
        if k in targets and str(v).strip():
            targets[k] = str(v).strip()
    cfg["targets"] = targets
    targets_v6 = dict(DEFAULT_TARGETS_V6)
    file_targets_v6 = cfg.get("targets_v6") or {}
    if not isinstance(file_targets_v6, dict):
        raise ValueError("配置里的 targets_v6 必须是对象，如 "
                         '{"ct": "240e:...", "cu": "2408:...", '
                         '"cm": "2409:..."}')
    for k, v in file_targets_v6.items():
        if k in targets_v6 and str(v).strip():
            targets_v6[k] = str(v).strip()
    cfg["targets_v6"] = targets_v6
    return cfg


def check_required_config(cfg):
    missing = [k for k in ("panel_url", "admin_username",
                           "admin_password", "server_id")
               if not str(cfg.get(k) or "").strip()]
    if missing:
        raise ValueError(f"配置缺失必填项：{', '.join(missing)}，"
                         f"请检查配置文件或环境变量")


# ---------------------------------------------------------------- 探测

def find_trace_tool():
    """优先 nexttrace，没有则回退 traceroute；两个都没有就明确报错退出。"""
    if shutil.which("nexttrace"):
        return "nexttrace"
    if shutil.which("traceroute"):
        log("未找到 nexttrace，回退到 traceroute（无 ASN 信息，"
            "只能靠 59.43 段识别 CN2 GIA，其余线路可能识别不出）")
        return "traceroute"
    raise RuntimeError(
        "未找到 nexttrace 或 traceroute，无法探测回程线路。\n"
        "请先安装 NextTrace（任选一种）：\n"
        "  通用一键安装：curl -sL https://nxtrace.org/nt | bash\n"
        "  Debian/Ubuntu：按 https://nxtrace.github.io/NTrace-core/ 接入官方 APT 源后 "
        "apt install nexttrace\n"
        "  或直接去 https://github.com/nxtrace/NTrace-core/releases 下载对应架构的二进制\n"
        "临时替代：apt install traceroute（只能识别 59.43 段的 CN2 GIA）")


def run_trace(target, tool, ipv6=False):
    """对一个目标跑一次路由探测，返回原始输出文本。

    ipv6=True 时用 --ipv6（NextTrace）或 -6（traceroute）。
    """
    if tool == "nexttrace":
        # NextTrace 没有 --quiet（-q 是 --queries）；用 --no-color + 简洁模式。
        # 注意：去色参数是 --no-color（或 -C），不是 --nocolor；写错会导致
        # nexttrace 打印 usage 却返回 0，解析器只能从 usage 文本里捡到
        # 零星 IP，误判为 2 跳且识别不出线路。
        # -k 是传统 traceroute 输出（新版默认将切 MTR，格式最稳）；--table 是
        # 表格输出；都不支持的老版本就用默认输出。解析只用正则，不依赖具体格式。
        fam = "--ipv6" if ipv6 else "--ipv4"
        attempts = [
            ["nexttrace", fam, "--no-color", "-k", target],
            ["nexttrace", fam, "--no-color", "--table", target],
            ["nexttrace", fam, "--no-color", target],
        ]
    else:
        attempts = [["traceroute", "-6" if ipv6 else "-4", "-n", target]]

    last_err = ""
    for args in attempts:
        try:
            r = subprocess.run(args, capture_output=True, text=True,
                               timeout=TRACE_TIMEOUT)
        except subprocess.TimeoutExpired:
            last_err = f"命令超时（>{TRACE_TIMEOUT}s）：{' '.join(args)}"
            continue
        except Exception as e:
            last_err = f"执行失败 {' '.join(args)}：{e}"
            continue
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout
        last_err = (f"{' '.join(args)} 返回码 {r.returncode}，"
                    f"stderr={r.stderr.strip()[:300]}")
        # nexttrace 参数不支持时会直接报 usage 错误，换下一组参数重试；
        # 其它失败（例如目标不可达）也会走到这里，最终统一报错。
    raise RuntimeError(f"探测 {target} 失败：{last_err}")


def _extract_geo(line, after_pos):
    """取 ASN（无 ASN 时取 "*" 占位符）之后那段当地理位置/网络文字。

    如 "中国 香港 电信/CTGNet"、"RFC1918"。去掉 [...] 标签与残留的
    RTT、* 号，空白合并；没有文字时返回 None。
    """
    rest = line[after_pos:]
    rest = GEO_TAG_RE.sub("", rest)
    rest = RTT_RE.sub("", rest)
    rest = re.sub(r"\s+", " ", rest).strip(" *")
    return rest or None


def parse_trace_output(text):
    """从 NextTrace / traceroute 输出里解析每一跳的 (IP, ASN, 延迟ms, 地理位置)。

    IPv4 与 IPv6 都解析：每行先找 IPv6 地址，找不到再找 IPv4（IPv6
    里嵌的 v4 映射地址 ::ffff:1.2.3.4 会被 IPv6 分支整段取走，不会
    只取到里面那段 v4）。每行取第一个 ASxxxx、ASN 之后的地理位置文字；
    RTT 取同行第一个，NextTrace 默认把延迟打在下一行（缩进的
    "3.80 ms / 11.07 ms / 7.35 ms"），此时取下一行的第一个 RTT。
    没有 ASN 的行按 TQ infer 表从 IP 段推断（如 59.43.* → AS4809、
    162.219.85.* → AS10099），推断不出才留 None；没有 RTT 的行延迟
    为 None，没有地理位置文字的行 geo 为 None。
    表头、无 IP 的行直接跳过。
    """
    lines = text.splitlines()
    hops = []
    for i, line in enumerate(lines):
        # 只解析跳行（行首是跳号）；表头、"Trace Stopped" 尾行等不含跳号，
        # 但含目标 IP，误解析会多出一跳（geo 只剩 ")"）。
        if not re.match(r"^\s*\d+\s", line):
            continue
        m = IPV6_RE.search(line) or IP_RE.search(line)
        if not m:
            continue
        a = ASN_RE.search(line)
        if a:
            geo_pos = a.end()
            asn = int(a.group(1))
        else:
            # 无 ASN 时用 "*" 占位符定位
            star = line.find("*", m.end())
            geo_pos = star + 1 if star >= 0 else m.end()
            asn = None
        # NextTrace 有时漏标 ASN（如 59.43 跳漏 AS4809、联通国际 CUG 跳
        # 漏 AS10099），按 TQ infer 表从 IP 段推断补上，否则逐跳表
        # 对应行下面不显示 ASN（_infer_asn_from_ip 在文件后面定义，
        # 调用时才解析名字，不影响导入）。
        if asn is None:
            asn = _infer_asn_from_ip(m.group(0))
        geo = _extract_geo(line, geo_pos)
        r = RTT_RE.search(line)
        if not r and i + 1 < len(lines):
            r = RTT_RE.search(lines[i + 1])
        hops.append((m.group(0), asn,
                     float(r.group(1)) if r else None, geo))
    return hops


# ---------------------------------------------------------------- TQ 分类
# 以下函数逐条对齐 TcpQuality 官方源码
# （runTcpQuality-core.sh 的 route_label_from_ip_trace() / classify()，
# 2026-11-13 用户定：三网回程线路判定方式与 TQ 保持一致）。
# 不要凭印象改动；改动前先对照 /tmp/tq-core.sh。
#
# 归一化：ips/asns 为等长列表，asns 是字符串（"" 表示未知，与 TQ 的 awk
# 字符串一致）；下标 0-based（TQ 的 awk 是 1-based，换算时注意）。

_CTGNET_PREFIXES = ("203.22.182.", "203.22.178.", "203.22.179.",
                    "203.128.224.", "69.194.", "2400:9380:")
# TQ is_163_ip：注意不含 218.30.（那是 is_oversea_163_ip，分类不用）。
# 与 classify_hop 用的 _is_163_ip（含 218.30.，逐跳显示保持现状）区分开。
_TQ_163_PREFIXES = ("202.97.", "202.96.", "219.141.", "219.142.", "106.37.",
                    "240e:")
_TELECOM_ACCESS_ASNS = {"4134", "4811", "4812", "4847", "23724", "134756",
                        "133776", "139201", "139203", "148969", "38283",
                        "58540", "58563"}
_TELECOM_ACCESS_PREFIXES = ("1.202.", "27.129.", "36.110.", "36.112.",
                            "58.213.", "101.95.", "101.226.", "106.227.",
                            "111.74.", "117.21.", "117.68.", "124.127.",
                            "140.249.", "180.102.", "183.47.", "219.148.",
                            "220.181.")
_MOBILE_ACCESS_ASNS = {"24547", "132510"}
_MOBILE_ACCESS_PREFIXES = ("111.63.", "183.201.", "183.203.")
_10099_PREFIXES = ("103.214.", "103.228.68.", "103.239.176.", "118.26.151.",
                   "162.245.124.", "202.77.23.", "203.160.66.",
                   "203.160.75.", "2401:8a00:",
                   # 联通国际 CUG：43.255.170.0/24 实测属 AS10099
                   # （ip-api 查 43.255.170.1/.77/.200 均为 AS10099）。
                   # 注意不是整个 43.255.168.0/21：43.255.175.1 已是
                   # AS9534、43.255.160.1 是 AS23838，只补这一个 /24。
                   # TQ 的 10099 入口表里没有这一段；这里只影响缺 ASN 时
                   # 的推断（ASN 在时本来就认 AS10099），不改 TQ 分类本身。
                   "43.255.170.")
_UNICOM_BACKBONE_PREFIXES = ("210.14.", "210.51.", "210.78.", "218.105.",
                             "219.158.", "2408:")
_UNICOM_BACKBONE_ASNS = {"9929", "4837", "4808"}
_UNICOM_ACCESS_ASNS = {"17816", "135061", "136958", "140979"}
# TQ infer_asn_from_ip 里 CERNET（AS4538）的 IP 段：固定前缀 + 第二段范围。
_4538_PREFIXES = ("59.64.", "101.4.", "101.76.", "111.114.", "113.54.",
                  "115.24.", "115.156.", "183.172.", "202.38.19",
                  "202.112.", "202.113.", "202.114.", "202.115.",
                  "202.116.", "202.117.", "202.118.", "202.119.",
                  "202.120.", "202.194.", "202.196.", "202.197.",
                  "202.198.", "202.200.", "202.201.", "202.202.",
                  "202.207.")


def _is_ctgnet_ip(ip):
    """TQ is_ctgnet_ip。"""
    return ip.startswith(_CTGNET_PREFIXES)


def _tq_is_163_ip(ip):
    """TQ is_163_ip（不含 218.30.）。"""
    return ip.startswith(_TQ_163_PREFIXES)


def _is_telecom_access_asn(asn):
    """TQ is_telecom_access_asn（asn 是字符串）。"""
    return asn in _TELECOM_ACCESS_ASNS


def _is_telecom_access_ip(ip):
    """TQ is_telecom_access_ip。"""
    return ip.startswith(_TELECOM_ACCESS_PREFIXES)


def _is_mobile_access_asn(asn):
    """TQ is_mobile_access_asn（asn 是字符串）。"""
    return asn in _MOBILE_ACCESS_ASNS


def _is_mobile_access_ip(ip):
    """TQ is_mobile_access_ip。"""
    return ip.startswith(_MOBILE_ACCESS_PREFIXES)


def _is_10099_entry_ip(ip):
    """TQ is_10099_entry_ip：10099 入口段（含 162.219.(32-39|85).）。"""
    if ip.startswith(_10099_PREFIXES):
        return True
    if ip.startswith("162.219."):
        parts = ip.split(".")
        if len(parts) >= 3 and parts[2].isdigit():
            third = int(parts[2])
            if 32 <= third <= 39 or third == 85:
                return True
    return False


def _is_10099_hop(asn, ip):
    """TQ is_10099_hop：ASN 为准，ASN 缺失时用 IP 段兜底。"""
    return asn == "10099" or (asn == "" and _is_10099_entry_ip(ip))


def _is_unicom_backbone_ip(ip):
    """TQ is_unicom_backbone_ip。"""
    return ip.startswith(_UNICOM_BACKBONE_PREFIXES)


def _is_unicom_backbone_asn(asn):
    """TQ is_unicom_backbone_asn。"""
    return asn in _UNICOM_BACKBONE_ASNS


def _is_unicom_access_asn(asn):
    """TQ is_unicom_access_asn。"""
    return asn in _UNICOM_ACCESS_ASNS


def _is_5604x(asn):
    """TQ is_cmi_asn 里的 /^5604[0-8]$/：AS56040–56048。"""
    return asn.isdigit() and 56040 <= int(asn) <= 56048


def _is_4538_ip(ip):
    """TQ infer_asn_from_ip 里 CERNET（AS4538）的 IP 段。"""
    if ip.startswith(_4538_PREFIXES):
        return True
    parts = ip.split(".")
    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
        first, second = int(parts[0]), int(parts[1])
        if first == 210 and (26 <= second <= 29 or 30 <= second <= 39
                             or 40 <= second <= 47):
            return True
        if first == 219 and 224 <= second <= 229:
            return True
        if first == 222 and (116 <= second <= 123 or 192 <= second <= 199
                             or 200 <= second <= 207):
            return True
    return False


def _infer_asn_from_ip(ip):
    """TQ infer_asn_from_ip：ASN 缺失时按 IP 段推断 ASN。返回 int 或 None。
    顺序与 TQ 源码一致（先匹配先返回）。"""
    if ip.startswith("59.43."):
        return 4809
    if (ip.startswith("203.22.182.") or ip.startswith("203.22.178.")
            or ip.startswith("203.22.179.")
            or ip.startswith("203.128.224.")
            or ip.startswith("69.194.")):
        return 23764
    if ip.startswith("2400:9380:"):
        return 23764
    if (ip.startswith("202.97.") or ip.startswith("202.96.")
            or ip.startswith("219.141.") or ip.startswith("219.142.")
            or ip.startswith("106.37.")):
        return 4134
    if ip.startswith("240e:"):
        return 4134
    if ip.startswith("219.158."):
        return 4837
    if ip.startswith("2408:"):
        return 4837
    if ip.startswith("223.120.") or ip.startswith("223.119."):
        return 58453
    if (ip.startswith("221.183.") or ip.startswith("111.24.")
            or ip.startswith("111.13.")):
        return 9808
    if ip.startswith("2402:4f00:f000:"):
        return 58807
    if ip.startswith("2409:8080:"):
        return 9808
    if _is_10099_entry_ip(ip):
        return 10099
    if ip.startswith("2401:8a00:"):
        return 10099
    if (ip.startswith("210.14.") or ip.startswith("210.51.")
            or ip.startswith("210.78.") or ip.startswith("218.105.")):
        return 9929
    if _is_4538_ip(ip):
        return 4538
    if ip.startswith("2001:252:"):
        return 23911
    if (ip.startswith("2001:da8:") or ip.startswith("2001:250:")
            or ip.startswith("2402:f000:")):
        return 23910
    if ip.startswith("159.226."):
        return 7497
    return None


def _tq_normalize_hops(hops):
    """按 TQ 的方式归一化跳点：按 IP 去重（保留首次出现，TQ seen_ip），
    ASN 缺失时按 TQ infer_asn_from_ip 表从 IP 段推断。
    返回 (ips, asns)，asns 是字符串，"" 表示未知。"""
    ips = []
    asns = []
    seen = set()
    for ip, asn, _rtt, _geo in hops:
        if not ip or ip in seen:
            continue
        seen.add(ip)
        if asn is None:
            inferred = _infer_asn_from_ip(ip)
            asn_s = str(inferred) if inferred is not None else ""
        else:
            asn_s = str(asn)
        ips.append(ip)
        asns.append(asn_s)
    return ips, asns


def _tq_has_cn2_to_163(ips, asns, first, target):
    """TQ has_cn2_to_163(first)：从 first（0-based，第一跳 59.43 下标）
    往后找第一个 59.43.245.* 跳，看它后面第一个非 59.43.* 跳是不是 163。
    找不到 245.* 跳时返回 False（即 CN2GIA），不是数尾随 163 跳数。
    注意内层循环：跳过 59.43.* 跳后，对第一个非 59.43 跳直接返回判定，
    不继续往后找。"""
    n = len(ips)
    for h in range(first, n):
        if not ips[h].startswith("59.43.245."):
            continue
        for m in range(h + 1, n):
            if ips[m].startswith("59.43."):
                continue
            return (asns[m] in ("4134", "4847")
                    or _tq_is_163_ip(ips[m])
                    or (target == "电信"
                        and (_is_telecom_access_asn(asns[m])
                             or _is_telecom_access_ip(ips[m]))))
    return False


def _tq_mobile_label_before(ips, asns, last, target):
    """TQ mobile_label_before(last)：扫下标 [0, last)，last 是 first_unicom
    的 0-based 下标；last<=0 返回 ""。"""
    if last <= 0:
        return ""
    has_cmin2 = False
    has_cmi = False
    for h in range(last):
        if asns[h] == "58807":
            has_cmin2 = True
        if (asns[h] in ("58453", "9808") or _is_5604x(asns[h])
                or (target == "移动"
                    and (_is_mobile_access_asn(asns[h])
                         or _is_mobile_access_ip(ips[h])))):
            has_cmi = True
    if has_cmin2 and has_cmi:
        return "CMIN2->CMI"
    if has_cmin2:
        return "CMIN2"
    if has_cmi:
        return "CMI"
    return ""


def _tq_has_163_before(ips, asns, last):
    """TQ has_163_before(last)：扫下标 [0, last) 有没有 163 跳。"""
    if last <= 0:
        return False
    for h in range(last):
        if asns[h] in ("4134", "4847") or _tq_is_163_ip(ips[h]):
            return True
    return False


def _tq_unicom_domestic_label_from_hop(ips, asns, first):
    """TQ unicom_domestic_label_from_hop(first)：从下标 first（含）往后扫；
    遇到 9929 立即返回 "9929"；遇到 4837/4808/联通接入 ASN/219.158./2408:
    记 has_4837；扫完有 has_4837 返回 "4837"，否则 ""。"""
    has_4837 = False
    for h in range(first, len(ips)):
        if (asns[h] == "9929" or ips[h].startswith("210.14.")
                or ips[h].startswith("210.51.")
                or ips[h].startswith("210.78.")
                or ips[h].startswith("218.105.")):
            return "9929"
        if (asns[h] in ("4837", "4808")
                or _is_unicom_access_asn(asns[h])
                or ips[h].startswith("219.158.")
                or ips[h].startswith("2408:")):
            has_4837 = True
    return "4837" if has_4837 else ""


def _compact_combo_label(label):
    """TQ compact_combo_label：超过两段只保留首尾。"""
    parts = label.split("->")
    if len(parts) > 2:
        return parts[0] + "->" + parts[-1]
    return label


def _is_unicom_route_hop(asns, ips, h):
    """TQ is_unicom_route_hop(h)。"""
    return (_is_unicom_backbone_asn(asns[h])
            or _is_unicom_backbone_ip(ips[h])
            or _is_unicom_access_asn(asns[h]))


def _tq_unicom_route_combo_label(ips, asns, target):
    """TQ unicom_route_combo_label()。first_unicom 是 0-based 下标；
    没找到联通跳时按 TQ 的 ""（数值 0）处理：domestic 从下标 0 扫全程
    （此时必然为空，因为有联通跳早被上面的循环找到），mobile_transit
    与 has_163_before 都因 last<=0 返回空/False。"""
    n = len(ips)
    first_unicom = None
    for h in range(n):
        if _is_10099_hop(asns[h], ips[h]):
            domestic = _tq_unicom_domestic_label_from_hop(ips, asns, h + 1)
            if domestic:
                return "10099->" + domestic
            return "10099"
        if _is_unicom_route_hop(asns, ips, h):
            first_unicom = h
            break
    if first_unicom is None:
        return _tq_unicom_domestic_label_from_hop(ips, asns, 0)
    domestic = _tq_unicom_domestic_label_from_hop(ips, asns, first_unicom)
    mobile_transit = _tq_mobile_label_before(ips, asns, first_unicom, target)
    if target == "联通" and domestic and mobile_transit:
        return _compact_combo_label(mobile_transit + "->" + domestic)
    if (target == "联通" and domestic
            and _tq_has_163_before(ips, asns, first_unicom)):
        return "163->" + domestic
    return domestic


def _tq_is_mainland_backbone_hop(asn, ip, target):
    """TQ is_mainland_backbone_hop(asn, ip)。"""
    if _is_10099_hop(asn, ip):
        return True
    if asn in ("9929", "4837", "4808"):
        return True
    if asn == "4809":
        return not ip.startswith("2605:9d80:")
    if asn in ("4134", "4847"):
        return True
    if _tq_is_163_ip(ip):
        return True
    if target == "电信" and (_is_telecom_access_asn(asn)
                             or _is_telecom_access_ip(ip)):
        return True
    if asn == "23764" or _is_ctgnet_ip(ip):
        return not _is_ctgnet_ip(ip)
    if asn in ("58807", "58453", "9808"):
        return True
    if _is_5604x(asn):
        return True
    if target == "移动" and (_is_mobile_access_asn(asn)
                             or _is_mobile_access_ip(ip)):
        return True
    if asn in ("23911", "23910", "4538", "7497"):
        return True
    return False


def _tq_label_from_mainland_hop(ips, asns, hop, target):
    """TQ label_from_mainland_hop(hop, asn, ip)，hop 是 0-based 下标。"""
    asn = asns[hop]
    ip = ips[hop]
    if _is_10099_hop(asn, ip):
        return "10099"
    if asn == "9929":
        return "9929"
    if asn in ("4837", "4808"):
        return "4837"
    if asn in ("4134", "4847") or _tq_is_163_ip(ip):
        return "163"
    if target == "电信" and (_is_telecom_access_asn(asn)
                             or _is_telecom_access_ip(ip)):
        return "163"
    if asn == "23764" or _is_ctgnet_ip(ip):
        return ""
    if asn == "4809":
        if _tq_has_cn2_to_163(ips, asns, hop, target):
            return "CN2GT"
        for h in range(hop, len(ips)):
            if asns[h] == "23764" or _is_ctgnet_ip(ips[h]):
                return "CTGGIA"
        return "CN2GIA"
    if asn == "58807":
        return "CMIN2"
    if asn in ("58453", "9808") or _is_5604x(asn):
        return "CMI"
    if target == "移动" and (_is_mobile_access_asn(asn)
                             or _is_mobile_access_ip(ip)):
        return "CMI"
    if asn in ("23911", "23910"):
        return "CERNET2"
    if asn == "4538":
        return "CERNET"
    if asn == "7497":
        return "CSTNET"
    return ""


def _tq_is_target_isp_hop(asn, ip, target):
    """TQ is_target_isp_hop(asn, ip)。"""
    if target == "电信":
        return (_tq_is_163_ip(ip) or _is_telecom_access_asn(asn)
                or _is_telecom_access_ip(ip))
    if target == "联通":
        return (_is_unicom_backbone_asn(asn) or _is_unicom_backbone_ip(ip)
                or _is_unicom_access_asn(asn))
    if target == "移动":
        return (asn in ("58807", "58453", "9808") or _is_5604x(asn)
                or _is_mobile_access_asn(asn)
                or _is_mobile_access_ip(ip))
    return False


def _tq_visible_hops_match_target_isp(ips, asns, target):
    """TQ visible_hops_match_target_isp()：ASN 为 "" 或 749 的跳跳过。"""
    for i in range(len(ips)):
        if asns[i] in ("", "749"):
            continue
        if _tq_is_target_isp_hop(asns[i], ips[i], target):
            continue
        return False
    return True


def _tq_label_from_target_ip(ips, asns, target):
    """TQ label_from_target_ip()：目标 IP 用最后一跳 IP；
    全部可见跳须匹配目标运营商，否则返回 ""。"""
    if not ips:
        return ""
    if not _tq_visible_hops_match_target_isp(ips, asns, target):
        return ""
    dest_ip = ips[-1]
    dest_asn = asns[-1]
    if target == "电信" and (_tq_is_163_ip(dest_ip)
                             or _is_telecom_access_asn(dest_asn)
                             or _is_telecom_access_ip(dest_ip)):
        return "163"
    if target == "联通" and (_is_unicom_backbone_asn(dest_asn)
                             or _is_unicom_backbone_ip(dest_ip)
                             or _is_unicom_access_asn(dest_asn)):
        return _tq_unicom_route_combo_label(ips, asns, target)
    if target == "移动" and dest_asn == "58807":
        return "CMIN2"
    if target == "移动" and (dest_asn in ("58453", "9808")
                             or _is_5604x(dest_asn)
                             or _is_mobile_access_asn(dest_asn)
                             or _is_mobile_access_ip(dest_ip)):
        return "CMI"
    return ""


def classify_carrier(carrier, hops):
    """按 TQ (TcpQuality runTcpQuality-core.sh route_label_from_ip_trace /
    classify()) 规则分类，与 TQ 逐条对齐（2026-11-13 用户定：三网回程
    线路判定方式与 TQ 保持一致）。

    优先级（TQ classify 顺序）：
      1. 有 59.43.* → CN2；59.43.245.* 后面直接接 163 才 CN2GT，
         否则 CN2GIA（找不到 245.* 跳时也是 CN2GIA，不是数尾随 163 跳数）；
         有 CTGNET（AS23764）时是 CTGGIA。
      2. 联通组合：经过联通骨干（9929/4837/4808/10099）时标联通的网，
         与目标运营商无关（电信回程借道 9929/4837 也标 9929/4837）。
      3. 有 AS58807 → CMIN2。
      4. 按跳顺序取第一个大陆骨干跳的标签。
      5. 兜底：按 ASN 是否出现依次查 CERNET2/9929/4837/163/CMI/
         CTGGIA/CERNET/CSTNET。
      6. 目标 IP：全部可见跳都匹配目标运营商时按目标 IP 的 ASN 推标签。
      都不中返回 None（TQ 的 "Hidden"，面板写 "未识别"）。
    ASN 缺失时按 TQ infer_asn_from_ip 表从 IP 段推断。
    注意：AS4808 在 TQ 里与 AS4837 归并为 "4837"，不再单独写 "4808"
    （"4808" 仍保留在 ROUTE_LABELS/PRIORITY 里兼容旧标签）。
    """
    ips, asns = _tq_normalize_hops(hops)
    if not ips:
        return None
    target = CARRIER_NAMES[carrier]
    # 1. 扫全部跳：has_cn2 / first_cn2 / has_ctgnet（TQ 只看 IP 前缀
    #    59.43.，不看 ASN 4809）
    has_cn2 = False
    first_cn2 = None
    has_ctgnet = False
    for i, (ip, asn) in enumerate(zip(ips, asns)):
        if asn == "23764" or _is_ctgnet_ip(ip):
            has_ctgnet = True
        if ip.startswith("59.43."):
            has_cn2 = True
            if first_cn2 is None:
                first_cn2 = i
    # 2. CN2
    if has_cn2:
        if _tq_has_cn2_to_163(ips, asns, first_cn2, target):
            return "CN2GT"
        if has_ctgnet:
            return "CTGGIA"
        return "CN2GIA"
    # 3. 联通组合
    label = _tq_unicom_route_combo_label(ips, asns, target)
    if label:
        return label
    # 4. CMIN2
    if "58807" in asns:
        return "CMIN2"
    # 5. 第一个大陆骨干跳
    for i, (ip, asn) in enumerate(zip(ips, asns)):
        if not _tq_is_mainland_backbone_hop(asn, ip, target):
            continue
        label = _tq_label_from_mainland_hop(ips, asns, i, target)
        if label:
            return label
    # 6. 兜底（按 ASN 是否出现）
    asn_set = set(asns)
    if "23911" in asn_set:
        return "CERNET2"
    if "9929" in asn_set:
        return "9929"
    if "4837" in asn_set or "4808" in asn_set:
        return "4837"
    if "4847" in asn_set:
        return "163"
    if asn_set & {"58453", "9808", "56040", "56041", "56042", "56044",
                  "56045", "56046", "56047", "56048"}:
        return "CMI"
    if has_ctgnet or "23764" in asn_set:
        return "CTGGIA"
    if "23910" in asn_set:
        return "CERNET2"
    if "4538" in asn_set:
        return "CERNET"
    if "7497" in asn_set:
        return "CSTNET"
    # 7. 目标 IP
    label = _tq_label_from_target_ip(ips, asns, target)
    if label:
        return label
    return None


def _label_priority(label):
    """线路标签的优先级（取最好线路用）：组合标签取各段最高者；
    未知标签按 1 计，避免 PRIORITY 查不到抛 KeyError 导致整轮探测失败。"""
    if label in PRIORITY:
        return PRIORITY[label]
    parts = label.split("->")
    if len(parts) > 1:
        return max(PRIORITY.get(p, 1) for p in parts)
    return 1


def _is_163_ip(ip):
    """电信 163 骨干常见段（逐跳显示 classify_hop 用，保持现状；
    含 218.30.，与 TQ 分类的 _tq_is_163_ip 区分开）。"""
    return ip.startswith("202.97.") or ip.startswith("218.30.")


def classify_hop(ip, asn):
    """给单跳打线路徽标（用于历史详情表格每跳的线路列）。

    59.43.* → CN2；AS4134/AS4847 或 202.97.* → 163；
    AS9929 → 9929；AS4837 → 4837；AS4808 → 4808；AS10099 → 10099；
    AS58807 → CMIN2；AS58453/AS9808/AS56040-48 → CMI；
    AS9808 → CMNET（移动骨干，无 CMI 特征时）；RFC1918 → 内网；
    其余 → None（不打标）。
    ASN 缺失时先按 TQ infer 表从 IP 段推断（例如联通国际 CUG
    43.255.170.77、162.219.85.5 → AS10099），推断不出且是内网 IP
    才标“内网”，否则不打标。
    """
    if ip.startswith("59.43."):
        return "CN2"
    if asn is None:
        asn = _infer_asn_from_ip(ip)
        if asn is None:
            if ip.startswith(("10.", "172.16.", "172.17.", "172.18.",
                              "172.19.", "172.2", "172.30.", "172.31.",
                              "192.168.")):
                return "内网"
            return None
    if asn == 4809:
        return "CN2"
    if asn in (4134, 4847) or _is_163_ip(ip):
        return "163"
    if asn == 9929:
        return "9929"
    if asn == 4837:
        return "4837"
    if asn == 4808:
        return "4808"
    if asn == 10099:
        return "10099"
    if asn == 58807:
        return "CMIN2"
    if asn == 58453 or 56040 <= asn <= 56048:
        return "CMI"
    if asn == 9808:
        return "CMNET"
    if asn == 23764:
        return "Tata"
    return None


def _resolve_v6_targets(target):
    """把一个 v6 目标解析成字面 IPv6 地址列表：字面 IP 直接用；
    域名用原始 getaddrinfo 查 AAAA（模块顶上把 socket.getaddrinfo
    替换成了只走 IPv4 的版本，这里必须用保存的原始函数）。"""
    try:
        socket.inet_pton(socket.AF_INET6, target)
        return [target]
    except Exception:
        pass
    try:
        infos = _orig_getaddrinfo(target, 80, socket.AF_INET6,
                                  socket.SOCK_STREAM)
    except Exception:
        return []
    return list({info[4][0] for info in infos})


def has_ipv6_egress(targets_v6, timeout=3):
    """本机有没有 IPv6 出口：对每个 v6 目标 TCP 连 80 端口，任一通即有。
    全不通（无 v6 出口，或目标 IP 已失效）返回 False，调用方跳过
    v6 探测、只出 v4 数据。单个目标最多等 timeout 秒。"""
    for target in targets_v6.values():
        for ip in _resolve_v6_targets(target):
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect((ip, 80, 0, 0))
                return True
            except Exception:
                continue
            finally:
                s.close()
    return False


def detect_route(targets, tool, ipv6=False):
    """跑三次探测，返回 (最好线路, {运营商: 线路或None}, {运营商: hops})。

    hops 是每跳的 (IP, ASN) 列表，供历史记录用。
    ipv6=True 时测 IPv6 三网（目标是 v6 字面 IP，run_trace 用 --ipv6/-6）。
    三个运营商都没识别出时返回 (None, ..., ...)，由调用方决定不写标签退出。
    """
    fam = "IPv6" if ipv6 else "IPv4"
    per_carrier = {}
    hops_by_carrier = {}
    for carrier in ("ct", "cu", "cm"):
        target = targets[carrier]
        log(f"探测{CARRIER_NAMES[carrier]}回程 [{fam}]：{target}")
        try:
            output = run_trace(target, tool, ipv6=ipv6)
        except Exception as e:
            log(f"{CARRIER_NAMES[carrier]}[{fam}]探测失败：{e}")
            per_carrier[carrier] = None
            hops_by_carrier[carrier] = []
            continue
        hops = parse_trace_output(output)
        hops_by_carrier[carrier] = hops
        label = classify_carrier(carrier, hops)
        per_carrier[carrier] = label
        log(f"{CARRIER_NAMES[carrier]}[{fam}]：{len(hops)} 跳，"
            f"识别结果={label or '未识别'}")
        # NextTrace API 有速率限制（pow token），三条连着跑第三条容易
        # 拿不到 ASN；每条之间停 10 秒错开。
        if carrier != "cm":
            time.sleep(10)
    found = [v for v in per_carrier.values() if v]
    if not found:
        return None, per_carrier, hops_by_carrier
    best = max(found, key=_label_priority)
    return best, per_carrier, hops_by_carrier


ROUTE_LABELS = {"CN2GIA", "CN2GT", "9929", "CMIN2", "CMI", "CMNET", "163", "4837", "4808", "未识别", "10099", "CTGGIA", "CERNET2", "CERNET", "CSTNET", "10099->9929", "10099->4837", "CMIN2->9929", "CMIN2->4837", "CMI->9929", "CMI->4837", "163->9929", "163->4837", "CMIN2->CMI"}


def _is_route_label(tag):
    """是不是线路标签：新值（ROUTE_LABELS）或旧值 "?"（兼容读旧标签，
    旧 "?" 标签仍能被 split_auto_tags 认出来，写出时一律用新值）。
    面板保存 tags 时会删掉 ">"，组合标签读回时是 "-" 形（如
    "10099-9929"），也认。"""
    if tag in ROUTE_LABELS or tag == "?":
        return True
    return tag.replace("-", "->") in ROUTE_LABELS


def format_routes_tag(per_carrier):
    """三网识别结果写成一个线路标签（左气泡）。

    三条是各自独立的回程，不能只取最好的一条（最好那条不代表
    另外两网也走它）。三网回程全一样时只填一个（如 "CN2GT"）；
    否则三条都写出来、空格隔开、放在一个气泡里
    （如 "163 163 CMIN2"、"CN2GIA 9929 CMIN2"）。
    未识别的运营商用 "未识别" 占位（"?" 在面板上显示不出来，不再用）。
    """
    values = [per_carrier.get(c) or "未识别" for c in ("ct", "cu", "cm")]
    if values[0] == values[1] == values[2]:
        return values[0]
    return " ".join(values)


def _is_single_route(tag):
    return _is_route_label(tag)


def _is_combined_route(tag):
    """线路标签（单枚）：三网拼在一个标签里，如 "163 163 CMIN2"
    或 "电信163 联通163 移动CMIN2"；三网全一样时只有单个值，如 "CN2GT"。"""
    parts = tag.split()
    if not parts:
        return False
    stripped = [p.replace("电信", "").replace("联通", "").replace("移动", "")
                for p in parts]
    if len(stripped) == 1:
        return _is_route_label(stripped[0])
    return all(_is_route_label(p) for p in stripped) and len(stripped) == 3


def _is_v6_route_tag(tag):
    """是不是 v6 自动线路标签：前缀 + 一个三网线路标签，
    如 "v6:163 163 CMI"、"v6 163 163 CMI"、"v6CN2GT"。
    面板保存 tags 时按 [^\\p{L}\\p{N} ._-] 清洗、删掉冒号，所以
    脚本写出时用 "v6 "（空格）前缀；面板已存坏的 "v6..."（冒号被删
    且无空格，如 "v6163 163-4837 163"）也认，用于清理，不再产出。
    手动备注里不要用 "v6" 开头，否则会被当成自动标签换掉。"""
    if not isinstance(tag, str):
        return False
    if tag.startswith("v6:") or tag.startswith("v6 "):
        return _is_combined_route(tag[3:])
    if tag.startswith("v6") and len(tag) > 2:
        # 面板清洗后残留的坏形态：冒号被删且无空格，如 "v6163 ..."
        return _is_combined_route(tag[2:])
    return False


_PANEL_TAG_KEEP_RE = re.compile(r"[^\w .\-]", re.UNICODE)


def _panel_stored_form(tag):
    """模拟面板保存 tags 时的清洗：面板只保留字母、数字、空格、点、
    下划线、连字符，其余字符（如冒号、">"）删掉。
    用于判断读回的 tags 是否已是写出形态的面板存版：写出 "163->4837"
    会被存成 "163-4837"，写出 "v6 163 ..." 会原样存成 "v6 163 ..."，
    而残留的坏形态 "v6163 ..." 模拟后仍与写出形态的面板存版不同，
    会写回一次修复，之后不再写回。"""
    return _PANEL_TAG_KEEP_RE.sub("", tag)


def split_auto_tags(old_tags):
    """把现有的 tags 切成（自动线路标签数，手动备注标签列表）。

    自动部分可能是 1 个线路标签（"CN2GT" 或 "163 163 CMIN2"），
    或上一版的 3 个独立标签（"163","163","CMIN2"）；
    有 IPv6 数据时后面再跟 1 个 v6 标签（"v6 163 163 CMI"，写出用
    "v6 " 空格前缀；读回时 "v6:" 与面板清洗残留的 "v6..." 坏形态也认），
    自动数 = 1 + 有无 v6 标签（旧版 3 标签形态同理，最多 4 个）；
    其余一律当手动备注保留，脚本绝不碰。
    先判 3 个独立标签，再判 1 个线路标签（单个 "163" 两种都像）。
    v6 标签只认第二位（或旧版第四位），第一位是 "v6:..." 时不当
    自动标签（v4 标签永远在第一位，那种属于损坏状态，保守保留）。
    """
    if not old_tags:
        return 0, []
    if len(old_tags) >= 3 and all(_is_single_route(t)
                                  for t in old_tags[:3]):
        if len(old_tags) >= 4 and _is_v6_route_tag(old_tags[3]):
            return 4, old_tags[4:]
        return 3, old_tags[3:]
    if _is_combined_route(old_tags[0]):
        if len(old_tags) >= 2 and _is_v6_route_tag(old_tags[1]):
            return 2, old_tags[2:]
        return 1, old_tags[1:]
    return 0, old_tags


# ---------------------------------------------------------------- 历史存储

HISTORY_KEEP_HOURS = 168  # 历史留 7 天（2026-11-12 用户定，和延迟/丢包历史一致）


def history_path(cfg):
    """历史文件路径：配置文件同目录下的 history.json。"""
    config_path = Path(cfg.get("_config_path", DEFAULT_CONFIG_PATH))
    return config_path.parent / "history.json"


PENDING_KEEP_SECONDS = 600  # 干跑结果复用有效期 10 分钟


def pending_path(cfg):
    """干跑待写文件路径：配置文件同目录下的 pending.json。"""
    config_path = Path(cfg.get("_config_path", DEFAULT_CONFIG_PATH))
    return config_path.parent / "pending.json"


def save_pending(cfg, per_carrier, hops_by_carrier, routes_tag,
                 per_carrier_v6=None, hops_by_carrier_v6=None,
                 routes_tag_v6=None):
    """干跑把完整探测结果存下来，供紧接着的正式跑直接复用（只探测一次）。

    存 {timestamp, per_carrier, hops_by_carrier, routes_tag,
    per_carrier_v6, hops_by_carrier_v6, routes_tag_v6}；
    正式跑 10 分钟内读到就不再探测。保存失败只记警告，不影响干跑返回。
    """
    path = pending_path(cfg)
    data = {
        "timestamp": int(time.time()),
        "per_carrier": per_carrier,
        "hops_by_carrier": hops_by_carrier,
        "routes_tag": routes_tag,
        "per_carrier_v6": per_carrier_v6,
        "hops_by_carrier_v6": hops_by_carrier_v6,
        "routes_tag_v6": routes_tag_v6,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False),
                        encoding="utf-8")
    except Exception as e:
        log(f"警告：干跑结果保存失败 {path}：{e}")


def load_pending(cfg):
    """读干跑存的结果；不存在、损坏、过期（>10 分钟）或没有识别出线路时
    返回 None（调用方正常探测）。返回 dict 或 None。"""
    path = pending_path(cfg)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    ts = data.get("timestamp")
    per_carrier = data.get("per_carrier")
    hops_by_carrier = data.get("hops_by_carrier")
    routes_tag = data.get("routes_tag")
    if not isinstance(ts, (int, float)):
        return None
    if time.time() - ts > PENDING_KEEP_SECONDS:
        return None
    if not isinstance(per_carrier, dict) or not isinstance(hops_by_carrier, dict):
        return None
    if not isinstance(routes_tag, str) or not routes_tag:
        return None
    if not any(per_carrier.get(c) for c in ("ct", "cu", "cm")):
        return None
    # v6 字段是可选的：旧版 pending 文件里没有，读到 None 即无 v6 数据；
    # 损坏的 v6 字段同样按无 v6 数据处理，不影响 v4 复用。
    per_carrier_v6 = data.get("per_carrier_v6")
    hops_by_carrier_v6 = data.get("hops_by_carrier_v6")
    routes_tag_v6 = data.get("routes_tag_v6")
    if not isinstance(per_carrier_v6, dict):
        per_carrier_v6 = None
    if not isinstance(hops_by_carrier_v6, dict):
        hops_by_carrier_v6 = None
    if not isinstance(routes_tag_v6, str) or not routes_tag_v6:
        routes_tag_v6 = None
    return {"per_carrier": per_carrier,
            "hops_by_carrier": hops_by_carrier,
            "routes_tag": routes_tag,
            "per_carrier_v6": per_carrier_v6,
            "hops_by_carrier_v6": hops_by_carrier_v6,
            "routes_tag_v6": routes_tag_v6}


def _parse_as_field(as_field):
    """解析 ip-api 的 `as` 字段（形如 "AS402898 VpsQuan L.L.C."），
    返回 (asn: int|None, org: str|None)。
    组织名是去掉开头 "AS<number>" 后剩下的部分，strip 为空则为 None；
    字段为空或格式不对时两个都为 None。"""
    as_field = as_field or ""
    m = re.search(r"AS(\d+)", as_field)
    asn = int(m.group(1)) if m else None
    org_m = re.match(r"AS\d+\s*(.*)", as_field)
    org = org_m.group(1).strip() if org_m else None
    return asn, (org or None)


def _get_local_ipv6():
    """从本机路由表取出口 IPv6（ip -6 route get，解析 src 字段）。

    v6 机器的公网 IPv6 配在网卡上，读本地路由表不依赖外部接口，
    到处都一样；是私网地址（ULA/链路本地/回环）或拿不到返回 None。
    """
    try:
        out = subprocess.run(
            ["ip", "-6", "route", "get", "2001:4860:4860::8888"],
            capture_output=True, text=True, timeout=10,
        ).stdout
        m = re.search(r"\bsrc\s+([0-9a-fA-F:]+)", out)
        if not m:
            return None
        ip = m.group(1)
        # 私网地址不要（ULA fc00::/7、链路本地 fe80::/10、回环 ::1）
        lower = ip.lower()
        if lower == "::1":
            return None
        first = next((p for p in lower.split(":") if p), None)
        if not first:
            return None
        first_val = int(first, 16)
        if (0xfc00 <= first_val <= 0xfdff) or (0xfe80 <= first_val <= 0xfebf):
            return None
        return ip
    except Exception:
        pass
    return None


def get_source_info(ip_version="v4"):
    """取本机公网 IP、ASN、组织名、地理位置（供历史记录首行“本机”用）。

    v4：IP 用 api.ipify.org（失败回退 ifconfig.me）；
    v6：IP 优先读本地路由表（ip -6 route get 的 src），拿不到再用
    api6.ipify.org（仅 IPv6 可达，失败回退 api64.ipify.org）。
    ASN/组织名/地理用 ip-api.com 免费接口，`as` 字段形如 "AS402898 VpsQuan L.L.C."，
    ASN 取数字，组织名取去掉开头 "AS<number>" 后剩下的部分（strip 为空则为 None）。
    任一步失败对应字段为 None，不影响主流程。
    返回 {"ip": str|None, "asn": int|None, "org": str|None, "geo": str|None}。
    """
    ip = None
    if ip_version == "v6":
        ip = _get_local_ipv6()
    if ip is None:
        if ip_version == "v6":
            urls = ("https://api6.ipify.org", "https://api64.ipify.org")
            pattern = re.compile(r"^[0-9a-fA-F:]+$")
        else:
            urls = ("https://api.ipify.org", "https://ifconfig.me")
            pattern = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": BROWSER_UA})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    candidate = resp.read().decode("utf-8", errors="ignore").strip()
                if ip_version == "v6":
                    if ":" in candidate and pattern.match(candidate):
                        ip = candidate
                        break
                elif pattern.match(candidate):
                    ip = candidate
                    break
            except Exception:
                continue
    if not ip:
        return {"ip": None, "asn": None, "org": None, "geo": None}
    asn = None
    org = None
    geo = None
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=status,as,country,regionName,city&lang=zh-CN",
            headers={"User-Agent": BROWSER_UA})
        with urllib.request.urlopen(req, timeout=10) as resp:
            info = json.loads(resp.read().decode("utf-8", errors="ignore"))
        if info.get("status") == "success":
            asn, org = _parse_as_field(info.get("as") or "")
            parts = [info.get("country") or "",
                     info.get("regionName") or "",
                     info.get("city") or ""]
            geo = " ".join(p for p in parts if p) or None
    except Exception:
        pass
    return {"ip": ip, "asn": asn, "org": org, "geo": geo}


def save_history(cfg, per_carrier, hops_by_carrier, routes_tag,
                 ip_version="v4"):
    """把本次探测结果追加进历史文件（带时间戳，留 7 天）。

    每条记录带 "ip_version"（"v4" 或 "v6"）；v4 每轮必存一条，
    v6 仅在 v6 探测成功时存一条；没有该字段的旧记录按 v4 处理
    （约定在主题侧）。
    每条记录：{ts, ts_unix, ip_version, routes_tag,
    carriers: {ct: {label, hops: [[ip, asn, rtt_ms, geo], ...]},
    cu: {...}, cm: {...}, _source: {ip, asn, org, geo}（本机信息，
    v4 记录写 v4 公网 IP、v6 记录写 v6 公网 IP，有 IP 时才写）}}。
    hops 只存有 IP 的跳（已去重连续重复）。
    返回本次记录（含 Unix 时间戳 ts_unix），供推送到 Worker 用。
    """
    path = history_path(cfg)
    try:
        records = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(records, list):
            records = []
    except Exception:
        records = []
    now = datetime.now(TZ)
    record = {
        "ts": now.strftime("%Y-%m-%d %H:%M:%S"),
        "ts_unix": int(now.timestamp()),
        "ip_version": ip_version,
        "routes_tag": routes_tag,
        "carriers": {},
    }
    for carrier in ("ct", "cu", "cm"):
        hops = hops_by_carrier.get(carrier) or []
        # 去掉连续重复的 IP（NextTrace 有时会把同一跳打两遍）
        deduped = []
        for hop in hops:
            if not deduped or deduped[-1] != hop:
                deduped.append(hop)
        record["carriers"][carrier] = {
            "label": per_carrier.get(carrier),
            "hops": [[ip, asn, rtt, geo] for ip, asn, rtt, geo in deduped],
        }
    # 本机信息（供面板历史首行“本机”用，游客看不到，由 Worker 过滤）；
    # v4 写 v4 公网 IP，v6 写 v6 公网 IP；拿不到 IP 时不写 _source。
    source = get_source_info(ip_version)
    if source.get("ip"):
        record["carriers"]["_source"] = source
    records.append(record)
    # 只留 7 天
    cutoff = now.timestamp() - HISTORY_KEEP_HOURS * 3600
    kept = []
    for r in records:
        try:
            ts = datetime.strptime(r["ts"], "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=TZ).timestamp()
        except Exception:
            continue
        if ts >= cutoff:
            kept.append(r)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(kept, ensure_ascii=False, indent=1),
                        encoding="utf-8")
        log(f"历史已保存：{path}（共 {len(kept)} 条，留 {HISTORY_KEEP_HOURS} 小时）")
    except Exception as e:
        log(f"警告：历史保存失败 {path}：{e}")
    return record


# ---------------------------------------------------------------- 面板 API

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/126.0 Safari/537.36")


def api_post(api_url, body, token=None):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(api_url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    # 面板在 Cloudflare 后面，urllib 默认 UA（Python-urllib/x.y）会被
    # Cloudflare 以 error 1010 拦截（HTTP 403），必须用浏览器 UA。
    req.add_header("User-Agent", BROWSER_UA)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="ignore")[:300]
        raise RuntimeError(f"HTTP {e.code}：{detail or e.reason}")


class PanelClient:
    def __init__(self, panel_url):
        self.api_url = panel_url.rstrip("/") + "/admin/api"

    def login(self, username, password):
        try:
            r = api_post(self.api_url, {"action": "login",
                                        "username": username,
                                        "password": password})
        except RuntimeError as e:
            if "HTTP 403" in str(e):
                raise RuntimeError(
                    "登录被拒（HTTP 403），可能是面板开了登录 Turnstile 验证"
                    "（脚本带不了验证 token），或是 Cloudflare 拦截了请求，"
                    "请检查面板登录设置或先在浏览器里确认")
            raise RuntimeError(f"登录请求失败：{e}")
        if not r.get("success") or not r.get("token"):
            raise RuntimeError(f"登录失败：{r.get('message') or r}")
        return r["token"]

    def list_servers(self, token):
        r = api_post(self.api_url, {"action": "list"}, token)
        if isinstance(r, list):
            return r
        for key in ("servers", "data", "list"):
            if isinstance(r.get(key), list):
                return r[key]
        raise RuntimeError(f"list 返回格式无法解析：{str(r)[:300]}")

    def edit_server(self, token, server):
        r = api_post(self.api_url, dict(server, action="edit"), token)
        if isinstance(r, dict) and r.get("success") is False:
            raise RuntimeError(f"edit 失败：{r.get('message') or r}")
        return r

    def push_route_history(self, panel_url, token, server_id, record):
        """把本次探测记录推给 Worker 的 /api/route-history（供面板历史卡片读）。

        Worker 未部署此接口时会 404，调用方应只记警告、不因此失败。
        """
        url = panel_url.rstrip("/") + "/api/route-history"
        body = {
            "server_id": server_id,
            "timestamp": record["ts_unix"],
            "ip_version": record.get("ip_version", "v4"),
            "routes_tag": record["routes_tag"],
            "carriers": record["carriers"],
        }
        r = api_post(url, body, token)
        if isinstance(r, dict) and r.get("success") is False:
            raise RuntimeError(f"route-history 推送失败：{r.get('message') or r}")
        return r


# ---------------------------------------------------------------- 标签处理

def split_tags(raw):
    """tags 可能是逗号分隔字符串或列表，统一切成列表。"""
    if raw is None:
        return []
    if isinstance(raw, list):
        parts = [str(x) for x in raw]
    else:
        parts = str(raw).split(",")
    return [p.strip() for p in parts if p.strip()]


def join_tags(parts):
    return ",".join(parts)


# ---------------------------------------------------------------- 主流程

def main(argv=None):
    ap = argparse.ArgumentParser(description="探测本机三网回程线路并更新面板标签")
    ap.add_argument("--dry-run", action="store_true",
                    help="只探测并打印会把标签改成什么，不登录面板、不调用 edit")
    ap.add_argument("--config", default=None,
                    help="配置文件路径（默认 ~/.config/route-detect/config.json，"
                         "也可用环境变量 ROUTE_DETECT_CONFIG 覆盖）")
    args = ap.parse_args(argv)

    config_path = Path(args.config or os.environ.get(ENV_CONFIG_PATH, "")
                       or DEFAULT_CONFIG_PATH).expanduser()
    try:
        cfg = load_config(config_path, args.dry_run)
        if not args.dry_run:
            check_required_config(cfg)
    except ValueError as e:
        return fail(str(e), 2)
    cfg["_config_path"] = str(config_path)

    # 1. 探测 v4（正式跑时若有 10 分钟内的干跑结果，直接复用，不再探测；
    #    cron 每小时跑的正式跑没有 pending 时正常探测，不受影响）
    pending = None
    if not args.dry_run:
        pending = load_pending(cfg)
    per_carrier_v6 = None
    hops_by_carrier_v6 = None
    routes_tag_v6 = None
    if pending is not None:
        per_carrier = pending["per_carrier"]
        hops_by_carrier = pending["hops_by_carrier"]
        routes_tag = pending["routes_tag"]
        per_carrier_v6 = pending.get("per_carrier_v6")
        hops_by_carrier_v6 = pending.get("hops_by_carrier_v6")
        routes_tag_v6 = pending.get("routes_tag_v6")
        found = [v for v in per_carrier.values() if v]
        _best = max(found, key=_label_priority) if found else None
        log("复用干跑结果（10 分钟内），不再探测")
    else:
        try:
            tool = find_trace_tool()
        except RuntimeError as e:
            return fail(str(e), 1)
        log(f"探测工具：{tool}")
        try:
            _best, per_carrier, hops_by_carrier = detect_route(cfg["targets"], tool)
        except Exception as e:
            return fail(f"探测异常：{e}", 1)
    if _best is None:
        log("三个运营商都没识别出线路，不写标签，直接退出"
            f"（各运营商结果：{per_carrier}）")
        return 3
    # 左气泡写三网各自的回程，不取最好的一条（最好那条不代表
    # 另外两网也走它）。三网全一样只填一个，否则三条都写、空格隔开、
    # 放在一个气泡里。右气泡是用户手打备注，脚本不动。
    if pending is None:
        routes_tag = format_routes_tag(per_carrier)
    log(f"三网识别结果：{per_carrier}，线路标签写成：{routes_tag}")
    # 1b. 同轮探测 IPv6 三网（无 v6 出口时跳过，只出 v4 数据；
    #     v6 三网都没识别出时本轮也不出 v6 数据，均不影响 v4）。
    if pending is None:
        if has_ipv6_egress(cfg["targets_v6"]):
            try:
                _best6, per_carrier_v6, hops_by_carrier_v6 = detect_route(
                    cfg["targets_v6"], tool, ipv6=True)
            except Exception as e:
                log(f"IPv6 探测异常：{e}")
                per_carrier_v6, hops_by_carrier_v6 = None, None
            if per_carrier_v6 and any(per_carrier_v6.values()):
                routes_tag_v6 = format_routes_tag(per_carrier_v6)
                log(f"三网 IPv6 识别结果：{per_carrier_v6}，"
                    f"线路标签写成：v6 {routes_tag_v6}")
            else:
                per_carrier_v6, hops_by_carrier_v6, routes_tag_v6 = None, None, None
                log("IPv6 三网都没识别出线路，本轮只出 v4 数据")
        else:
            log("无 IPv6 出口，跳过 IPv6 探测，本轮只出 v4 数据")
    elif routes_tag_v6:
        log(f"复用干跑 IPv6 结果：{per_carrier_v6}，线路标签：v6 {routes_tag_v6}")
    # 历史：v4 每轮必存一条；v6 仅在探测成功时存一条（各带 ip_version），
    # 供面板线路历史用
    record = save_history(cfg, per_carrier, hops_by_carrier, routes_tag)
    record_v6 = None
    if per_carrier_v6 and any(per_carrier_v6.values()):
        if not routes_tag_v6:
            routes_tag_v6 = format_routes_tag(per_carrier_v6)
        record_v6 = save_history(cfg, per_carrier_v6, hops_by_carrier_v6,
                                 routes_tag_v6, ip_version="v6")

    if args.dry_run:
        save_pending(cfg, per_carrier, hops_by_carrier, routes_tag,
                     per_carrier_v6, hops_by_carrier_v6, routes_tag_v6)
        v6_note = (f" + 「v6 {routes_tag_v6}」" if routes_tag_v6
                   else "（无 IPv6 数据）")
        log(f"dry-run：会把线路标签改成「{routes_tag}」{v6_note}，"
            f"后面的手动标签原样保留（本次不登录、不调用 edit）")
        return 0

    # 2. 登录面板并读全量服务器
    client = PanelClient(cfg["panel_url"])
    try:
        token = client.login(cfg["admin_username"], cfg["admin_password"])
        log("面板登录成功")
        servers = client.list_servers(token)
    except Exception as e:
        return fail(str(e), 1)

    server = None
    for s in servers:
        if isinstance(s, dict) and str(s.get("id")) == str(cfg["server_id"]):
            server = s
            break
    if server is None:
        return fail(f"面板 list 里找不到 server_id={cfg['server_id']} 的服务器，"
                    f"请检查配置（server_id 在面板后台服务器列表里看），"
                    f"本次共读到 {len(servers)} 台", 1)

    # 3. 比较并按需写回（只改线路标签，手动备注原样保留）
    # 新 tags = [v4 线路标签] + (["v6 " + v6 线路标签] 若本轮有 v6 数据)
    # + 手动备注；v4 与 v6 两项一起比较，任一变了才写回。
    # v6 前缀用空格不用冒号：面板保存时会删掉冒号，"v6:" 写出会被存成
    # "v6..."（主题与下轮读回都认不出），"v6 " 的空格面板会保留。
    old_tags = split_tags(server.get("tags"))
    _auto_n, manual_tags = split_auto_tags(old_tags)
    new_tags = [routes_tag]
    if routes_tag_v6:
        new_tags.append("v6 " + routes_tag_v6)
    new_tags += manual_tags
    # 历史推送：标签变没变都推（跳数可能变了、标签没变），Worker 没部署
    # 此接口时只记警告、不失败（标签写回才是主业）。
    # v4 每轮必推；v6 仅在探测成功时推一条。
    try:
        client.push_route_history(cfg["panel_url"], token,
                                  cfg["server_id"], record)
        log("历史已推送到 Worker（/api/route-history）")
    except Exception as e:
        log(f"警告：历史推送失败（Worker 可能还没部署此接口）：{e}")
    if record_v6 is not None:
        try:
            client.push_route_history(cfg["panel_url"], token,
                                      cfg["server_id"], record_v6)
            log("IPv6 历史已推送到 Worker（/api/route-history）")
        except Exception as e:
            log(f"警告：IPv6 历史推送失败（Worker 可能还没部署此接口）：{e}")
    # 比较时模拟面板清洗：面板会把 "->" 存成 "-"，不模拟会每次都误判
    # 为变化、无意义写回；残留的坏形态（如 "v6..."）模拟后与写出形态
    # 的面板存版仍不同，会写回一次修复，之后不再写回。
    # 手动备注原样比（新旧同一份）。
    new_auto_n = 1 + (1 if routes_tag_v6 else 0)
    old_stored = [_panel_stored_form(t) for t in old_tags[:_auto_n]]
    new_stored = [_panel_stored_form(t) for t in new_tags[:new_auto_n]]
    if old_stored == new_stored and new_tags[new_auto_n:] == old_tags[_auto_n:]:
        log(f"线路未变（当前线路标签已是「{routes_tag}」），不写回")
        return 0
    new_server = dict(server)
    new_server["tags"] = join_tags(new_tags)
    log(f"标签变化：{join_tags(old_tags) or '(无标签)'} → {join_tags(new_tags)}，"
        f"调用 edit 全量回写")
    try:
        client.edit_server(token, new_server)
    except Exception as e:
        return fail(str(e), 1)
    log(f"写回成功：server_id={cfg['server_id']}，tags 已改为 "
        f"「{join_tags(new_tags)}」")
    return 0


if __name__ == "__main__":
    sys.exit(main())
ROUTE_DETECT_PY
chmod +x "${INSTALL_DIR}/route_detect.py"

# 3-4. 配置：优先级：环境变量 > 已有配置文件 > 交互输入
#    环境变量：ROUTE_DETECT_SERVER_ID（机器 UUID）、ROUTE_DETECT_SERVER_NUMBER（列表序号）、ROUTE_DETECT_ADMIN_PASSWORD（面板密码）
#    传了环境变量就用它并更新配置；没传且已有配置就复用；都没有才问。
#    （面板不返回机器公网 IP，所以序号无法自动识别，只能传参或手动选。）
ENV_SID="${ROUTE_DETECT_SERVER_ID:-}"
ENV_SNUM="${ROUTE_DETECT_SERVER_NUMBER:-}"
ENV_PASS="${ROUTE_DETECT_ADMIN_PASSWORD:-}"

# 先读已有配置（有的话）
EXISTING_SID=""
EXISTING_PASS=""
if [ -f "${CONFIG_FILE}" ]; then
  EXISTING_SID="$(python3 -c "import json,sys; c=json.load(open(sys.argv[1],encoding='utf-8')); print(c.get('server_id') or '')" "${CONFIG_FILE}" 2>/dev/null || true)"
  EXISTING_PASS="$(python3 -c "import json,sys; c=json.load(open(sys.argv[1],encoding='utf-8')); print(c.get('admin_password') or '')" "${CONFIG_FILE}" 2>/dev/null || true)"
fi

# 环境变量给序号时，先拉列表换成 server_id
if [ -n "${ENV_SNUM}" ]; then
  echo "[3/5] 从面板拉取服务器列表…"
  SERVERS_JSON="$(curl -sSL "${PANEL_URL}/api/servers")"
  if [ -z "${SERVERS_JSON}" ]; then
    echo "拉取失败，请检查面板地址 ${PANEL_URL}" >&2; exit 1
  fi
  ENV_SID="$(echo "${SERVERS_JSON}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
servers = data if isinstance(data, list) else data.get('servers', [])
idx = int(sys.argv[1]) - 1
print(servers[idx]['id'])
" "${ENV_SNUM}")"
  echo "      环境变量指定第 ${ENV_SNUM} 台：${ENV_SID}"
fi

SERVER_ID="${ENV_SID:-${EXISTING_SID}}"
ADMIN_PASS="${ENV_PASS:-${EXISTING_PASS}}"
USED_ENV=0
[ -n "${ENV_SID}" ] || [ -n "${ENV_SNUM}" ] || [ -n "${ENV_PASS}" ] && USED_ENV=1

# 缺哪项就只问哪项
if [ -z "${SERVER_ID}" ]; then
  echo "[3/5] 从面板拉取服务器列表…"
  SERVERS_JSON="$(curl -sSL "${PANEL_URL}/api/servers")"
  if [ -z "${SERVERS_JSON}" ]; then
    echo "拉取失败，请检查面板地址 ${PANEL_URL}" >&2; exit 1
  fi
  echo "${SERVERS_JSON}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
servers = data if isinstance(data, list) else data.get('servers', [])
for i, s in enumerate(servers, 1):
    print(f\"{i}. {s.get('name','?')}  (id={s.get('id','?')})\")
" >&2
  prompt CHOICE "选第几台（输入编号）: "
  SERVER_ID="$(echo "${SERVERS_JSON}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
servers = data if isinstance(data, list) else data.get('servers', [])
idx = int(sys.argv[1]) - 1
print(servers[idx]['id'])
" "${CHOICE}")"
  SERVER_NAME="$(echo "${SERVERS_JSON}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
servers = data if isinstance(data, list) else data.get('servers', [])
idx = int(sys.argv[1]) - 1
print(servers[idx].get('name',''))
" "${CHOICE}")"
  echo "      已选：${SERVER_NAME}（${SERVER_ID}）"
fi

if [ -z "${ADMIN_PASS}" ]; then
  prompt ADMIN_PASS "面板管理员密码（输入不显示）: " 1
fi

# 有环境变量传入或缺过项时，写（更新）配置；纯复用已有配置时不动
if [ "${USED_ENV}" -eq 1 ] || [ -z "${EXISTING_SID}" ] || [ -z "${EXISTING_PASS}" ]; then
  mkdir -p "${CONFIG_DIR}"
  python3 - "${CONFIG_FILE}" "${PANEL_URL}" "${ADMIN_USER}" "${ADMIN_PASS}" "${SERVER_ID}" <<'PYEOF'
import json, sys
path, panel_url, admin_username, admin_password, server_id = sys.argv[1:6]
with open(path, 'w', encoding='utf-8') as f:
    json.dump({
        "panel_url": panel_url,
        "admin_username": admin_username,
        "admin_password": admin_password,
        "server_id": server_id,
    }, f, ensure_ascii=False, indent=2)
PYEOF
  chmod 600 "${CONFIG_FILE}"
  echo "[4/5] 配置已写 ${CONFIG_FILE}（权限 600）"
else
  echo "[3/5] 已有配置 ${CONFIG_FILE}，直接复用（不问序号和密码）"
fi

# 5. cron + 试跑
CRON_LINE="5 * * * * /usr/bin/python3 ${INSTALL_DIR}/route_detect.py >> ${LOG_FILE} 2>&1"
if crontab -l 2>/dev/null | grep -Fq "${INSTALL_DIR}/route_detect.py"; then
  echo "[5/5] cron 已存在，跳过"
else
  (crontab -l 2>/dev/null; echo "${CRON_LINE}") | crontab -
  echo "[5/5] cron 已加：${CRON_LINE}"
fi
echo ""
echo "试跑（dry-run，不写标签、不推送）…"
python3 "${INSTALL_DIR}/route_detect.py" --dry-run
echo ""
echo "正式跑一遍（写标签+推送）…"
python3 "${INSTALL_DIR}/route_detect.py"
echo ""
echo "完成。以后每小时 05 分自动跑。"
