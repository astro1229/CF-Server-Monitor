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
CARRIER_NAMES = {"ct": "电信", "cu": "联通", "cm": "移动"}

# 线路优先级（单台机器只出一个标签，取三个运营商里优先级最高的那条线）
PRIORITY = {"CN2GIA": 5, "9929": 4, "CMIN2": 3, "CN2GT": 2, "163": 1, "CMI": 1}

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
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


def run_trace(target, tool):
    """对一个目标跑一次路由探测，返回原始输出文本。"""
    if tool == "nexttrace":
        # NextTrace 没有 --quiet（-q 是 --queries）；用 --no-color + 简洁模式。
        # 注意：去色参数是 --no-color（或 -C），不是 --nocolor；写错会导致
        # nexttrace 打印 usage 却返回 0，解析器只能从 usage 文本里捡到
        # 零星 IP，误判为 2 跳且识别不出线路。
        # -k 是传统 traceroute 输出（新版默认将切 MTR，格式最稳）；--table 是
        # 表格输出；都不支持的老版本就用默认输出。解析只用正则，不依赖具体格式。
        attempts = [
            ["nexttrace", "--ipv4", "--no-color", "-k", target],
            ["nexttrace", "--ipv4", "--no-color", "--table", target],
            ["nexttrace", "--ipv4", "--no-color", target],
        ]
    else:
        attempts = [["traceroute", "-4", "-n", target]]

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

    每行取第一个 IPv4、第一个 ASxxxx、ASN 之后的地理位置文字；RTT 取同行
    第一个，NextTrace 默认把延迟打在下一行（缩进的 "3.80 ms / 11.07 ms /
    7.35 ms"），此时取下一行的第一个 RTT。没有 ASN 的行 ASN 为 None，
    没有 RTT 的行延迟为 None，没有地理位置文字的行 geo 为 None。
    表头、无 IP 的行直接跳过。
    """
    lines = text.splitlines()
    hops = []
    for i, line in enumerate(lines):
        # 只解析跳行（行首是跳号）；表头、"Trace Stopped" 尾行等不含跳号，
        # 但含目标 IP，误解析会多出一跳（geo 只剩 ")"）。
        if not re.match(r"^\s*\d+\s", line):
            continue
        m = IP_RE.search(line)
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
        geo = _extract_geo(line, geo_pos)
        r = RTT_RE.search(line)
        if not r and i + 1 < len(lines):
            r = RTT_RE.search(lines[i + 1])
        hops.append((m.group(0), asn,
                     float(r.group(1)) if r else None, geo))
    return hops


def _has_cn2(hops):
    """TQ：任何一跳 IP 以 59.43. 开头即算经过 CN2（不靠 ASN 标注，
    NextTrace 有时会漏标 59.43 跳的 AS4809）；AS4809 也算 CN2 证据。"""
    return (any(ip.startswith("59.43.") for ip, _, _, _ in hops)
            or any(asn == 4809 for _, asn, _, _ in hops if asn is not None))


def _is_163_ip(ip):
    """电信 163 骨干常见段（TQ is_163_ip 的简化版）。"""
    return ip.startswith("202.97.") or ip.startswith("218.30.")


def _has_cn2_to_163(hops):
    """TQ has_cn2_to_163：找到第一个 CN2 跳（59.43 IP 或 AS4809），之后若
    出现非 59.43 且为 AS4134/AS4847 或 163 段 IP，则算 CN2 转 163 → CN2GT；
    否则 CN2GIA。"""
    first_cn2 = None
    for i, (ip, asn, _rtt, _geo) in enumerate(hops):
        if ip.startswith("59.43.") or asn == 4809:
            first_cn2 = i
            break
    if first_cn2 is None:
        return False
    for ip, asn, _rtt, _geo in hops[first_cn2 + 1:]:
        if ip.startswith("59.43."):
            continue
        if asn in (4134, 4847):
            return True
        if _is_163_ip(ip):
            return True
    return False


def _ip_prefix_label(ip, carrier):
    """无 ASN 时的 IP 段兜底（NextTrace API 被限流、拿不到 ASN 时用）。

    按运营商区分（202.97.* 是电信自己的 163 网段，联通借道不算）：
      59.43.* → CN2（任何运营商）；
      电信：202.97.* → 163；
      联通：218.105.* → 9929；
      移动：223.119.*/223.120.* → CMI（ASN 缺失时无法区分 CMI/CMIN2，
      默认 CMI），221.183.* → CMNET。
    其余返回 None。
    """
    if ip.startswith("59.43."):
        return "CN2"
    if carrier == "ct" and ip.startswith("202.97."):
        return "163"
    if carrier == "cu" and ip.startswith("218.105."):
        return "9929"
    if carrier == "cm":
        if ip.startswith("223.119.") or ip.startswith("223.120."):
            return "CMI"
        if ip.startswith("221.183."):
            return "CMNET"
    return None


def classify_carrier(carrier, hops):
    """按 TQ (TcpQuality runTcpQuality-core.sh classify()) 规则分类。

    优先级：CN2（59.43）最高——任何运营商的回程只要经过 59.43，
    整条就标 CN2，再按是否转 163 分 CN2GIA/CN2GT。
    其次按运营商：
      联通：AS9929 → 9929；AS4837/AS4808 → 163。
      移动：AS58807 → CMIN2；AS58453/AS9808/AS56040-56048 → CMI。
      电信：无 59.43 时 AS4134/AS4847 → 163。
    （AS58453 是 CMI 不是 CMIN2；AS58807 才是 CMIN2。）
    ASN 缺失时（NextTrace API 限流）用 IP 段兜底。
    """
    asns = {asn for _, asn, _rtt, _geo in hops if asn is not None}

    # CN2 优先：任何运营商只要经过 59.43 就标 CN2
    if _has_cn2(hops):
        if _has_cn2_to_163(hops):
            return "CN2GT"
        return "CN2GIA"

    if carrier == "ct":
        if 4134 in asns or 4847 in asns:
            return "163"
    elif carrier == "cu":
        if 9929 in asns:
            return "9929"
        if 4837 in asns or 4808 in asns:
            return "163"
    elif carrier == "cm":
        if 58807 in asns:
            return "CMIN2"
        if (58453 in asns or 9808 in asns
                or any(a is not None and 56040 <= a <= 56048
                       for a in asns)):
            return "CMI"
    # ASN 缺失兜底：用 IP 段判断（NextTrace API 限流时）
    for ip, _asn, _rtt, _geo in hops:
        label = _ip_prefix_label(ip, carrier)
        if label is None:
            continue
        if carrier == "ct" and label in ("CN2", "163"):
            return "CN2GT" if label == "CN2" else "163"
        if carrier == "cu" and label in ("CN2", "9929", "163"):
            return label
        if carrier == "cm" and label in ("CMI", "CMNET"):
            return label
    return None


def classify_hop(ip, asn):
    """给单跳打线路徽标（用于历史详情表格每跳的线路列）。

    59.43.* → CN2；AS4134/AS4847 或 202.97.* → 163；
    AS9929 → 9929；AS58807 → CMIN2；AS58453/AS9808/AS56040-48 → CMI；
    AS9808 → CMNET（移动骨干，无 CMI 特征时）；RFC1918 → 内网；
    其余 → None（不打标）。
    """
    if ip.startswith("59.43."):
        return "CN2"
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
    if asn == 58807:
        return "CMIN2"
    if asn == 58453 or 56040 <= asn <= 56048:
        return "CMI"
    if asn == 9808:
        return "CMNET"
    if asn == 23764:
        return "Tata"
    return None


def detect_route(targets, tool):
    """跑三次探测，返回 (最好线路, {运营商: 线路或None}, {运营商: hops})。

    hops 是每跳的 (IP, ASN) 列表，供历史记录用。
    三个运营商都没识别出时返回 (None, ..., ...)，由调用方决定不写标签退出。
    """
    per_carrier = {}
    hops_by_carrier = {}
    for carrier in ("ct", "cu", "cm"):
        target = targets[carrier]
        log(f"探测{CARRIER_NAMES[carrier]}回程：{target}")
        try:
            output = run_trace(target, tool)
        except Exception as e:
            log(f"{CARRIER_NAMES[carrier]}探测失败：{e}")
            per_carrier[carrier] = None
            hops_by_carrier[carrier] = []
            continue
        hops = parse_trace_output(output)
        hops_by_carrier[carrier] = hops
        label = classify_carrier(carrier, hops)
        per_carrier[carrier] = label
        log(f"{CARRIER_NAMES[carrier]}：{len(hops)} 跳，"
            f"识别结果={label or '未识别'}")
        # NextTrace API 有速率限制（pow token），三条连着跑第三条容易
        # 拿不到 ASN；每条之间停 10 秒错开。
        if carrier != "cm":
            time.sleep(10)
    found = [v for v in per_carrier.values() if v]
    if not found:
        return None, per_carrier, hops_by_carrier
    best = max(found, key=lambda v: PRIORITY[v])
    return best, per_carrier, hops_by_carrier


ROUTE_LABELS = {"CN2GIA", "CN2GT", "9929", "CMIN2", "CMI", "163", "?"}


def format_routes_tag(per_carrier):
    """三网识别结果写成一个线路标签（左气泡）。

    三条是各自独立的回程，不能只取最好的一条（最好那条不代表
    另外两网也走它）。三网回程全一样时只填一个（如 "CN2GT"）；
    否则三条都写出来、空格隔开、放在一个气泡里
    （如 "163 163 CMIN2"、"CN2GIA 9929 CMIN2"）。
    未识别的运营商用 ? 占位。
    """
    values = [per_carrier.get(c) or "?" for c in ("ct", "cu", "cm")]
    if values[0] == values[1] == values[2]:
        return values[0]
    return " ".join(values)


def _is_single_route(tag):
    return tag in ROUTE_LABELS


def _is_combined_route(tag):
    """线路标签（单枚）：三网拼在一个标签里，如 "163 163 CMIN2"
    或 "电信163 联通163 移动CMIN2"；三网全一样时只有单个值，如 "CN2GT"。"""
    parts = tag.split()
    if not parts:
        return False
    stripped = [p.replace("电信", "").replace("联通", "").replace("移动", "")
                for p in parts]
    if len(stripped) == 1:
        return stripped[0] in ROUTE_LABELS
    return all(p in ROUTE_LABELS for p in stripped) and len(stripped) == 3


def split_auto_tags(old_tags):
    """把现有的 tags 切成（自动线路标签数，手动备注标签列表）。

    自动部分可能是 1 个线路标签（"CN2GT" 或 "163 163 CMIN2"），
    或上一版的 3 个独立标签（"163","163","CMIN2"）；
    其余一律当手动备注保留，脚本绝不碰。
    先判 3 个独立标签，再判 1 个线路标签（单个 "163" 两种都像）。
    """
    if not old_tags:
        return 0, []
    if len(old_tags) >= 3 and all(_is_single_route(t)
                                  for t in old_tags[:3]):
        return 3, old_tags[3:]
    if _is_combined_route(old_tags[0]):
        return 1, old_tags[1:]
    return 0, old_tags


# ---------------------------------------------------------------- 历史存储

HISTORY_KEEP_HOURS = 168  # 历史留 7 天（2026-11-12 用户定，和延迟/丢包历史一致）


def history_path(cfg):
    """历史文件路径：配置文件同目录下的 history.json。"""
    config_path = Path(cfg.get("_config_path", DEFAULT_CONFIG_PATH))
    return config_path.parent / "history.json"


def save_history(cfg, per_carrier, hops_by_carrier, routes_tag):
    """把本次探测结果追加进历史文件（带时间戳，留 7 天）。

    每条记录：{ts, routes_tag, carriers: {ct: {label, hops: [[ip, asn, rtt_ms, geo], ...]},
    cu: {...}, cm: {...}}}。hops 只存有 IP 的跳（已去重连续重复）。
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

    # 1. 探测
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
    routes_tag = format_routes_tag(per_carrier)
    log(f"三网识别结果：{per_carrier}，线路标签写成：{routes_tag}")
    # 历史：每次探测结果都存一份（带时间戳，留 7 天），供面板线路历史用
    record = save_history(cfg, per_carrier, hops_by_carrier, routes_tag)

    if args.dry_run:
        log(f"dry-run：会把线路标签改成「{routes_tag}」，"
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
    old_tags = split_tags(server.get("tags"))
    _auto_n, manual_tags = split_auto_tags(old_tags)
    new_tags = [routes_tag] + manual_tags
    # 历史推送：标签变没变都推（跳数可能变了、标签没变），Worker 没部署
    # 此接口时只记警告、不失败（标签写回才是主业）。
    try:
        client.push_route_history(cfg["panel_url"], token,
                                  cfg["server_id"], record)
        log("历史已推送到 Worker（/api/route-history）")
    except Exception as e:
        log(f"警告：历史推送失败（Worker 可能还没部署此接口）：{e}")
    if new_tags == old_tags:
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

# 3. 选机器：从面板公开接口拉列表，按编号选
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

# 4. 面板管理员密码 + 写配置
prompt ADMIN_PASS "面板管理员密码（输入不显示）: " 1
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
echo "完成。正式跑一遍（写标签+推送）用：python3 ${INSTALL_DIR}/route_detect.py"
