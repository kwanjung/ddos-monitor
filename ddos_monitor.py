#!/usr/bin/env python3
"""
DDoS 실시간 모니터링 도구 (EC2 애플리케이션 레벨)
"""

from __future__ import annotations

import argparse
import curses
import json
import os
import socket
import subprocess
import sys
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from statistics import median
from typing import Optional


# ---------------------------------------------------------------------------
# 상수
# ---------------------------------------------------------------------------

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

STATE_ORDER = [
    "ESTABLISHED", "SYN_RECV", "TIME_WAIT",
    "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT",
    "LAST_ACK", "CLOSING", "SYN_SENT", "LISTEN",
]

# 표시할 nstat 카운터 (delta/sec 로 렌더)
NSTAT_KEYS_TCP = [
    "TcpPassiveOpens",
    "TcpActiveOpens",
    "TcpAttemptFails",
    "TcpRetransSegs",
    "TcpExtListenOverflows",
    "TcpExtListenDrops",
    "TcpExtTCPReqQFullDrop",
    "TcpExtSyncookiesSent",
    "TcpExtEmbryonicRsts",
    "TcpExtTCPAbortOnMemory",
    "TcpExtTCPAbortOnTimeout",
]

NSTAT_KEYS_UDP = [
    "UdpInDatagrams",
    "UdpOutDatagrams",
    "UdpInErrors",
    "UdpNoPorts",
    "UdpRcvbufErrors",
    "UdpSndbufErrors",
    "IpReasmReqds",
    "IpReasmFails",
]

# 하위 호환용 (json 필드에서 쓰임)
NSTAT_KEYS = NSTAT_KEYS_TCP + NSTAT_KEYS_UDP

NSTAT_LABELS = {
    "TcpPassiveOpens":            "PassiveOpens",
    "TcpActiveOpens":             "ActiveOpens",
    "TcpAttemptFails":            "AttemptFails",
    "TcpRetransSegs":             "RetransSegs",
    "TcpExtListenOverflows":      "ListenOverflows",
    "TcpExtListenDrops":          "ListenDrops",
    "TcpExtTCPReqQFullDrop":      "ReqQFullDrop",
    "TcpExtSyncookiesSent":       "SyncookiesSent",
    "TcpExtEmbryonicRsts":        "EmbryonicRsts",
    "TcpExtTCPAbortOnMemory":     "AbortOnMemory",
    "TcpExtTCPAbortOnTimeout":    "AbortOnTimeout",
    "UdpInDatagrams":             "UdpIn",
    "UdpOutDatagrams":            "UdpOut",
    "UdpInErrors":                "UdpInErrors",
    "UdpNoPorts":                 "UdpNoPorts",
    "UdpRcvbufErrors":            "UdpRcvbufErr",
    "UdpSndbufErrors":            "UdpSndbufErr",
    "IpReasmReqds":               "IpReasmReqds",
    "IpReasmFails":               "IpReasmFails",
}

# 카운터가 0 이 아니면 즉시 주의 표시
COUNTER_NONZERO_WARN = {
    "TcpExtListenOverflows",
    "TcpExtListenDrops",
    "TcpExtTCPReqQFullDrop",
    "TcpExtSyncookiesSent",
    "TcpExtTCPAbortOnMemory",
    "UdpRcvbufErrors",
    "UdpSndbufErrors",
}


# ---------------------------------------------------------------------------
# 데이터 클래스
# ---------------------------------------------------------------------------

# 소스 IP / 서브넷 카운터 상한. 스푸핑성 봇넷 공격에서 tick 당 수백만 unique
# 소스 IP 가 들어올 수 있어 무제한 Counter 는 도구 자체를 부하 요인으로 만든다.
# 이 상한을 넘으면:
#   - 상위 K 개는 정확히 유지 (top-N 표시용)
#   - 그 이하는 스킵되고 spilled 카운터로만 집계 (진짜 unique 수는 HLL 로 별도)
DEFAULT_SRC_TRACK_LIMIT = 50_000


class BoundedCounter:
    """상한 있는 Counter. 상한 도달 시 신규 key 는 무시하고 spilled 카운트만 증가.
    """

    __slots__ = ("_c", "_max", "spilled", "spilled_hits")

    def __init__(self, max_entries: int = DEFAULT_SRC_TRACK_LIMIT) -> None:
        self._c: Counter = Counter()
        self._max = max_entries
        self.spilled: int = 0       # 상한 초과로 무시된 신규 key 개수 (누적)
        self.spilled_hits: int = 0  # 상한 초과 상태에서 발생한 관측 횟수

    def add(self, key) -> None:
        if key in self._c:
            self._c[key] += 1
        elif len(self._c) < self._max:
            self._c[key] = 1
        else:
            self.spilled += 1
            self.spilled_hits += 1

    def most_common(self, n: int):
        return self._c.most_common(n)

    def values(self):
        return self._c.values()

    def __len__(self) -> int:
        return len(self._c)

    def __bool__(self) -> bool:
        return bool(self._c)

    @property
    def saturated(self) -> bool:
        return len(self._c) >= self._max


class HLL:
    """HyperLogLog cardinality estimator (fixed-size, ~1.5 KB).
    """

    __slots__ = ("_p", "_m", "_reg", "_alpha")

    def __init__(self, p: int = 12) -> None:
        # p=12 → m=4096 → 표준 오차 ~1.6%. 메모리 4 KB (bytes list)
        self._p = p
        self._m = 1 << p
        self._reg = bytearray(self._m)
        # 상수 alpha_m (Flajolet et al.)
        if self._m == 16:   self._alpha = 0.673
        elif self._m == 32: self._alpha = 0.697
        elif self._m == 64: self._alpha = 0.709
        else:               self._alpha = 0.7213 / (1 + 1.079 / self._m)

    def add(self, item: str) -> None:
        import hashlib
        h = int.from_bytes(hashlib.blake2b(item.encode("utf-8"), digest_size=8).digest(), "big")
        idx = h >> (64 - self._p)
        # 나머지 (64 - p) 비트에서 "leftmost 1 의 위치 + 1" 을 rank 로.
        # (MSB 가 1 이면 rank=1, 두번째 비트만 1 이면 rank=2, ...)
        remaining_bits = 64 - self._p
        remaining = h & ((1 << remaining_bits) - 1)
        if remaining == 0:
            rank = remaining_bits + 1
        else:
            rank = remaining_bits - remaining.bit_length() + 1
        if rank > self._reg[idx]:
            self._reg[idx] = rank

    def count(self) -> int:
        import math
        m = self._m
        raw = self._alpha * m * m / sum(math.pow(2, -r) for r in self._reg)
        # small-range correction
        if raw <= 2.5 * m:
            zeros = self._reg.count(0)
            if zeros:
                return int(m * math.log(m / zeros))
        return int(raw)

    def clear(self) -> None:
        self._reg = bytearray(self._m)


@dataclass
class ConnSample:
    ts: float
    state_counts: Counter = field(default_factory=Counter)
    src_ip_counts: BoundedCounter = field(default_factory=BoundedCounter)
    src_subnet24_counts: BoundedCounter = field(default_factory=BoundedCounter)
    dst_port_counts: Counter = field(default_factory=Counter)       # 로컬 포트별 ESTABLISHED
    src_ip_hll: HLL = field(default_factory=HLL)
    src_subnet24_hll: HLL = field(default_factory=HLL)
    zero_queue_established: int = 0
    total_conns: int = 0
    filtered_conns: int = 0
    long_idle_established: int = 0  # --track-age 활성 시에만 채워짐
    listen_queues: list = field(default_factory=list)               # [(port, curr, backlog), ...]

    def half_open_ratio(self) -> float:
        est = self.state_counts.get("ESTABLISHED", 0)
        syn = self.state_counts.get("SYN_RECV", 0)
        return syn / max(1, est)

    def to_json(self) -> dict:
        return {
            "ts": self.ts,
            "state_counts": dict(self.state_counts),
            "top_sources": self.src_ip_counts.most_common(20),
            "unique_source_ips_tracked": len(self.src_ip_counts),
            "unique_source_ips_hll": self.src_ip_hll.count(),
            "src_ips_saturated": self.src_ip_counts.saturated,
            "src_ips_spilled": self.src_ip_counts.spilled,
            "unique_source_subnets24_tracked": len(self.src_subnet24_counts),
            "unique_source_subnets24_hll": self.src_subnet24_hll.count(),
            "top_dst_ports": self.dst_port_counts.most_common(20),
            "zero_queue_established": self.zero_queue_established,
            "long_idle_established": self.long_idle_established,
            "total_conns": self.total_conns,
            "filtered_conns": self.filtered_conns,
            "half_open_ratio": round(self.half_open_ratio(), 4),
            "listen_queues": self.listen_queues,
        }


@dataclass
class UdpSample:
    """/proc/net/udp{,6} 스냅샷.
    소켓 단위 rx_queue 깊이와 소켓별 drops 카운터만 관찰.
    """
    ts: float
    sockets: list = field(default_factory=list)   # [(local_port, rx_queue, drops_cum), ...]
    total_drops: int = 0                          # 필터링된 소켓들의 drops 합
    total_rx_queue: int = 0                       # 필터링된 소켓들의 rx_queue 합
    socket_count: int = 0

    def to_json(self, prev_drops_map: Optional[dict] = None) -> dict:
        obj = {
            "ts": self.ts,
            "socket_count": self.socket_count,
            "total_rx_queue": self.total_rx_queue,
            "sockets": [
                {"port": p, "rx_queue": rxq, "drops": d}
                for p, rxq, d in self.sockets
            ][:32],
        }
        return obj


@dataclass
class SysSample:
    ts: float
    cpu_total: int = 0        # jiffies 합계 (user+nice+system+idle+iowait+irq+softirq+steal)
    cpu_idle: int = 0         # idle + iowait
    cpu_softirq: int = 0      # softirq jiffies
    ncpu: int = 1
    mem_total_kb: int = 0
    mem_avail_kb: int = 0
    load1: float = 0.0
    load5: float = 0.0
    load15: float = 0.0
    net_rx: int = 0           # 선택된 NIC 들의 rx bytes 합
    net_tx: int = 0
    net_rx_pkts: int = 0
    net_tx_pkts: int = 0
    net_rx_drops: int = 0
    net_rx_errors: int = 0
    net_tx_drops: int = 0
    net_tx_errors: int = 0
    nics: list = field(default_factory=list)
    conntrack_count: int = 0
    conntrack_max: int = 0

    def cpu_pct(self, prev: "SysSample") -> float:
        dt_total = self.cpu_total - prev.cpu_total
        dt_idle = self.cpu_idle - prev.cpu_idle
        if dt_total <= 0:
            return 0.0
        return max(0.0, min(100.0, 100.0 * (dt_total - dt_idle) / dt_total))

    def softirq_pct(self, prev: "SysSample") -> float:
        dt_total = self.cpu_total - prev.cpu_total
        dt_soft = self.cpu_softirq - prev.cpu_softirq
        if dt_total <= 0:
            return 0.0
        return max(0.0, min(100.0, 100.0 * dt_soft / dt_total))

    def net_bps(self, prev: "SysSample") -> tuple[float, float]:
        dt = max(1e-6, self.ts - prev.ts)
        rx = max(0.0, (self.net_rx - prev.net_rx) * 8.0 / dt)
        tx = max(0.0, (self.net_tx - prev.net_tx) * 8.0 / dt)
        return rx, tx

    def net_pps(self, prev: "SysSample") -> tuple[float, float]:
        dt = max(1e-6, self.ts - prev.ts)
        rx = max(0.0, (self.net_rx_pkts - prev.net_rx_pkts) / dt)
        tx = max(0.0, (self.net_tx_pkts - prev.net_tx_pkts) / dt)
        return rx, tx

    def net_err_rate(self, prev: "SysSample") -> dict:
        dt = max(1e-6, self.ts - prev.ts)
        return {
            "rx_drops": max(0.0, (self.net_rx_drops - prev.net_rx_drops) / dt),
            "rx_errors": max(0.0, (self.net_rx_errors - prev.net_rx_errors) / dt),
            "tx_drops": max(0.0, (self.net_tx_drops - prev.net_tx_drops) / dt),
            "tx_errors": max(0.0, (self.net_tx_errors - prev.net_tx_errors) / dt),
        }


@dataclass
class ProcSample:
    ts: float
    pid: int
    name: str = ""
    utime: int = 0            # /proc/pid/stat user jiffies
    stime: int = 0            # kernel jiffies
    rss_kb: int = 0
    vsize_kb: int = 0
    threads: int = 0
    num_fds: int = 0
    voluntary_ctxt: int = 0
    nonvoluntary_ctxt: int = 0
    alive: bool = True

    def cpu_pct(self, prev: "ProcSample", sys_prev: "SysSample", sys_cur: "SysSample") -> float:
        dt_total = sys_cur.cpu_total - sys_prev.cpu_total
        dt_proc = (self.utime + self.stime) - (prev.utime + prev.stime)
        if dt_total <= 0:
            return 0.0
        # 시스템 전체 대비가 아닌, 개별 코어 대비로 100%가 최대가 되도록 스케일링
        return max(0.0, 100.0 * dt_proc * max(1, sys_cur.ncpu) / dt_total)


@dataclass
class NstatSample:
    ts: float
    counters: dict = field(default_factory=dict)

    def delta_per_sec(self, prev: "NstatSample") -> dict:
        dt = max(1e-6, self.ts - prev.ts)
        return {
            k: (self.counters.get(k, 0) - prev.counters.get(k, 0)) / dt
            for k in self.counters.keys() | prev.counters.keys()
        }


@dataclass
class Alert:
    ts: float
    severity: str  # "WARN" | "CRIT"
    msg: str


# ---------------------------------------------------------------------------
# 수집 함수
# ---------------------------------------------------------------------------

def _decode_hex_addr(addr: str) -> tuple[str, int]:
    """/proc/net/tcp 형식의 addr:port 를 (ip, port) 로 변환한다.
    - IPv4: 8 hex chars, 32비트 워드가 host byte order (리눅스 x86 = little-endian)
    - IPv6: 32 hex chars, 각 32비트 워드가 host byte order (워드별로 뒤집어야 함)
    """
    ip_hex, port_hex = addr.split(":")
    port = int(port_hex, 16)
    if len(ip_hex) == 8:
        b = bytes.fromhex(ip_hex)
        return socket.inet_ntop(socket.AF_INET, b[::-1]), port
    b = bytearray(bytes.fromhex(ip_hex))
    for i in range(0, len(b), 4):
        b[i:i + 4] = b[i:i + 4][::-1]
    return socket.inet_ntop(socket.AF_INET6, bytes(b)), port


def scan_proc_tcp(
    port_min: Optional[int],
    port_max: Optional[int],
    age_tracker: Optional["AgeTracker"] = None,
    idle_age_threshold: float = 30.0,
    ipv6: bool = True,
    src_track_limit: int = DEFAULT_SRC_TRACK_LIMIT,
) -> ConnSample:
    """/proc/net/tcp{,6} 스캔. port_min/max 가 있으면 로컬 포트로 필터.

    """
    sample = ConnSample(
        ts=time.time(),
        src_ip_counts=BoundedCounter(src_track_limit),
        src_subnet24_counts=BoundedCounter(src_track_limit),
    )
    now = sample.ts
    current_keys: Optional[set] = set() if age_tracker else None

    paths = ["/proc/net/tcp"]
    if ipv6:
        paths.append("/proc/net/tcp6")

    for path in paths:
        try:
            with open(path, "r") as f:
                next(f, None)  # header
                for line in f:
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    local, remote, state, txrx = parts[1], parts[2], parts[3], parts[4]
                    sample.total_conns += 1

                    try:
                        lport = int(local.rsplit(":", 1)[1], 16)
                    except (ValueError, IndexError):
                        continue

                    if port_min is not None and not (port_min <= lport <= port_max):
                        continue

                    sample.filtered_conns += 1
                    sname = TCP_STATES.get(state, f"UNK_{state}")
                    sample.state_counts[sname] += 1

                    # LISTEN 소켓: accept queue 깊이 = tx_queue, backlog 상한 = rx_queue
                    # /proc/net/tcp 는 LISTEN 소켓의 remote 가 0 이라 별도로 처리
                    if sname == "LISTEN":
                        try:
                            tx_hex, rx_hex = txrx.split(":")
                            tx_q, rx_q = int(tx_hex, 16), int(rx_hex, 16)
                            sample.listen_queues.append((lport, tx_q, rx_q))
                        except ValueError:
                            pass
                        continue

                    if sname != "ESTABLISHED":
                        continue

                    # ESTABLISHED 전용 처리
                    tx = rx = -1
                    try:
                        tx_hex, rx_hex = txrx.split(":")
                        tx, rx = int(tx_hex, 16), int(rx_hex, 16)
                    except ValueError:
                        pass
                    if tx == 0 and rx == 0:
                        sample.zero_queue_established += 1

                    sample.dst_port_counts[lport] += 1

                    try:
                        src_ip, src_port = _decode_hex_addr(remote)
                    except (ValueError, OSError):
                        continue
                    sample.src_ip_counts.add(src_ip)
                    sample.src_ip_hll.add(src_ip)
                    # /24 서브넷 집계 (IPv4 만; IPv6 는 /64 사용)
                    if ":" in src_ip:
                        subnet = ":".join(src_ip.split(":")[:4]) + "::/64"
                    else:
                        subnet = ".".join(src_ip.split(".")[:3]) + ".0/24"
                    sample.src_subnet24_counts.add(subnet)
                    sample.src_subnet24_hll.add(subnet)

                    if age_tracker is not None:
                        key = (src_ip, src_port, lport)
                        current_keys.add(key)
                        first_seen = age_tracker.observe(key, now)
                        age = now - first_seen
                        if age >= idle_age_threshold and tx == 0 and rx == 0:
                            sample.long_idle_established += 1
        except OSError:
            continue

    if age_tracker is not None:
        age_tracker.prune(current_keys, now)

    return sample


def scan_proc_udp(
    port_min: Optional[int],
    port_max: Optional[int],
    ipv6: bool = True,
) -> UdpSample:
    """/proc/net/udp{,6} 파싱. 각 UDP 소켓의 local_port, rx_queue, drops 를 수집.

    /proc/net/udp 컬럼 (커널 2.6+, drops 는 3.0+):
      sl  local_addr:port  remote_addr:port  st  tx_queue:rx_queue  tr  tm->when
      retrnsmt  uid  timeout  inode  ref  pointer  drops(optional)

    """
    s = UdpSample(ts=time.time())
    paths = ["/proc/net/udp"]
    if ipv6:
        paths.append("/proc/net/udp6")
    for path in paths:
        try:
            with open(path) as f:
                header = f.readline()
                # 헤더에서 drops 컬럼 인덱스 확인. 헤더 예:
                #   sl  local_address rem_address st tx_queue rx_queue tr tm->when \
                #   retrnsmt   uid  timeout inode ref pointer drops
                # 데이터 라인의 컬럼 수와 헤더의 컬럼 수가 다를 수 있으므로
                # 뒤에서 몇 번째 인지 (음수 인덱스) 로 저장한다.
                hdr_tokens = header.split()
                drops_neg_idx: Optional[int] = None
                if "drops" in hdr_tokens:
                    # 헤더 마지막 토큰이 drops 이면 -1, 그 앞이면 -2 ...
                    drops_neg_idx = hdr_tokens.index("drops") - len(hdr_tokens)
                for line in f:
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    local = parts[1]
                    txrx = parts[4]
                    try:
                        lport = int(local.rsplit(":", 1)[1], 16)
                    except (ValueError, IndexError):
                        continue
                    if port_min is not None and not (port_min <= lport <= port_max):
                        continue
                    try:
                        _, rx_hex = txrx.split(":")
                        rx_q = int(rx_hex, 16)
                    except ValueError:
                        rx_q = 0
                    drops = 0
                    if drops_neg_idx is not None and abs(drops_neg_idx) <= len(parts):
                        try:
                            drops = int(parts[drops_neg_idx])
                        except ValueError:
                            drops = 0
                    s.sockets.append((lport, rx_q, drops))
                    s.total_rx_queue += rx_q
                    s.total_drops += drops
                    s.socket_count += 1
        except OSError:
            continue
    return s


class AgeTracker:
    """5-tuple (원격 IP, 원격 포트, 로컬 포트) 를 관찰한 최초 시각으로 매핑.

    ESTABLISHED 로 유지되는 동안 계속 확인되며, 프로세스 재시작이나 연결 종료 시
    prune() 에서 제거된다. 메모리 상한은 max_entries 로 제한.

    """

    def __init__(self, max_entries: int = 200_000) -> None:
        self._first_seen: dict[tuple[str, int, int], float] = {}
        self._max = max_entries
        self.saturated: bool = False
        self.rejected_new: int = 0  # 상한 초과로 추적 못한 신규 key 개수 (누적)

    def observe(self, key, now: float) -> float:
        v = self._first_seen.get(key)
        if v is None:
            if len(self._first_seen) >= self._max:
                self.saturated = True
                self.rejected_new += 1
                return now
            self._first_seen[key] = now
            return now
        return v

    def prune(self, current_keys, now: float) -> None:
        stale = [k for k in self._first_seen if k not in current_keys]
        for k in stale:
            del self._first_seen[k]
        if len(self._first_seen) < self._max:
            self.saturated = False

    def __len__(self) -> int:
        return len(self._first_seen)


def _pick_nics(explicit: Optional[list[str]]) -> list[str]:
    """모니터링할 NIC 목록. 명시 안 하면 lo 를 제외한 모든 up 인터페이스."""
    if explicit:
        return list(explicit)
    nics: list[str] = []
    try:
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                name = line.split(":", 1)[0].strip()
                if name and name != "lo":
                    nics.append(name)
    except OSError:
        pass
    return nics


def read_sys(nics: list[str]) -> SysSample:
    """CPU / 메모리 / load / NIC bytes 를 /proc 에서 스냅샷."""
    s = SysSample(ts=time.time(), nics=nics)

    try:
        ncpu = 0
        with open("/proc/stat") as f:
            for line in f:
                if not line.startswith("cpu"):
                    break
                parts = line.split()
                if parts[0] == "cpu":
                    vals = [int(x) for x in parts[1:]]
                    while len(vals) < 8:
                        vals.append(0)
                    # vals: user, nice, system, idle, iowait, irq, softirq, steal
                    s.cpu_total = sum(vals[:8])
                    s.cpu_idle = vals[3] + vals[4]
                    s.cpu_softirq = vals[6]
                else:
                    ncpu += 1
        s.ncpu = max(1, ncpu)
    except (OSError, ValueError, IndexError):
        pass

    try:
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, rest = line.partition(":")
                v = rest.strip().split()
                if not v:
                    continue
                try:
                    n = int(v[0])
                except ValueError:
                    continue
                if k == "MemTotal":
                    s.mem_total_kb = n
                elif k == "MemAvailable":
                    s.mem_avail_kb = n
                if s.mem_total_kb and s.mem_avail_kb:
                    break
    except OSError:
        pass

    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
            if len(parts) >= 3:
                s.load1, s.load5, s.load15 = float(parts[0]), float(parts[1]), float(parts[2])
    except (OSError, ValueError):
        pass

    try:
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                name, _, rest = line.partition(":")
                name = name.strip()
                if name not in nics:
                    continue
                cols = rest.split()
                # rx: bytes packets errs drop fifo frame compressed multicast
                # tx: bytes packets errs drop fifo colls carrier compressed
                if len(cols) >= 16:
                    s.net_rx        += int(cols[0])
                    s.net_rx_pkts   += int(cols[1])
                    s.net_rx_errors += int(cols[2])
                    s.net_rx_drops  += int(cols[3])
                    s.net_tx        += int(cols[8])
                    s.net_tx_pkts   += int(cols[9])
                    s.net_tx_errors += int(cols[10])
                    s.net_tx_drops  += int(cols[11])
    except (OSError, ValueError):
        pass

    # conntrack: 모듈이 로드된 경우에만. 파일 없으면 조용히 스킵.
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_count") as f:
            s.conntrack_count = int(f.read().strip())
        with open("/proc/sys/net/netfilter/nf_conntrack_max") as f:
            s.conntrack_max = int(f.read().strip())
    except (OSError, ValueError):
        pass

    return s


def resolve_pid(pid_arg: Optional[int], pname_arg: Optional[str],
                substring: bool = False) -> Optional[int]:
    """--pid 우선. 아니면 --pname 으로 /proc 스캔.

    - 기본은 exact match (comm == pname_arg).
    - substring=True 이면 부분 매치 허용 (여러 매치 시 최소 PID 선택).
    - /proc 열거 순서는 inode 기반이라 비결정적이므로 반드시 정렬된 후보 중 선택.
    """
    if pid_arg:
        return pid_arg if os.path.isdir(f"/proc/{pid_arg}") else None
    if not pname_arg:
        return None
    matches: list[int] = []
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/comm") as f:
                    comm = f.read().strip()
            except OSError:
                continue
            if comm == pname_arg or (substring and pname_arg in comm):
                matches.append(int(entry))
    except OSError:
        pass
    if not matches:
        return None
    return min(matches)


def read_proc(pid: int) -> ProcSample:
    p = ProcSample(ts=time.time(), pid=pid)
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
        # comm 은 괄호로 묶여있고 공백 포함 가능. 뒤에서 오프셋 계산.
        r_paren = data.rfind(")")
        comm = data[data.find("(") + 1: r_paren]
        rest = data[r_paren + 2:].split()
        # rest 인덱스 (proc(5) 기준, stat 필드 3(state) 부터 0-index)
        #   0: state, 11: utime, 12: stime, 17: num_threads, 20: vsize, 21: rss(pages)
        p.name = comm
        p.utime = int(rest[11])
        p.stime = int(rest[12])
        p.threads = int(rest[17])
        p.vsize_kb = int(rest[20]) // 1024
        p.rss_kb = int(rest[21]) * (os.sysconf("SC_PAGESIZE") // 1024)
    except (OSError, IndexError, ValueError):
        p.alive = False
        return p

    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("voluntary_ctxt_switches:"):
                    p.voluntary_ctxt = int(line.split()[1])
                elif line.startswith("nonvoluntary_ctxt_switches:"):
                    p.nonvoluntary_ctxt = int(line.split()[1])
    except (OSError, ValueError):
        pass

    try:
        p.num_fds = len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        # 권한 부족일 수 있음 (다른 유저의 프로세스). fd 수는 0 으로 둠.
        pass

    return p


def read_nstat() -> NstatSample:
    """nstat -az (누적 절대값) 를 파싱한다.
    nstat 없거나 실패 시 /proc/net/{snmp,netstat} 를 폴백으로 사용."""
    sample = NstatSample(ts=time.time())
    try:
        r = subprocess.run(
            ["nstat", "-az"], capture_output=True, text=True, timeout=5, check=False
        )
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        sample.counters[parts[0]] = int(parts[1])
                    except ValueError:
                        pass
            if sample.counters:
                return sample
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    # 폴백: /proc/net/snmp, /proc/net/netstat (키-값 두 줄 페어)
    for path in ("/proc/net/snmp", "/proc/net/netstat"):
        try:
            with open(path) as f:
                lines = f.readlines()
        except OSError:
            continue
        for i in range(0, len(lines) - 1, 2):
            hdr = lines[i].split()
            vals = lines[i + 1].split()
            if len(hdr) < 2 or len(vals) < 2 or hdr[0] != vals[0]:
                continue
            prefix = hdr[0].rstrip(":")
            for k, v in zip(hdr[1:], vals[1:]):
                key = f"{prefix}{k}" if prefix in ("Tcp", "Ip", "Udp", "Icmp") else f"{prefix}{k}"
                try:
                    sample.counters[key] = int(v)
                except ValueError:
                    pass
    return sample


# ---------------------------------------------------------------------------
# 알람 판정
# ---------------------------------------------------------------------------

class AlarmEngine:
    """롤링 윈도우 기반 이상 감지.

    각 지표에 대해 최근 N 개의 관측치를 유지하고, 중앙값을 baseline 으로 사용한다.
    baseline * multiplier 를 초과하면 알람을 발생시킨다.
    N 미달 상태에서는 알람을 발생시키지 않는다 (워밍업 구간).
    """

    def __init__(self, window: int = 60, warmup: int = 20) -> None:
        self.window = window
        self.warmup = warmup
        self.history: dict[str, deque[float]] = {}
        self.recent_alerts: deque[Alert] = deque(maxlen=200)
        self.last_alert_ts: dict[str, float] = {}
        self.cooldown = 10.0  # 초, 동일 지표 반복 알람 억제

    def _hist(self, name: str) -> deque[float]:
        h = self.history.get(name)
        if h is None:
            h = deque(maxlen=self.window)
            self.history[name] = h
        return h

    def observe(self, name: str, value: float) -> Optional[float]:
        """관측치를 넣고, warmup 이후이면 baseline(median)을 반환한다."""
        h = self._hist(name)
        h.append(value)
        if len(h) < self.warmup:
            return None
        # baseline 은 히스토리에서 현재값을 뺀 값들의 중앙값
        sorted_h = sorted(list(h)[:-1])
        return median(sorted_h) if sorted_h else None

    def check_ratio(
        self, name: str, value: float, multiplier: float, floor: float, severity: str, msg_fmt: str
    ) -> Optional[Alert]:
        baseline = self.observe(name, value)
        if baseline is None:
            return None
        if value < floor:
            return None
        threshold = max(floor, baseline * multiplier)
        if value <= threshold:
            return None
        now = time.time()
        if now - self.last_alert_ts.get(name, 0.0) < self.cooldown:
            return None
        self.last_alert_ts[name] = now
        alert = Alert(
            ts=now,
            severity=severity,
            msg=msg_fmt.format(value=value, baseline=baseline, threshold=threshold),
        )
        self.recent_alerts.appendleft(alert)
        return alert

    def check_absolute(
        self, name: str, value: float, threshold: float, severity: str, msg_fmt: str
    ) -> Optional[Alert]:
        now = time.time()
        if value < threshold:
            return None
        if now - self.last_alert_ts.get(name, 0.0) < self.cooldown:
            return None
        self.last_alert_ts[name] = now
        alert = Alert(ts=now, severity=severity, msg=msg_fmt.format(value=value, threshold=threshold))
        self.recent_alerts.appendleft(alert)
        return alert


def evaluate_alerts(
    engine: AlarmEngine,
    conn: ConnSample,
    rates: dict,
    src_top_share: float,
    prev_established: Optional[int],
    sys_stats: Optional[dict] = None,
) -> None:
    """지표별 알람 판정. 결과는 engine.recent_alerts 에 누적."""

    if sys_stats:
        cpu = sys_stats.get("cpu_pct", 0.0)
        if cpu >= 90:
            engine.check_absolute(
                "cpu_high", cpu, threshold=90.0, severity="CRIT",
                msg_fmt="CPU {value:.1f}% (>= {threshold:.0f}%)",
            )
        elif cpu >= 70:
            engine.check_absolute(
                "cpu_elev", cpu, threshold=70.0, severity="WARN",
                msg_fmt="CPU {value:.1f}% elevated",
            )
        mem_pct = sys_stats.get("mem_pct", 0.0)
        if mem_pct >= 90:
            engine.check_absolute(
                "mem_high", mem_pct, threshold=90.0, severity="CRIT",
                msg_fmt="메모리 사용률 {value:.0f}%",
            )
        load1 = sys_stats.get("load1", 0.0)
        ncpu = max(1, sys_stats.get("ncpu", 1))
        if load1 > 2.0 * ncpu:
            engine.check_absolute(
                "load_high", load1, threshold=2.0 * ncpu, severity="WARN",
                msg_fmt="load1 {value:.2f} (> 2x cores)",
            )

    engine.check_ratio(
        "syn_recv", conn.state_counts.get("SYN_RECV", 0),
        multiplier=5.0, floor=50, severity="CRIT",
        msg_fmt="SYN_RECV 급증: {value:.0f} (baseline {baseline:.1f}, >{threshold:.0f})",
    )

    engine.check_ratio(
        "passive_opens", rates.get("TcpPassiveOpens", 0.0),
        multiplier=5.0, floor=50, severity="CRIT",
        msg_fmt="PassiveOpens 급증: {value:.0f}/s (baseline {baseline:.1f}/s)",
    )

    for k in ("TcpExtListenOverflows", "TcpExtListenDrops", "TcpExtTCPReqQFullDrop"):
        v = rates.get(k, 0.0)
        engine.check_absolute(
            k, v, threshold=1.0, severity="CRIT",
            msg_fmt=f"{NSTAT_LABELS[k]} 증가: {{value:.1f}}/s (backlog 포화 신호)",
        )

    if rates.get("TcpExtSyncookiesSent", 0.0) > 0:
        engine.check_absolute(
            "syncookies", rates["TcpExtSyncookiesSent"],
            threshold=1.0, severity="WARN",
            msg_fmt="SyncookiesSent 발동: {value:.1f}/s (SYN flood 진행 중)",
        )

    est = conn.state_counts.get("ESTABLISHED", 0)
    tw = conn.state_counts.get("TIME_WAIT", 0)
    if est > 100 and tw / max(1, est) > 5.0:
        engine.check_absolute(
            "time_wait_ratio", tw / max(1, est),
            threshold=5.0, severity="WARN",
            msg_fmt="TIME_WAIT / ESTABLISHED = {value:.1f} (rapid churn 의심)",
        )

    if src_top_share > 0.3 and est > 200:
        engine.check_absolute(
            "top_source_share", src_top_share,
            threshold=0.3, severity="WARN",
            msg_fmt="단일 소스 IP 편중: 전체 ESTABLISHED 중 {value:.1%} 차지",
        )

    # half-open ratio: SYN_RECV / ESTABLISHED
    ho = conn.half_open_ratio()
    if est > 100 and ho > 0.5:
        engine.check_absolute(
            "half_open", ho, threshold=0.5, severity="CRIT",
            msg_fmt="half-open ratio {value:.2f} (SYN_RECV / ESTABLISHED)",
        )

    # accept queue near backlog
    for lport, curr, backlog in conn.listen_queues:
        if backlog > 0 and curr >= backlog * 0.8:
            engine.check_absolute(
                f"listenq_{lport}", curr, threshold=backlog * 0.8, severity="CRIT",
                msg_fmt=f"port {lport} accept queue {{value:.0f}}/{backlog} (>=80%)",
            )

    if sys_stats:
        rx_pps = sys_stats.get("net_rx_pps", 0.0)
        engine.check_ratio(
            "rx_pps", rx_pps,
            multiplier=5.0, floor=10_000, severity="CRIT",
            msg_fmt="RX pps 급증: {value:,.0f}/s (baseline {baseline:,.0f}/s)",
        )
        err = sys_stats.get("net_err", {})
        rx_drop = err.get("rx_drops", 0.0)
        if rx_drop > 0:
            engine.check_absolute(
                "rx_drops", rx_drop, threshold=1.0, severity="CRIT",
                msg_fmt="NIC rx_drop {value:.1f}/s (NIC 큐 오버런)",
            )
        rx_err = err.get("rx_errors", 0.0)
        if rx_err > 0:
            engine.check_absolute(
                "rx_errors", rx_err, threshold=1.0, severity="WARN",
                msg_fmt="NIC rx_error {value:.1f}/s",
            )
        ct_pct = sys_stats.get("conntrack_pct", 0.0)
        if ct_pct >= 80:
            engine.check_absolute(
                "conntrack", ct_pct, threshold=80.0, severity="CRIT",
                msg_fmt="conntrack 테이블 {value:.0f}% 사용 (신규 연결 거부 위험)",
            )
        softirq = sys_stats.get("softirq_pct", 0.0)
        if softirq >= 30:
            engine.check_absolute(
                "softirq", softirq, threshold=30.0, severity="WARN",
                msg_fmt="softirq CPU {value:.1f}% (NET_RX 단일 코어 병목 가능)",
            )

    # UDP 커널 카운터 기반 알람
    udp_rcv_err = rates.get("UdpRcvbufErrors", 0.0)
    if udp_rcv_err > 0:
        engine.check_absolute(
            "udp_rcvbuf", udp_rcv_err, threshold=1.0, severity="CRIT",
            msg_fmt="UdpRcvbufErrors {value:.1f}/s (애플리케이션이 UDP 수신 못 따라잡음)",
        )
    udp_snd_err = rates.get("UdpSndbufErrors", 0.0)
    if udp_snd_err > 0:
        engine.check_absolute(
            "udp_sndbuf", udp_snd_err, threshold=1.0, severity="WARN",
            msg_fmt="UdpSndbufErrors {value:.1f}/s (UDP 송신 병목)",
        )
    engine.check_ratio(
        "udp_noports", rates.get("UdpNoPorts", 0.0),
        multiplier=5.0, floor=20, severity="WARN",
        msg_fmt="UdpNoPorts {value:.0f}/s (반사/스캔 트래픽 의심)",
    )
    engine.check_ratio(
        "udp_in", rates.get("UdpInDatagrams", 0.0),
        multiplier=5.0, floor=1000, severity="CRIT",
        msg_fmt="UdpIn {value:,.0f}/s 급증 (baseline {baseline:,.0f}/s)",
    )
    ip_reasm_fails = rates.get("IpReasmFails", 0.0)
    if ip_reasm_fails >= 5:
        engine.check_absolute(
            "ip_reasm", ip_reasm_fails, threshold=5.0, severity="WARN",
            msg_fmt="IpReasmFails {value:.1f}/s (fragmentation 공격 의심)",
        )


# ---------------------------------------------------------------------------
# 렌더러 - curses
# ---------------------------------------------------------------------------

class CursesRenderer:
    def __init__(self, stdscr, args) -> None:
        self.stdscr = stdscr
        self.args = args
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(200)
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_RED, -1)
        curses.init_pair(4, curses.COLOR_CYAN, -1)
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)
        self.C_OK = curses.color_pair(1)
        self.C_WARN = curses.color_pair(2)
        self.C_CRIT = curses.color_pair(3) | curses.A_BOLD
        self.C_HDR = curses.color_pair(4) | curses.A_BOLD
        self.C_ACC = curses.color_pair(5)

    def _safe_addstr(self, y, x, s, attr=0) -> None:
        try:
            self.stdscr.addstr(y, x, s, attr)
        except curses.error:
            pass

    def render(self, conn: ConnSample, rates: dict, alerts: deque, paused: bool,
               port_desc: str, age_size: int, uptime: float,
               sys_stats: Optional[dict] = None,
               proc_stats: Optional[dict] = None,
               udp: Optional["UdpSample"] = None,
               udp_drops_rate: float = 0.0,
               tracker_saturated: bool = False,
               tracker_rejected: int = 0) -> None:
        try:
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
        except curses.error:
            # 터미널 disconnect/resize 중이면 이 tick 은 skip 하고 다음에 재시도
            return

        # -- 헤더 --
        title = " DDoS Monitor "
        host = socket.gethostname()
        status = "PAUSED" if paused else "LIVE"
        hdr = (
            f"{title} host={host}  ports={port_desc}  interval={self.args.interval:.1f}s"
            f"  uptime={_fmt_dur(uptime)}  {status}"
        )
        self._safe_addstr(0, 0, hdr.ljust(w - 1), self.C_HDR)

        top_y = 1  # 다음 시스템 라인을 그릴 y 위치
        # -- 시스템 리소스 라인 1: CPU / Mem / Load --
        if sys_stats:
            cpu = sys_stats.get("cpu_pct", 0.0)
            softirq = sys_stats.get("softirq_pct", 0.0)
            ncpu = sys_stats.get("ncpu", 1)
            l1 = sys_stats.get("load1", 0.0)
            l5 = sys_stats.get("load5", 0.0)
            l15 = sys_stats.get("load15", 0.0)
            mem_used = sys_stats.get("mem_used_mb", 0)
            mem_total = sys_stats.get("mem_total_mb", 0)
            mem_pct = sys_stats.get("mem_pct", 0.0)

            cpu_attr = 0
            if cpu >= 70: cpu_attr = self.C_WARN
            if cpu >= 90: cpu_attr = self.C_CRIT
            softirq_attr = self.C_WARN if softirq >= 30 else 0
            mem_attr = 0
            if mem_pct >= 80: mem_attr = self.C_WARN
            if mem_pct >= 95: mem_attr = self.C_CRIT
            load_attr = self.C_WARN if l1 > ncpu else 0

            x = 0
            self._safe_addstr(top_y, x, "SYS  ", self.C_HDR); x += 5
            seg = f"CPU {cpu:5.1f}%  "; self._safe_addstr(top_y, x, seg, cpu_attr); x += len(seg)
            seg = f"si {softirq:4.1f}%  "; self._safe_addstr(top_y, x, seg, softirq_attr); x += len(seg)
            seg = f"load {l1:.2f}/{l5:.2f}/{l15:.2f} (of {ncpu}c)  "
            self._safe_addstr(top_y, x, seg, load_attr); x += len(seg)
            seg = f"Mem {mem_used:,}/{mem_total:,}MB ({mem_pct:.0f}%)"
            self._safe_addstr(top_y, x, seg[: max(0, w - x - 1)], mem_attr)
            top_y += 1

            # -- 시스템 리소스 라인 2: NIC bps/pps/drops + conntrack --
            rx_bps = sys_stats.get("net_rx_bps", 0.0)
            tx_bps = sys_stats.get("net_tx_bps", 0.0)
            rx_pps = sys_stats.get("net_rx_pps", 0.0)
            tx_pps = sys_stats.get("net_tx_pps", 0.0)
            err = sys_stats.get("net_err", {}) or {}
            rx_drop = err.get("rx_drops", 0.0)
            rx_errs = err.get("rx_errors", 0.0)
            nic_desc = ",".join(sys_stats.get("nics", [])) or "-"
            ct_count = sys_stats.get("conntrack_count", 0)
            ct_max = sys_stats.get("conntrack_max", 0)
            ct_pct = sys_stats.get("conntrack_pct", 0.0)

            drop_attr = 0
            if rx_drop > 0 or rx_errs > 0:
                drop_attr = self.C_CRIT if rx_drop > 0 else self.C_WARN
            ct_attr = 0
            if ct_pct >= 80: ct_attr = self.C_WARN
            if ct_pct >= 95: ct_attr = self.C_CRIT

            x = 0
            self._safe_addstr(top_y, x, "NET  ", self.C_HDR); x += 5
            seg = f"{_fmt_bps(rx_bps)} rx / {_fmt_bps(tx_bps)} tx  "
            self._safe_addstr(top_y, x, seg); x += len(seg)
            seg = f"{_fmt_pps(rx_pps)} rx / {_fmt_pps(tx_pps)} tx  "
            self._safe_addstr(top_y, x, seg); x += len(seg)
            seg = f"drop {rx_drop:.1f}/s err {rx_errs:.1f}/s  "
            self._safe_addstr(top_y, x, seg, drop_attr); x += len(seg)
            if ct_max > 0:
                seg = f"conntrack {ct_count:,}/{ct_max:,} ({ct_pct:.0f}%)  "
                self._safe_addstr(top_y, x, seg, ct_attr); x += len(seg)
            seg = f"[{nic_desc}]"
            self._safe_addstr(top_y, x, seg[: max(0, w - x - 1)])
            top_y += 1

        # -- 프로세스 라인 (--pid/--pname 설정 시) --
        if proc_stats:
            pid = proc_stats.get("pid")
            pname = proc_stats.get("name", "?")
            pcpu = proc_stats.get("cpu_pct", 0.0)
            rss_mb = proc_stats.get("rss_mb", 0)
            threads = proc_stats.get("threads", 0)
            fds = proc_stats.get("num_fds", 0)
            vctx = proc_stats.get("voluntary_ctxt_rate", 0.0)
            nctx = proc_stats.get("nonvoluntary_ctxt_rate", 0.0)
            alive = proc_stats.get("alive", True)

            attr_dead = self.C_CRIT if not alive else 0
            pcpu_attr = self.C_WARN if pcpu >= 70 else 0
            if pcpu >= 90: pcpu_attr = self.C_CRIT

            x = 0
            self._safe_addstr(top_y, x, "PROC ", self.C_HDR); x += 5
            if not alive:
                self._safe_addstr(top_y, x, f"pid={pid} DEAD", attr_dead)
            else:
                seg = f"{pname}[{pid}]  "
                self._safe_addstr(top_y, x, seg); x += len(seg)
                seg = f"CPU {pcpu:5.1f}%  "
                self._safe_addstr(top_y, x, seg, pcpu_attr); x += len(seg)
                seg = f"RSS {rss_mb:,}MB  threads {threads}  fds {fds}  ctx v/nv {vctx:.0f}/{nctx:.0f}/s"
                self._safe_addstr(top_y, x, seg[: max(0, w - x - 1)])
            top_y += 1

        # -- 좌측: TCP 상태 --
        y = top_y + 1
        base_y = y
        self._safe_addstr(y, 0, "TCP States (filtered)", self.C_HDR); y += 1
        for name in STATE_ORDER:
            n = conn.state_counts.get(name, 0)
            attr = 0
            if name == "SYN_RECV" and n > 50:
                attr = self.C_WARN
            if name == "SYN_RECV" and n > 500:
                attr = self.C_CRIT
            self._safe_addstr(y, 2, f"{name:<12} {n:>10,}", attr)
            y += 1

        y += 1
        self._safe_addstr(y, 2,
            f"Filtered / Total : {conn.filtered_conns:>7,} / {conn.total_conns:>7,}"); y += 1
        est = conn.state_counts.get("ESTABLISHED", 0)
        share = conn.zero_queue_established / max(1, est)
        self._safe_addstr(y, 2,
            f"ESTAB (Rq=0,Sq=0): {conn.zero_queue_established:>7,}"
            f" ({share:>6.1%}) [heuristic]",
            self.C_WARN if share > 0.7 and est > 200 else 0,
        ); y += 1
        # half-open ratio
        ho = conn.half_open_ratio()
        ho_attr = 0
        if est > 100 and ho > 0.5: ho_attr = self.C_CRIT
        elif est > 100 and ho > 0.2: ho_attr = self.C_WARN
        self._safe_addstr(y, 2,
            f"half-open ratio  : {ho:>7.3f}  (SYN_RECV / ESTAB)", ho_attr); y += 1
        # 소스 다양성 (BoundedCounter saturated 시 HLL 추정치 함께 표시)
        uniq_ip = len(conn.src_ip_counts)
        uniq_sub = len(conn.src_subnet24_counts)
        ip_hll = conn.src_ip_hll.count()
        sub_hll = conn.src_subnet24_hll.count()
        div_attr = 0
        if conn.src_ip_counts.saturated:
            div_attr = self.C_WARN
            self._safe_addstr(y, 2,
                f"unique src IPs   : {uniq_ip:>7,}+ (HLL~{ip_hll:,})"
                f"  /24 subnets: {uniq_sub:,}+ (HLL~{sub_hll:,})", div_attr); y += 1
        else:
            self._safe_addstr(y, 2,
                f"unique src IPs   : {uniq_ip:>7,}  /24 subnets: {uniq_sub:,}"); y += 1
        if self.args.track_age:
            sat_note = ""
            attr = self.C_WARN if conn.long_idle_established > 200 else 0
            if tracker_saturated:
                sat_note = f"  SATURATED (rejected {tracker_rejected:,})"
                attr = self.C_CRIT
            self._safe_addstr(y, 2,
                f"Long-idle ESTAB  : {conn.long_idle_established:>7,}"
                f"  (age>={self.args.idle_age:.0f}s)  tracker={age_size:,}{sat_note}",
                attr,
            ); y += 1

        # LISTEN accept queue depth
        if conn.listen_queues:
            y += 1
            self._safe_addstr(y, 0, "LISTEN accept queue (curr / backlog)", self.C_HDR); y += 1
            for lport, curr, backlog in sorted(conn.listen_queues)[:8]:
                pct = curr / backlog if backlog else 0.0
                attr = 0
                if pct >= 0.5: attr = self.C_WARN
                if pct >= 0.8: attr = self.C_CRIT
                self._safe_addstr(y, 2,
                    f"port {lport:>5}: {curr:>6,} / {backlog:<6,}  ({pct:>6.1%})", attr); y += 1

        # -- 우측: 커널 카운터 delta (TCP + UDP 분리) --
        col2 = max(46, w // 2)
        y2 = base_y
        self._safe_addstr(y2, col2, "TCP counters (per second)", self.C_HDR); y2 += 1
        for key in NSTAT_KEYS_TCP:
            v = rates.get(key, 0.0)
            label = NSTAT_LABELS.get(key, key)
            attr = 0
            if key in COUNTER_NONZERO_WARN and v > 0:
                attr = self.C_CRIT
            elif v > 0 and key in ("TcpExtTCPAbortOnTimeout", "TcpExtEmbryonicRsts"):
                attr = self.C_WARN
            self._safe_addstr(y2, col2 + 2, f"{label:<18} {v:>10.1f}", attr)
            y2 += 1

        y2 += 1
        self._safe_addstr(y2, col2, "UDP / IP counters (per second)", self.C_HDR); y2 += 1
        for key in NSTAT_KEYS_UDP:
            v = rates.get(key, 0.0)
            label = NSTAT_LABELS.get(key, key)
            attr = 0
            if key in COUNTER_NONZERO_WARN and v > 0:
                attr = self.C_CRIT
            elif v > 0 and key in ("UdpNoPorts", "UdpInErrors", "IpReasmFails"):
                attr = self.C_WARN
            self._safe_addstr(y2, col2 + 2, f"{label:<18} {v:>10.1f}", attr)
            y2 += 1

        # -- UDP 소켓 상태 (필터된 로컬 포트) --
        if udp and udp.socket_count > 0:
            y += 1
            self._safe_addstr(y, 0, "UDP sockets (filtered)", self.C_HDR); y += 1
            self._safe_addstr(y, 2,
                f"sockets: {udp.socket_count:,}   "
                f"rx_queue total: {udp.total_rx_queue:,} bytes   "
                f"drops: {udp_drops_rate:.1f}/s",
                self.C_CRIT if udp_drops_rate > 0 else 0,
            ); y += 1
            # 상위 rx_queue 소켓
            top_rq = sorted(udp.sockets, key=lambda t: t[1], reverse=True)[:6]
            for lport, rxq, _drops in top_rq:
                if rxq == 0:
                    continue
                attr = self.C_WARN if rxq > 65536 else 0
                if rxq > 524288: attr = self.C_CRIT
                self._safe_addstr(y, 2,
                    f"port {lport:>5}: rx_queue {rxq:>10,} bytes", attr); y += 1

        # -- Top 소스 IPs + /24 --
        y = max(y, y2) + 1
        if y < h - 4:
            col_a = 0
            col_b = max(60, w // 2)
            self._safe_addstr(y, col_a, "Top source IPs (ESTAB)", self.C_HDR)
            self._safe_addstr(y, col_b, "Top /24 subnets (ESTAB)", self.C_HDR)
            y += 1
            total_est = max(1, sum(conn.src_ip_counts.values()))
            top_ips = conn.src_ip_counts.most_common(self.args.top)
            top_subs = conn.src_subnet24_counts.most_common(self.args.top)
            n = min(len(top_ips), len(top_subs), max(0, h - 4 - y))
            for i in range(max(len(top_ips), len(top_subs))):
                if y >= h - 4:
                    break
                if i < len(top_ips):
                    ip, cnt = top_ips[i]
                    pct = cnt / total_est
                    attr = 0
                    if pct > 0.3: attr = self.C_WARN
                    if pct > 0.6: attr = self.C_CRIT
                    self._safe_addstr(
                        y, col_a + 2,
                        f"{i+1:>2}. {ip:<38} {cnt:>7,} ({pct:>5.1%})", attr,
                    )
                if i < len(top_subs):
                    sub, cnt = top_subs[i]
                    pct = cnt / total_est
                    attr = self.C_WARN if pct > 0.3 else 0
                    self._safe_addstr(
                        y, col_b + 2,
                        f"{i+1:>2}. {sub:<24} {cnt:>7,} ({pct:>5.1%})", attr,
                    )
                y += 1

        # -- 포트별 분포 (한 줄에 요약) --
        if conn.dst_port_counts and y < h - 4:
            top_ports = conn.dst_port_counts.most_common(8)
            parts = [f"{p}:{c:,}" for p, c in top_ports]
            self._safe_addstr(y, 0, "Ports (ESTAB):  " + "  ".join(parts)[: w - 3], self.C_ACC)
            y += 1

        # -- 알람 (하단 3줄) --
        alert_y = max(y, h - 4)
        self._safe_addstr(alert_y, 0, "Alerts (recent)", self.C_HDR)
        for i, a in enumerate(list(alerts)[:2]):
            attr = self.C_CRIT if a.severity == "CRIT" else self.C_WARN
            ts = time.strftime("%H:%M:%S", time.localtime(a.ts))
            line = f"[{ts}] {a.severity} {a.msg}"
            self._safe_addstr(alert_y + 1 + i, 2, line[: w - 3], attr)

        # -- 도움말 --
        self._safe_addstr(
            h - 1, 0,
            " q: quit   p: pause   r: reset baseline   d: dump snapshot ".ljust(w - 1),
            curses.A_REVERSE,
        )
        try:
            self.stdscr.refresh()
        except curses.error:
            pass


def _fmt_dur(s: float) -> str:
    s = int(s)
    return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"


def _fmt_bps(bps: float) -> str:
    for unit, div in (("Gbps", 1e9), ("Mbps", 1e6), ("Kbps", 1e3)):
        if bps >= div:
            return f"{bps / div:6.2f} {unit}"
    return f"{bps:6.0f} bps"


def _fmt_pps(pps: float) -> str:
    for unit, div in (("Mpps", 1e6), ("Kpps", 1e3)):
        if pps >= div:
            return f"{pps / div:6.2f} {unit}"
    return f"{pps:6.0f} pps"


# ---------------------------------------------------------------------------
# JSON 모드
# ---------------------------------------------------------------------------

def json_line(conn: ConnSample, rates: dict, alerts: list[Alert],
              sys_stats: Optional[dict] = None,
              proc_stats: Optional[dict] = None,
              udp: Optional[UdpSample] = None,
              udp_drops_rate: float = 0.0,
              tracker_info: Optional[dict] = None) -> str:
    obj = conn.to_json()
    obj["rates"] = {NSTAT_LABELS.get(k, k): round(v, 3) for k, v in rates.items() if k in NSTAT_KEYS}
    obj["alerts"] = [{"ts": a.ts, "severity": a.severity, "msg": a.msg} for a in alerts]
    obj["host"] = socket.gethostname()
    if sys_stats:
        obj["sys"] = {
            "cpu_pct": round(sys_stats.get("cpu_pct", 0.0), 2),
            "softirq_pct": round(sys_stats.get("softirq_pct", 0.0), 2),
            "ncpu": sys_stats.get("ncpu", 1),
            "load": [sys_stats.get("load1", 0.0), sys_stats.get("load5", 0.0), sys_stats.get("load15", 0.0)],
            "mem_used_mb": sys_stats.get("mem_used_mb", 0),
            "mem_total_mb": sys_stats.get("mem_total_mb", 0),
            "mem_pct": round(sys_stats.get("mem_pct", 0.0), 1),
            "net_rx_bps": round(sys_stats.get("net_rx_bps", 0.0), 1),
            "net_tx_bps": round(sys_stats.get("net_tx_bps", 0.0), 1),
            "net_rx_pps": round(sys_stats.get("net_rx_pps", 0.0), 1),
            "net_tx_pps": round(sys_stats.get("net_tx_pps", 0.0), 1),
            "net_err": {k: round(v, 3) for k, v in (sys_stats.get("net_err") or {}).items()},
            "nics": sys_stats.get("nics", []),
            "conntrack_count": sys_stats.get("conntrack_count", 0),
            "conntrack_max": sys_stats.get("conntrack_max", 0),
            "conntrack_pct": round(sys_stats.get("conntrack_pct", 0.0), 2),
        }
    if proc_stats:
        obj["proc"] = proc_stats
    if udp is not None:
        u = udp.to_json()
        u["drops_rate"] = round(udp_drops_rate, 3)
        obj["udp"] = u
    if tracker_info is not None:
        obj["age_tracker"] = tracker_info
    return json.dumps(obj, ensure_ascii=False)


# ---------------------------------------------------------------------------
# 메인 루프
# ---------------------------------------------------------------------------

def parse_ports(spec: Optional[str]) -> tuple[Optional[int], Optional[int]]:
    if not spec:
        return None, None
    if "-" in spec:
        a, b = spec.split("-", 1)
        return int(a), int(b)
    p = int(spec)
    return p, p


def run(stdscr, args) -> None:
    port_min, port_max = parse_ports(args.ports)
    port_desc = args.ports if args.ports else "ALL"
    tracker = AgeTracker() if args.track_age else None
    engine = AlarmEngine(window=args.baseline_window, warmup=min(20, args.baseline_window // 3))

    nics = _pick_nics([n.strip() for n in args.nics.split(",") if n.strip()] if args.nics else None)

    renderer = CursesRenderer(stdscr, args) if not args.json else None

    log_fp = open(args.log, "a", buffering=1) if args.log else None
    if log_fp:
        log_fp.write(f"# ddos_monitor start ts={time.time()} host={socket.gethostname()}\n")

    start = time.time()
    paused = False
    prev_nstat: Optional[NstatSample] = None
    prev_sys: Optional[SysSample] = None
    prev_proc: Optional[ProcSample] = None
    prev_udp: Optional[UdpSample] = None
    prev_established: Optional[int] = None
    sys_stats: dict = {}
    proc_stats: dict = {}
    target_pid: Optional[int] = None
    udp_cur: Optional[UdpSample] = None
    udp_drops_rate: float = 0.0
    last_logged_alert_ts: float = 0.0

    try:
        while True:
            loop_start = time.time()

            if not paused:
                conn = scan_proc_tcp(
                    port_min, port_max,
                    age_tracker=tracker,
                    idle_age_threshold=args.idle_age,
                    ipv6=not args.no_ipv6,
                    src_track_limit=args.src_track_limit,
                )
                nstat_cur = read_nstat()
                sys_cur = read_sys(nics)
                udp_cur = scan_proc_udp(port_min, port_max, ipv6=not args.no_ipv6)
                if prev_udp is not None:
                    dt = max(1e-6, udp_cur.ts - prev_udp.ts)
                    udp_drops_rate = max(0.0, (udp_cur.total_drops - prev_udp.total_drops) / dt)
                else:
                    udp_drops_rate = 0.0
                prev_udp = udp_cur

                if prev_nstat is None:
                    rates = {}
                else:
                    rates = nstat_cur.delta_per_sec(prev_nstat)
                prev_nstat = nstat_cur

                if prev_sys is not None:
                    rx_bps, tx_bps = sys_cur.net_bps(prev_sys)
                    rx_pps, tx_pps = sys_cur.net_pps(prev_sys)
                    net_err = sys_cur.net_err_rate(prev_sys)
                    cpu_pct = sys_cur.cpu_pct(prev_sys)
                    softirq_pct = sys_cur.softirq_pct(prev_sys)
                else:
                    rx_bps = tx_bps = rx_pps = tx_pps = cpu_pct = softirq_pct = 0.0
                    net_err = {}

                mem_used_kb = max(0, sys_cur.mem_total_kb - sys_cur.mem_avail_kb)
                mem_pct = 100.0 * mem_used_kb / sys_cur.mem_total_kb if sys_cur.mem_total_kb else 0.0
                ct_pct = 100.0 * sys_cur.conntrack_count / sys_cur.conntrack_max if sys_cur.conntrack_max else 0.0
                sys_stats = {
                    "cpu_pct": cpu_pct,
                    "softirq_pct": softirq_pct,
                    "ncpu": sys_cur.ncpu,
                    "load1": sys_cur.load1,
                    "load5": sys_cur.load5,
                    "load15": sys_cur.load15,
                    "mem_used_mb": mem_used_kb // 1024,
                    "mem_total_mb": sys_cur.mem_total_kb // 1024,
                    "mem_pct": mem_pct,
                    "net_rx_bps": rx_bps,
                    "net_tx_bps": tx_bps,
                    "net_rx_pps": rx_pps,
                    "net_tx_pps": tx_pps,
                    "net_err": net_err,
                    "nics": nics,
                    "conntrack_count": sys_cur.conntrack_count,
                    "conntrack_max": sys_cur.conntrack_max,
                    "conntrack_pct": ct_pct,
                }

                # --pid / --pname 프로세스 모니터링
                if args.pid or args.pname:
                    if target_pid is None or not os.path.isdir(f"/proc/{target_pid}"):
                        target_pid = resolve_pid(args.pid, args.pname, args.pname_substring)
                        prev_proc = None
                    if target_pid:
                        proc_cur = read_proc(target_pid)
                        if proc_cur.alive:
                            pcpu = proc_cur.cpu_pct(prev_proc, prev_sys or sys_cur, sys_cur) if prev_proc else 0.0
                            if prev_proc is not None:
                                dt = max(1e-6, proc_cur.ts - prev_proc.ts)
                                vctx_rate = max(0.0, (proc_cur.voluntary_ctxt - prev_proc.voluntary_ctxt) / dt)
                                nctx_rate = max(0.0, (proc_cur.nonvoluntary_ctxt - prev_proc.nonvoluntary_ctxt) / dt)
                            else:
                                vctx_rate = nctx_rate = 0.0
                            proc_stats = {
                                "pid": proc_cur.pid,
                                "name": proc_cur.name,
                                "alive": True,
                                "cpu_pct": pcpu,
                                "rss_mb": proc_cur.rss_kb // 1024,
                                "vsize_mb": proc_cur.vsize_kb // 1024,
                                "threads": proc_cur.threads,
                                "num_fds": proc_cur.num_fds,
                                "voluntary_ctxt_rate": vctx_rate,
                                "nonvoluntary_ctxt_rate": nctx_rate,
                            }
                            prev_proc = proc_cur
                        else:
                            proc_stats = {"pid": target_pid, "alive": False}
                            target_pid = None
                            prev_proc = None
                    else:
                        proc_stats = {"pid": None, "alive": False, "name": args.pname or "?"}

                prev_sys = sys_cur

                est = conn.state_counts.get("ESTABLISHED", 0)
                top_share = 0.0
                if conn.src_ip_counts:
                    top_share = max(conn.src_ip_counts.values()) / max(1, sum(conn.src_ip_counts.values()))

                evaluate_alerts(engine, conn, rates, top_share, prev_established, sys_stats)
                prev_established = est

                if udp_drops_rate > 0:
                    engine.check_absolute(
                        "udp_sock_drops", udp_drops_rate, threshold=1.0, severity="CRIT",
                        msg_fmt="UDP 소켓 drops {value:.1f}/s (rx buffer 오버플로)",
                    )

                if tracker is not None and tracker.saturated:
                    engine.check_absolute(
                        "age_tracker_saturated", 1, threshold=1, severity="WARN",
                        msg_fmt=f"AgeTracker saturated (rejected {tracker.rejected_new:,} new keys) — long-idle 지표 불완전",
                    )

                if log_fp:
                    # 이 tick 에서 새로 발화된 알람만 기록 (중복 방지).
                    # recent_alerts 는 appendleft 되므로 앞쪽이 최신.
                    for a in engine.recent_alerts:
                        if a.ts <= last_logged_alert_ts:
                            break
                        log_fp.write(json.dumps({
                            "ts": a.ts, "severity": a.severity, "msg": a.msg
                        }) + "\n")
                    if engine.recent_alerts:
                        last_logged_alert_ts = engine.recent_alerts[0].ts

                if args.json:
                    tracker_info = None
                    if tracker is not None:
                        tracker_info = {
                            "size": len(tracker),
                            "max": tracker._max,
                            "saturated": tracker.saturated,
                            "rejected_new_total": tracker.rejected_new,
                        }
                    sys.stdout.write(json_line(conn, rates, list(engine.recent_alerts)[:5],
                                               sys_stats, proc_stats,
                                               udp_cur, udp_drops_rate,
                                               tracker_info) + "\n")
                    sys.stdout.flush()

            if renderer is not None:
                renderer.render(
                    conn,
                    rates,
                    engine.recent_alerts,
                    paused,
                    port_desc,
                    len(tracker) if tracker else 0,
                    time.time() - start,
                    sys_stats,
                    proc_stats if (args.pid or args.pname) else None,
                    udp_cur,
                    udp_drops_rate,
                    tracker.saturated if tracker else False,
                    tracker.rejected_new if tracker else 0,
                )

                # 키 입력 (interval 동안 나눠서 폴링)
                deadline = loop_start + args.interval
                while time.time() < deadline:
                    try:
                        ch = stdscr.getch()
                    except curses.error:
                        ch = -1
                    if ch == ord("q"):
                        return
                    elif ch == ord("p"):
                        paused = not paused
                    elif ch == ord("r"):
                        engine = AlarmEngine(
                            window=args.baseline_window,
                            warmup=min(20, args.baseline_window // 3),
                        )
                    elif ch == ord("d") and log_fp:
                        log_fp.write("# manual dump: " + json_line(
                            conn, rates, list(engine.recent_alerts)[:20]
                        ) + "\n")
                    time.sleep(0.05)
            else:
                # JSON 모드: 그냥 sleep
                elapsed = time.time() - loop_start
                if elapsed < args.interval:
                    time.sleep(args.interval - elapsed)
    finally:
        if log_fp:
            log_fp.write(f"# ddos_monitor stop ts={time.time()}\n")
            log_fp.close()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="EC2 애플리케이션 레벨 DDoS 실시간 모니터링",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "예시:\n"
            "  sudo ./ddos_monitor.py --ports 12010-12020 --interval 2\n"
            "  ./ddos_monitor.py --ports 12010-12020 --track-age --idle-age 30\n"
            "  ./ddos_monitor.py --ports 12010-12020 --pname gameserver --nics eth0\n"
            "  ./ddos_monitor.py --ports 12010-12020 --json > /var/log/ddos_mon.jsonl\n"
        ),
    )
    p.add_argument("--ports", help="로컬 포트 필터, 단일 (12010) 또는 범위 (12010-12020). 미지정 시 전체 소켓")
    p.add_argument("--interval", type=float, default=2.0, help="수집 주기(초). 기본 2s. DDoS 상황에서는 3-5s 권장")
    p.add_argument("--top", type=int, default=15, help="소스 IP 상위 N")
    p.add_argument("--baseline-window", type=int, default=60,
                   help="baseline 계산에 사용할 최근 관측치 개수 (interval 기준)")
    p.add_argument("--track-age", action="store_true",
                   help="ESTABLISHED 5-tuple 관찰 시각을 추적하여 long-idle 카운트 계산 (메모리 사용 증가)")
    p.add_argument("--idle-age", type=float, default=30.0,
                   help="--track-age 사용 시 idle 판정 임계 (초). Recv-Q=Send-Q=0 AND age>=threshold 인 연결")
    p.add_argument("--no-ipv6", action="store_true", help="/proc/net/tcp6 스캔 생략")
    p.add_argument("--nics", help="네트워크 사용량 집계에 포함할 NIC 목록 (콤마 구분). 미지정 시 lo 제외 전체")
    p.add_argument("--pid", type=int, help="특정 PID 의 CPU/RSS/threads/fd/ctx 모니터링")
    p.add_argument("--pname", help="프로세스 comm 으로 찾아 모니터링 (--pid 미지정 시).")
    p.add_argument("--pname-exact", action="store_true",
                   help="--pname 을 substring 이 아닌 exact match 로 검색 (기본 True 로 동작). 유지된 옵션.")
    p.add_argument("--pname-substring", action="store_true",
                   help="--pname 을 substring 매치로 검색 (여러 매치 시 최소 PID)")
    p.add_argument("--src-track-limit", type=int, default=DEFAULT_SRC_TRACK_LIMIT,
                   help=f"소스 IP / /24 카운터 상한 (기본 {DEFAULT_SRC_TRACK_LIMIT:,}). 상한 초과 시 신규 소스는 top-K 유지 목적으로 스킵되고 HLL 추정만 반영")
    p.add_argument("--json", action="store_true",
                   help="curses UI 대신 tick 마다 stdout 으로 JSON 1줄 출력 (파일/SIEM ingest 용)")
    p.add_argument("--log", help="알람 이벤트를 JSON Lines 로 기록할 파일 경로")
    args = p.parse_args(argv)

    if args.json:
        try:
            run(None, args)
        except KeyboardInterrupt:
            pass
        return 0

    try:
        curses.wrapper(run, args)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
