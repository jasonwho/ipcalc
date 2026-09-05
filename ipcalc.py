#!/usr/bin/env python3
"""离线 IPv4 / IPv6 计算器，仅依赖 Python 标准库。"""

import argparse
import ipaddress as ip
import os
import shutil
import sys
import textwrap
import unicodedata


def address_type(address):
    """分类针对输入地址，不声称整个网段具有相同属性。"""
    special = (
        ("10.0.0.0/8", "私有地址 · RFC 1918"),
        ("172.16.0.0/12", "私有地址 · RFC 1918"),
        ("192.168.0.0/16", "私有地址 · RFC 1918"),
        ("100.64.0.0/10", "运营商共享地址 CGNAT · RFC 6598"),
        ("192.0.2.0/24", "文档示例地址 · RFC 5737"),
        ("198.51.100.0/24", "文档示例地址 · RFC 5737"),
        ("203.0.113.0/24", "文档示例地址 · RFC 5737"),
        ("198.18.0.0/15", "基准测试地址 · RFC 2544"),
        ("2001:db8::/32", "文档示例地址 · RFC 3849"),
        ("3fff::/20", "文档示例地址 · RFC 9637"),
        ("fc00::/7", "唯一本地地址 ULA · RFC 4193"),
        ("2001:2::/48", "基准测试地址 · RFC 5180"),
    )
    if address.is_unspecified:
        return "未指定地址"
    if address.is_loopback:
        return "环回地址"
    if address.is_multicast:
        return "组播地址"
    if address.is_link_local:
        return "链路本地地址"
    if address.version == 6 and address.ipv4_mapped:
        return "IPv4 映射地址 · " + address_type(address.ipv4_mapped)
    for cidr, label in special:
        network = ip.ip_network(cidr)
        if address.version == network.version and address in network:
            return label
    if address.version == 6 and address.is_site_local:
        return "站点本地地址"
    if address.is_reserved:
        return "保留地址"
    if address.is_global:
        return "全局地址"
    return "特殊用途 / 非全局地址"


def reverse_zone(network):
    step = 8 if network.version == 4 else 4
    if network.prefixlen % step:
        return "无单一对齐区域；需按反向 DNS 边界拆分或委派"
    count = network.prefixlen // step
    if network.version == 4:
        parts = str(network.network_address).split(".")[:count]
        suffix = "in-addr.arpa"
    else:
        parts = list(network.network_address.exploded.replace(":", "")[:count])
        suffix = "ip6.arpa"
    return ".".join(list(reversed(parts)) + [suffix])


def analyze(value):
    value = value.strip()
    if "%" in value:
        raise ValueError("请移除 IPv6 的接口作用域标识后重试")
    interface = ip.ip_interface(value)
    address, network = interface.ip, interface.network
    bits = 32 if address.version == 4 else 128
    total = network.num_addresses
    result = dict(
        input=value, address=address, network=network, bits=bits,
        host_bits=bits - network.prefixlen, total=total,
        first=network.network_address, last=network.broadcast_address,
        reverse_zone=reverse_zone(network), classification=address_type(address),
    )
    if address.version == 4:
        # /31 点对点和 /32 主机路由不扣除两端地址。
        ordinary = network.prefixlen < 31
        result.update(
            first_host=network.network_address + (1 if ordinary else 0),
            last_host=network.broadcast_address - (1 if ordinary else 0),
            usable=total - 2 if ordinary else total,
        )
    return result


class Terminal:
    def __init__(self):
        self.color = (sys.stdout.isatty() and "NO_COLOR" not in os.environ
                      and os.environ.get("TERM") != "dumb")
        self.width = max(32, min(shutil.get_terminal_size((100, 24)).columns, 110))

    def paint(self, value, code):
        return f"\033[{code}m{value}\033[0m" if self.color else str(value)

    def title(self, value):
        print("\n" + self.paint(value, "1;36"))
        print(self.paint("─" * self.width, "90"))

    def row(self, label, value, code="1;32"):
        # 中英文混排按显示宽度对齐；长值独占一行，避免 IPv6 列互相挤压。
        display_width = sum(2 if unicodedata.east_asian_width(c) in "WF" else 1
                            for c in label)
        prefix = "  " + label + " " * max(1, 23 - display_width)
        value = str(value)
        value_width = sum(2 if unicodedata.east_asian_width(c) in "WF" else 1
                          for c in value)
        if value_width + 25 > self.width:
            print(self.paint("  " + label, "97"))
            for line in textwrap.wrap(value, width=self.width - 4,
                                      break_on_hyphens=False):
                print("    " + self.paint(line, code))
        else:
            print(self.paint(prefix, "97") + self.paint(value, code))

    def bit_view(self, address, prefix):
        bits = f"{int(address):0{32 if address.version == 4 else 128}b}"
        group_size = 8 if address.version == 4 else 16
        groups_per_line = max(1, min(4, (self.width - 10) // (group_size + 1)))
        groups = []
        for start in range(0, len(bits), group_size):
            groups.append("".join(self.paint(bit, "1;36" if i < prefix else "33")
                                  for i, bit in enumerate(bits[start:start + group_size], start)))
        for start in range(0, len(groups), groups_per_line):
            print(f"  {start * group_size:03d}  " + " ".join(groups[start:start + groups_per_line]))
        # 关闭颜色后仍能准确读取前缀位置，含非 4 位对齐的 IPv6 前缀。
        self.row("位分界", f"前 {prefix} 位 = 网络位；后 {len(bits) - prefix} 位 = 主机位", "37")


def render(data):
    out = Terminal()
    a, n = data["address"], data["network"]
    out.title(f"IPv{a.version} 地址 / 网段分析")
    out.row("输入", data["input"])
    out.row("地址类型", data["classification"], "1;35")
    out.title("网络 Network")
    out.row("标准化网段", n)
    out.row("网络地址", n.network_address)
    out.row("前缀 / 主机位", f"/{n.prefixlen} / {data['host_bits']} bits")
    out.row("子网掩码", n.netmask)
    out.row("反掩码 / Wildcard", n.hostmask)
    out.row("首地址", data["first"], "1;35")
    out.row("末地址", data["last"], "1;35")
    out.row("地址总数", f"{data['total']:,}")
    if a.version == 4:
        out.row("广播地址", n.broadcast_address if n.prefixlen < 31 else "不适用")
        out.row("首个可用主机", data["first_host"], "1;35")
        out.row("末个可用主机", data["last_host"], "1;35")
        out.row("可用主机数", f"{data['usable']:,}")
        first_octet = int(a) >> 24
        cls = "A" if first_octet < 128 else "B" if first_octet < 192 else "C" if first_octet < 224 else "D" if first_octet < 240 else "E"
        out.row("地址分类", f"{cls}类地址")
    else:
        out.row("广播地址", "不适用")
        out.row("/64 子网数", f"{1 << (64 - n.prefixlen):,}"
                if n.prefixlen <= 64 else "0")
    out.title("地址表示 Representations")
    out.row("压缩格式", a.compressed)
    if a.version == 6:
        out.row("完整格式", a.exploded)
    out.row("十进制整数", int(a))
    out.row("十六进制", f"0x{int(a):0{data['bits'] // 4}x}")
    out.row("八进制", oct(int(a)))
    out.row("PTR 查询名称", a.reverse_pointer)
    if a.version == 6:
        out.title("接口信息 Interface")
        out.row("低 64 位", ":".join(a.exploded.split(":")[4:]))
        if a.is_multicast or a.is_unspecified or a.is_loopback or a.ipv4_mapped:
            out.row("请求节点组播", "不适用")
        else:
            solicited = ip.IPv6Address(int(ip.IPv6Address("ff02::1:ff00:0")) | (int(a) & 0xFFFFFF))
            out.row("请求节点组播", solicited)
        if a.ipv4_mapped:
            out.row("映射的 IPv4", a.ipv4_mapped)
    out.title("前缀位图")
    out.bit_view(a, n.prefixlen)
    print()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="离线分析 IPv4 / IPv6 地址或 CIDR 网段；终端自动着色。",
        epilog="示例：%(prog)s 192.168.1.130/26  |  %(prog)s 2001:db8::/48",
    )
    parser.add_argument("address", help="IPv4 / IPv6 地址，可带前缀；IPv4 也支持点分掩码")
    args = parser.parse_args(argv)
    try:
        data = analyze(args.address)
    except ValueError as error:
        parser.error(f"无效的 IP 地址或网段：{error}")
    render(data)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
