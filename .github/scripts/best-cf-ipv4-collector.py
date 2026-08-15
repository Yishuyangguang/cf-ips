import os
import re
import socket
import ssl
import time
import ipaddress
import concurrent.futures
from urllib.request import Request, urlopen

# 1. Cloudflare 官方 IPv4 网段白名单
CF_IPV4_NETWORKS = [
    ipaddress.ip_network('173.245.48.0/20'),
    ipaddress.ip_network('103.21.244.0/22'),
    ipaddress.ip_network('103.22.200.0/22'),
    ipaddress.ip_network('103.31.4.0/22'),
    ipaddress.ip_network('141.101.64.0/18'),
    ipaddress.ip_network('108.162.192.0/18'),
    ipaddress.ip_network('190.93.240.0/20'),
    ipaddress.ip_network('188.114.96.0/20'),
    ipaddress.ip_network('197.234.240.0/22'),
    ipaddress.ip_network('198.41.128.0/17'),
    ipaddress.ip_network('162.158.0.0/15'),
    ipaddress.ip_network('104.16.0.0/13'),
    ipaddress.ip_network('104.24.0.0/14'),
    ipaddress.ip_network('172.64.0.0/13'),
    ipaddress.ip_network('131.0.72.0/22')
]

# 2. 远程优质 Cloudflare IP 数据源
SOURCES = [
    "https://raw.githubusercontent.com/ymyuuu/IPDB/main/bestcf.txt",
    "https://raw.githubusercontent.com/ip-scanner/cloudflare/master/clean-ips.txt",
    "https://raw.githubusercontent.com/vfarid/cf-clean-ips/main/list.txt"
]

# 3. 🇺🇸 Cloudflare 美国本土核心机房机场代码（IATA COLO）
US_COLO_SET = {
    # 美西
    'LAX', 'SFO', 'SJC', 'SMF', 'SAN', 'SEA', 'PDX', 'PHX', 'LAS', 'SLC', 'DEN', 'BOI', 'RNO',
    # 美中
    'DFW', 'IAH', 'SAT', 'AUS', 'OKC', 'MCI', 'STL', 'ORD', 'MSP', 'IND', 'CMH', 'CLE', 'DTW', 'OMA', 'DSM', 'MEM', 'BNA',
    # 美东与美南
    'ATL', 'MIA', 'TPA', 'MCO', 'JAX', 'CLT', 'RDU', 'RIC', 'IAD', 'BWI', 'PHL', 'EWR', 'JFK', 'LGA', 'BOS', 'BDL', 'PIT', 'BUF',
    # 夏威夷与阿拉斯加
    'HNL', 'ANC'
}

# 4. 内置高可用保底 Anycast 官方种子池
BUILTIN_SEED_IPS = [
    "104.16.132.229", "104.16.133.229", "104.17.150.10", "104.18.20.100",
    "104.19.18.150", "104.20.45.8", "104.21.12.1", "104.22.3.99",
    "104.24.100.5", "104.25.15.6", "104.26.8.20", "104.27.180.12",
    "172.64.150.88", "172.65.20.1", "172.67.180.5", "162.159.130.1",
    "198.41.214.162", "198.41.215.162", "173.245.58.51", "173.245.59.51",
    "108.162.193.10", "108.162.194.10", "141.101.121.10", "141.101.122.10"
]

def is_cloudflare_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in CF_IPV4_NETWORKS)
    except ValueError:
        return False

def fetch_source_ips(url):
    ips = set()
    try:
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        with urlopen(req, timeout=6) as response:
            content = response.read().decode('utf-8', errors='ignore')
            matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
            for ip in matches:
                if is_cloudflare_ip(ip):
                    ips.add(ip)
        print(f"✅ 成功从 [{url}] 提取出 {len(ips)} 个有效 IP")
    except Exception as e:
        print(f"⚠️ 跳过失效源 [{url}]: {e}")
    return ips

def fast_tcp_check(ip, port=443, timeout=0.8):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.close()
        return ip
    except Exception:
        return None

def trace_us_node(ip, timeout=1.5):
    start_time = time.time()
    sock = None
    ssl_sock = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        ssl_sock = ctx.wrap_socket(sock, server_hostname="speed.cloudflare.com")
        ssl_sock.settimeout(timeout)
        ssl_sock.connect((ip, 443))

        req = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: curl/7.88.1\r\nConnection: close\r\n\r\n"
        ssl_sock.sendall(req.encode('utf-8'))

        data = ssl_sock.recv(4096).decode('utf-8', errors='ignore')
        latency_ms = (time.time() - start_time) * 1000

        if "colo=" in data:
            colo_match = re.search(r'colo=([A-Z]{3})', data)
            loc_match = re.search(r'loc=([A-Z]{2})', data)
            colo = colo_match.group(1) if colo_match else ""
            loc = loc_match.group(1) if loc_match else ""
            
            if colo in US_COLO_SET or loc == "US":
                return (ip, latency_ms, colo or loc)
        return (ip, None, None)
    except Exception:
        return (ip, None, None)
    finally:
        if ssl_sock:
            try: ssl_sock.close()
            except: pass
        elif sock:
            try: sock.close()
            except: pass

def main():
    print("🚀 开始收集 Cloudflare 官方 IPv4 节点池...")
    all_raw_ips = set(BUILTIN_SEED_IPS)

    for url in SOURCES:
        all_raw_ips.update(fetch_source_ips(url))

    print(f"\n📊 汇总去重后待测 IP 总量: {len(all_raw_ips)} 个")

    # 1. 快速 TCP 粗筛
    print("⚡ 启动 60 线程进行极速 TCP 探活粗筛...")
    alive_ips = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as executor:
        futures = [executor.submit(fast_tcp_check, ip) for ip in all_raw_ips]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                alive_ips.append(res)

    print(f"🎉 存活节点数: {len(alive_ips)} 个，进入 TLS 美国机房深度嗅探...")

    # 2. 深度 Trace 嗅探与测速
    us_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(trace_us_node, ip): ip for ip in alive_ips}
        for f in concurrent.futures.as_completed(futures):
            ip, latency, colo = f.result()
            if latency is not None and colo is not None:
                us_results.append((ip, latency, colo))

    # 按真实延迟升序排序
    us_results.sort(key=lambda x: x[1])
    print(f"\n🇺🇸 成功嗅探到纯正美国节点: {len(us_results)} 个")

    # 3. C 段网段打散算法（每个 /24 子网最多取 2 个 IP）
    subnet_count = {}
    best_us_ips = []
    seen_ips = set()

    for ip, latency, colo in us_results:
        if ip in seen_ips:
            continue

        c_subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        count = subnet_count.get(c_subnet, 0)
        
        if count < 2:
            seen_ips.add(ip)
            subnet_count[c_subnet] = count + 1
            tag_idx = len(best_us_ips) + 1
            formatted_entry = f"{ip}#🇺🇸美国{tag_idx:02d}"
            best_us_ips.append(formatted_entry)
            print(f"  └─ [{formatted_entry}] ({colo} 机房) 延迟: {latency:.1f}ms")

        if len(best_us_ips) >= 30:
            break

    # 4. 写入根目录下的 best-cf-ipv4.txt
    output_path = "best-cf-ipv4.txt"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(best_us_ips) + "\n")

    print(f"\n💾 优选完成！已将最优的 {len(best_us_ips)} 个美国 IPv4 写入 {output_path}")

if __name__ == "__main__":
    main()
