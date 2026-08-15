import os
import re
import socket
import time
import ipaddress
import concurrent.futures
from urllib.request import Request, urlopen

# Cloudflare 官方 IPv4 网段白名单
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

# 远程高质量 Cloudflare IP 数据源
SOURCES = [
    "https://raw.githubusercontent.com/ymyuuu/IPDB/main/bestcf.txt",
    "https://raw.githubusercontent.com/ip-scanner/cloudflare/master/clean-ips.txt",
    "https://raw.githubusercontent.com/vfarid/cf-clean-ips/main/list.txt",
    "https://www.cloudflare.com/ips-v4"
]

# 🇺🇸 Cloudflare 美国本土所有核心机房机场代码（IATA COLO）
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

def is_cloudflare_ip(ip_str):
    """严格校验是否为 Cloudflare 官方公网 IPv4"""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in CF_IPV4_NETWORKS)
    except ValueError:
        return False

def fetch_source_ips(url):
    """带超时与容错的远程源抓取"""
    ips = set()
    try:
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        with urlopen(req, timeout=8) as response:
            content = response.read().decode('utf-8', errors='ignore')
            matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
            for ip in matches:
                if is_cloudflare_ip(ip):
                    ips.add(ip)
        print(f"✅ 成功从 [{url}] 抓取并清洗出 {len(ips)} 个有效 CF 节点")
    except Exception as e:
        print(f"⚠️ 跳过异常源 [{url}]: {e}")
    return ips

def test_and_filter_us_ip(ip, timeout=2.0):
    """
    测速 + 美国机房（Colo）精准嗅探
    返回: (ip, latency_ms, colo_code) 或 (ip, None, None)
    """
    start_time = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 80))
        
        http_req = (
            f"GET /cdn-cgi/trace HTTP/1.1\r\n"
            f"Host: speed.cloudflare.com\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.sendall(http_req.encode('utf-8'))
        
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        
        latency_ms = (time.time() - start_time) * 1000
        
        # 提取机房代码 (如 colo=LAX)
        colo_match = re.search(r'colo=([A-Z]{3})', response)
        if colo_match:
            colo = colo_match.group(1)
            if colo in US_COLO_SET:
                return (ip, latency_ms, colo)
        
        return (ip, None, None)
    except Exception:
        return (ip, None, None)

def main():
    print("🚀 开始收集 Cloudflare 官方 IPv4 节点池...")
    all_raw_ips = set()

    for url in SOURCES:
        all_raw_ips.update(fetch_source_ips(url))

    print(f"\n📊 汇总去重后待测 IP 总量: {len(all_raw_ips)} 个")
    if not all_raw_ips:
        print("❌ 未获取到可用 IP，退出")
        return

    print("⚡ 启动 50 线程并发进行【延迟测速 + 美国机房嗅探】...")
    us_results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(test_and_filter_us_ip, ip): ip for ip in all_raw_ips}
        for future in concurrent.futures.as_completed(futures):
            ip, latency, colo = future.result()
            if latency is not None and colo is not None:
                us_results.append((ip, latency, colo))

    # 按延迟由低到高排序
    us_results.sort(key=lambda x: x[1])
    print(f"\n🎉 成功嗅探到纯美国 (US) 节点: {len(us_results)} 个")

    # 提取前 30 个最优且绝对唯一的美国 IP，并自动添加 🇺🇸美国01~30 备注
    seen_ips = set()
    best_us_ips = []
    
    for ip, latency, colo in us_results:
        if ip not in seen_ips:
            seen_ips.add(ip)
            tag_index = len(best_us_ips) + 1
            formatted_entry = f"{ip}#🇺🇸美国{tag_index:02d}"
            best_us_ips.append(formatted_entry)
            print(f"🇺🇸 [{formatted_entry}] ({colo}) 延迟: {latency:.1f}ms")
            
        if len(best_us_ips) >= 30:
            break

    # 写入文件
    output_path = "best-cf-ipv4.txt"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(best_us_ips) + "\n")

    print(f"\n💾 优选完成！已将最优的 {len(best_us_ips)} 个带备注的美国 IPv4 写入 {output_path}")

if __name__ == "__main__":
    main()
