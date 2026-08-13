import concurrent.futures
import ipaddress
import re
import sys
import time
import urllib3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import requests
from curl_cffi import requests as cf_requests

# 屏蔽 verify=False 产生的 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

try:
    from ip2region import util
    from ip2region.searcher import new_with_buffer
except ImportError:
    util = None
    new_with_buffer = None

if TYPE_CHECKING:
    from ip2region.searcher import Searcher
    from playwright.sync_api import Browser

# 11 个专业优选 IP 数据源
SOURCES: dict[str, str] = {
    'https://www.wetest.vip/page/cloudfront/address_v4.html': 'WeTest',
    'https://api.uouin.com/cloudflare.html': 'UOUIN',
    'https://bestcf.pages.dev/xinyitang3/ipv4.txt': 'Mia',
    'https://bestcf.pages.dev/tiancheng/all.txt': 'Tiancheng',
    'https://raw.githubusercontent.com/gslege/CloudflareIP/refs/heads/main/SG.txt': 'Gslege-SG',
    'https://raw.githubusercontent.com/gslege/CloudflareIP/refs/heads/main/DE.txt': 'Gslege-DE',
    'https://raw.githubusercontent.com/gslege/CloudflareIP/refs/heads/main/US.txt': 'Gslege-US',
    'https://raw.githubusercontent.com/ymyuuu/IPDB/refs/heads/main/BestCF/bestcfv4.txt': 'IPDB',
    'https://vps789.com/openApi/cfIpApi': 'VPS789',
    'https://api.4ce.cn/api/bestCFIP': 'vvhan',
    'https://ip.164746.xyz': 'https://ip.164746.xyz',
}

PORT: str = '443'
CHECK_HOST: str = 'check.proxyip.cmliussss.net'
HEADERS: dict[str, str] = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0',
}
IPV4_PATTERN: str = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
OUTPUT_FILE: Path = Path('best-cf-ipv4.txt')
XDB_URL: str = 'https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb'
XDB_FILE: Path = Path(__file__).resolve().parent / 'data' / 'ip2region_v4.xdb'
MAX_RETRIES: int = 3
RETRY_BACKOFF_FACTOR: float = 2.0


def _session() -> cf_requests.Session:
    """用于爬取源站数据的伪装 Chrome Session"""
    session = cf_requests.Session(impersonate='chrome')
    session.headers.update(HEADERS)
    return session


def fetch(session: cf_requests.Session, url: str, timeout: int = 15) -> str:
    last_err: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = session.get(url, timeout=timeout)
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            last_err = e
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF_FACTOR ** attempt)
    assert last_err is not None
    raise last_err


def extract_ipv4(text: str) -> set[str]:
    ips: set[str] = set()
    for match in re.finditer(IPV4_PATTERN, text):
        try:
            ip = ipaddress.ip_address(match.group())
            ips.add(str(ip))
        except ValueError:
            continue
    return ips


def _ensure_xdb() -> None:
    if XDB_FILE.exists():
        return
    XDB_FILE.parent.mkdir(parents=True, exist_ok=True)
    print(f'Downloading {XDB_URL} ...')
    with _session() as sess:
        resp = sess.get(XDB_URL, timeout=120)
        resp.raise_for_status()
        XDB_FILE.write_bytes(resp.content)


_searcher = None


def _get_searcher() -> 'Searcher':
    global _searcher
    if new_with_buffer is None:
        raise RuntimeError('ip2region 未安装')
    if _searcher is None:
        _ensure_xdb()
        _searcher = new_with_buffer(
            util.version_from_header(util.load_header_from_file(str(XDB_FILE))),
            util.load_content_from_file(str(XDB_FILE)),
        )
    return _searcher


def lookup_country(ip: str) -> str:
    try:
        region = _get_searcher().search(ip)
        code = region.split('|')[-1].strip()
        if re.fullmatch(r'[A-Z]{2}', code):
            return code
    except Exception:
        pass
    return 'XX'


def beijing_timestamp() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M')


_browser = None
_pw = None


def _get_browser() -> 'Browser':
    global _browser, _pw
    if sync_playwright is None:
        raise RuntimeError('Playwright 未安装')
    if _browser is None:
        _pw = sync_playwright().start()
        _browser = _pw.chromium.launch(headless=True)
    return _browser


def fetch_rendered(url: str, timeout: int = 30000) -> str:
    context = _get_browser().new_context(user_agent=HEADERS['User-Agent'])
    page = context.new_page()
    try:
        page.goto(url, wait_until='networkidle', timeout=timeout)
        return page.content()
    finally:
        context.close()


def collect_ips(session: cf_requests.Session) -> set[str]:
    all_ips: set[str] = set()
    tiers = [
        ('HTTP', lambda u: fetch(session, u)),
        ('Browser', fetch_rendered),
    ]
    for url, name in SOURCES.items():
        for label, fetcher in tiers:
            try:
                ips = extract_ipv4(fetcher(url))
            except Exception as e:
                print(f'  [{name}] {label} 尝试失败: {e}')
                continue
            if ips:
                all_ips.update(ips)
                print(f'  [{name}] {label} 成功抓取: {len(ips)} 个 IPv4')
                break
            print(f'  [{name}] {label}: 0 个 IP，尝试降级...')
        else:
            print(f'  [{name}] 所有模式均失败')
    return all_ips


def test_proxy_ip(ip: str, port: str = PORT, timeout: float = 2.5) -> bool:
    """高效极速版：检测 Cloudflare IP 是否可正常代理转发请求"""
    target_url = f"https://{ip}:{port}/"
    headers = {
        "Host": CHECK_HOST,
        "User-Agent": HEADERS["User-Agent"]
    }
    try:
        # 采用原生 requests 轻量高效发起 HTTPS 探测
        resp = requests.get(
            target_url,
            headers=headers,
            timeout=timeout,
            verify=False
        )
        if resp.status_code == 200:
            return True
    except Exception:
        pass
    return False


def verify_and_filter_us_ips(all_ips: set[str], target_count: int = 30) -> list[str]:
    _get_searcher()
    
    # 1. 过滤美国 IP
    us_ips = [ip for ip in all_ips if lookup_country(ip) == 'US']
    print(f'🇺🇸 识别到 {len(us_ips)} 个美国候选节点，开始做 C 段去重与可用性测速...')

    # 2. C 段网络打散策略
    seen_subnets = set()
    candidate_ips = []
    
    for ip in us_ips:
        c_subnet = '.'.join(ip.split('.')[:3])
        if c_subnet not in seen_subnets:
            seen_subnets.add(c_subnet)
            candidate_ips.append(ip)
            
    for ip in us_ips:
        if ip not in candidate_ips:
            candidate_ips.append(ip)

    # 3. 多线程并发测速
    valid_ips = []
    print(f'🌐 开始并发测试节点连通性 (目标精选 {target_count} 个)...\n')
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_ip = {executor.submit(test_proxy_ip, ip): ip for ip in candidate_ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                is_ok = future.result()
                if is_ok:
                    valid_ips.append(ip)
                    print(f'  ✅ [可用] {ip}:{PORT}')
                    if len(valid_ips) >= target_count:
                        print(f'\n🎉 已成功凑齐 {target_count} 个合格节点，结束测速！')
                        break
                else:
                    print(f'  ❌ [不可用] {ip}:{PORT}')
            except Exception:
                pass

    return valid_ips[:target_count]


def main() -> int:
    print('🚀 开始获取 Cloudflare 全网数据源...\n')
    session = _session()

    all_ips = collect_ips(session)
    if not all_ips:
        print('❌ 未抓取到任何 IP')
        return 1
    print(f'\n全网去重共得 {len(all_ips)} 个 IP')

    final_us_ips = verify_and_filter_us_ips(all_ips, target_count=30)

    if not final_us_ips:
        print('❌ 未检测到可用的美国节点')
        return 1

    tmp = OUTPUT_FILE.with_suffix('.tmp')
    timestamp = beijing_timestamp()
    
    # 按照 🇺🇸美国01、🇺🇸美国02...30 进行格式化输出
    with tmp.open('w', encoding='utf-8') as f:
        f.write(f'#{len(final_us_ips)} best US ips updated at {timestamp}\n')
        for idx, ip in enumerate(final_us_ips, 1):
            num_str = f"{idx:02d}"
            f.write(f'{ip}:{PORT}#🇺🇸美国{num_str}\n')
            
    tmp.replace(OUTPUT_FILE)
    print(f'\n✅ 成功将 {len(final_us_ips)} 个测速合格的美国节点写入 {OUTPUT_FILE}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
