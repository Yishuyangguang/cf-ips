import ipaddress
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from curl_cffi import requests as cf_requests

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


def filter_top_30_us_ips(all_ips: set[str]) -> list[str]:
    """仅保留美国 IP，并按照 C 段离散度精选 30 个最佳节点"""
    _get_searcher()

    # 1. 离线识别，筛选出所有美国 IP
    us_ips = [ip for ip in all_ips if lookup_country(ip) == 'US']
    print(f'🇺🇸 共识别到 {len(us_ips)} 个美国节点，开始进行 C 段打散精选...')

    # 2. 第一轮：每个 C 段 (x.x.x.0/24) 只保留 1 个代表 IP
    seen_subnets = set()
    selected_ips = []

    for ip in us_ips:
        c_subnet = '.'.join(ip.split('.')[:3])
        if c_subnet not in seen_subnets:
            seen_subnets.add(c_subnet)
            selected_ips.append(ip)
            if len(selected_ips) == 30:
                break

    # 3. 如果独立 C 段不足 30 个，进行第二轮补足（允许同 C 段最多 2 个 IP）
    if len(selected_ips) < 30:
        seen_counts = {'.'.join(ip.split('.')[:3]): 1 for ip in selected_ips}
        for ip in us_ips:
            if ip in selected_ips:
                continue
            c_subnet = '.'.join(ip.split('.')[:3])
            if seen_counts.get(c_subnet, 0) < 2:
                seen_counts[c_subnet] = seen_counts.get(c_subnet, 0) + 1
                selected_ips.append(ip)
                if len(selected_ips) == 30:
                    break

    return selected_ips


def main() -> int:
    print('🚀 开始获取 Cloudflare 全网数据源...\n')
    session = _session()

    all_ips = collect_ips(session)
    if not all_ips:
        print('❌ 未抓取到任何 IP')
        return 1
    print(f'\n全网去重共得 {len(all_ips)} 个 IP')

    print('🌐 本地离线识别美国节点并精选 30 个离散 C 段...')
    final_us_ips = filter_top_30_us_ips(all_ips)

    if not final_us_ips:
        print('❌ 未筛选到美国节点')
        return 1

    tmp = OUTPUT_FILE.with_suffix('.tmp')
    timestamp = beijing_timestamp()

    # 格式化输出带编号备注：🇺🇸美国01、🇺🇸美国02...30
    with tmp.open('w', encoding='utf-8') as f:
        f.write(f'#{len(final_us_ips)} best US ips updated at {timestamp}\n')
        for idx, ip in enumerate(final_us_ips, 1):
            num_str = f"{idx:02d}"
            f.write(f'{ip}:{PORT}#🇺🇸美国{num_str}\n')

    tmp.replace(OUTPUT_FILE)
    print(f'\n✅ 成功保存 {len(final_us_ips)} 个精选美国节点至 {OUTPUT_FILE}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
