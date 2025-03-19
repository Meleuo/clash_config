import dns.resolver
from geoip2.database import Reader
import re
import hashlib
import base64
import yaml
import json
import requests
import logging
from flask import Flask, request, jsonify
from flask_caching import Cache
from typing import List, Dict, Optional
import os

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 获取当前py文件目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 加载配置文件
def load_config() -> dict:
    """加载配置文件"""
    try:
        with open(f"{BASE_DIR}/config.yaml", 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"加载配置文件失败: {e}")
        return {}

config = load_config()

# 初始化 Flask 应用
app = Flask(__name__)

# 配置缓存
app.config['CACHE_TYPE'] = config['cache']['type']
app.config['CACHE_DIR'] = config['cache']['dir']
app.config['CACHE_DEFAULT_TIMEOUT'] = config['cache']['timeout']
cache = Cache(app)

def get_urlmd5(url: str) -> str:
    """生成URL的MD5哈希值"""
    return hashlib.md5(url.encode('utf-8')).hexdigest()

def get_nodes(url: str) -> Optional[List[Dict]]:
    """获取节点信息，支持缓存"""
    urlmd5 = get_urlmd5(url)
    
    # 尝试从缓存获取
    cached_data = cache.get(urlmd5)
    if cached_data:
        logger.info(f"从缓存中获取数据: {urlmd5}")
        return cached_data
    try:
        # 添加clash标志
        # url = f"{url}&flag=clash"
        
        # headers = {
        #     'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        # }
        
        # response = requests.get(url, allow_redirects=True, timeout=100)
        # response.raise_for_status()
        # 解码响应内容
        import subprocess   
        content = subprocess.check_output(f"curl -SsLk '{url}'", shell=True).decode("utf-8")
        content = f'{content}\n'
        proxies = yaml.safe_load(content).get('proxies', [])
        # 设置缓存
        cache.set(urlmd5, proxies, timeout=config['cache']['node_timeout'])
        return proxies
        
    except requests.exceptions.RequestException as e:
        logger.error(f"获取节点失败: {url}, 错误: {e}")
        return None
    except yaml.YAMLError as e:
        logger.error(f"解析YAML失败: {url}, 错误: {e}")
        return None
    except Exception as e:
        logger.error(f"获取节点失败: {url}, 错误: {e}")
        return None

def get_ip_by_dnspython(domain: str) -> Optional[str]:
    """使用dnspython解析域名获取IP地址"""
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, 'A')
        return answers[0].to_text()
    except Exception as e:
        logger.error(f"DNS解析失败: {domain}, 错误: {e}")
        return None

# 创建预定义的代理组模板
def create_proxy_group_template(country_list: List[str]) -> Dict:
    """创建预定义的代理组配置"""
    return {
        "🚀 地区选择": {"name": "🚀 地区选择", "type": "select", "proxies": country_list},
        "♻️ 自动选择": {
            "name": "♻️ 自动选择",
            "type": "url-test",
            "url": config['test_url'],
            "interval": config['test_interval'],
            "tolerance": config['test_tolerance'],
            "proxies": country_list
        },
        "🔯 故障转移": {"name": "🔯 故障转移", "type": "fallback", "url": "http://www.gstatic.com/generate_204", "interval": 180, "proxies": country_list},
        "🔮 负载均衡": {"name": "🔮 负载均衡", "type": "load-balance", "strategy": "consistent-hashing", "url": "http://www.gstatic.com/generate_204", "interval": 180, "proxies": country_list},
        "🎯 全球直连": {"name": "🎯 全球直连", "type": "select", "proxies": ["DIRECT", "🚀 节点选择", "♻️ 自动选择"]},
        "🛑 全球拦截": {"name": "🛑 全球拦截", "type": "select", "proxies": ["REJECT", "DIRECT"]},
        "🐟 漏网之鱼": {"name": "🐟 漏网之鱼", "type": "select", "proxies": ["DIRECT", "🚀 节点选择", "♻️ 自动选择"]}
    }

@app.route('/', methods=['GET'])
def index():
    """主路由处理函数"""
    try:
        # 获取并解码URL参数
        url_base64 = request.args.get('url')
        if not url_base64:
            return  ":)"
        logger.info(f"Get url_base64: {url_base64}")
        urls = base64.b64decode(url_base64).decode('utf-8').split('\n')
        logger.info(f"Get urls: {urls}")
        # 初始化数据结构
        data = {**config['clash'], "proxies": [], "proxy-groups": []}
        proxies_group = {}
        
        # 获取并处理节点
        nodes = []
        for url in urls:
            url = url.strip()
            if not url:
                continue
            # 提取出url 的一级域名
            url_domain = re.match(r'https?://(.*)/', url).group(1)
            print(f"Get url_domain:  {url_domain}")
            url_nodes = get_nodes(url)
            if url_nodes:
                # 把node的name 重写一下, 增加一个url 的二级域名
                # for node in url_nodes:
                #     node['name'] = f"{url_domain} - {node['name']}"
                nodes.extend(url_nodes)
                
                print(f"Get nodes:  {url} success, {len(url_nodes)} nodes")
            else:
                print(f"Get nodes:  {url} failed")
                print(f"Error: {url_nodes}")
                
        # 节点去重和过滤
        filtered_nodes = [
            node for node in nodes 
            if not any(kw in node['name'] for kw in config['exclude_keywords'])
        ]
        unique_nodes = list({json.dumps(node) for node in filtered_nodes})
        nodes = [json.loads(node) for node in unique_nodes]
        
        for i in nodes:
            _ip = i['server']
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', i['server']):
                _ip = get_ip_by_dnspython(i['server'])
            try:
                response = reader.country(_ip)
                # 修改: 保留name字段
                if not response.country.iso_code:
                    # print(response.country)
                    raise ValueError
                if not proxies_group.get(response.country.iso_code):
                    proxies_group[response.country.iso_code] = {'name': response.country.iso_code, 'type': 'url-test', 'url': 'http://www.gstatic.com/generate_204',
                                                                'interval': 300, 'tolerance': 50, 'proxies': []}
                proxies_group[response.country.iso_code]['proxies'].append(
                    i['name'])
            except:
                # print('其他')
                if not proxies_group.get('其他'):
                    proxies_group['其他'] = {'name': '其他', 'type': 'url-test', 'url': 'http://www.gstatic.com/generate_204',
                                           'interval': 300, 'tolerance': 50, 'proxies': []}
                proxies_group['其他']['proxies'].append(i['name'])
        # print(proxies_group,'---------')
        data['proxies'] = nodes

        # 创建预定义的代理组
        proxies_group_2 = create_proxy_group_template(list(proxies_group.keys()))
        data['proxy-groups'] = list(proxies_group_2.values()) + \
            list(proxies_group.values())
        _node_select = []
        for i in data['proxy-groups']:
            # print(i)
            if not any(_ex in i['name'] for _ex in ['漏网之鱼', '全球拦截', '全球直连']):  # 使用any函数简化代码
                _node_select.append(i['name'])

        data['proxy-groups'] = [
            {"name": "🚀 节点选择", "type": "select",
                "proxies": _node_select + [i['name'] for i in data['proxies']]}
        ] + data['proxy-groups']
        
        rules_yaml = requests.get('https://raw.githubusercontent.com/Meleuo/clash_config/refs/heads/master/rules.yaml').text
        data['rules'] = yaml.safe_load(rules_yaml)['rules']

        rule_providers_yaml = requests.get('https://raw.githubusercontent.com/Meleuo/clash_config/refs/heads/master/rule-providers.yaml').text
        data['rule-providers'] = yaml.safe_load(rule_providers_yaml)['rule-providers']

        return yaml.dump(data, allow_unicode=True)
        
    except Exception as e:
        logger.error(f"处理请求失败: {e}")
        return jsonify({"error": str(e)}), 500

# 初始化GeoIP2数据库
try:
    reader = Reader(f'{BASE_DIR}/GeoLite2-Country.mmdb')
except Exception as e:
    logger.error(f"加载GeoIP2数据库失败: {e}")
    reader = None

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=17894)
