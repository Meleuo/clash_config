import dns.resolver
import socket
from geoip2.database import Reader
import re
import copy
import hashlib
import base64
import yaml
import json
import requests
from flask import Flask, request, jsonify
from flask_caching import Cache

# 获取当前py文件目录
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)

app.config['CACHE_TYPE'] = 'FileSystemCache'  # 指定缓存类型为文件系统
app.config['CACHE_DIR'] = '/tmp/clash_conf/'  # 指定缓存目录
app.config['CACHE_DEFAULT_TIMEOUT'] = 300  # 设置默认缓存超时时间（秒）

cache = Cache(app)


def get_urlmd5(url):
    md5 = hashlib.md5()
    md5.update(url.encode('utf-8'))
    return md5.hexdigest()


def get_nodes(url):
    urlmd5 = get_urlmd5(url)
    ce = cache.get(urlmd5)
    if ce:
        print(f"从缓存中获取数据: {urlmd5}")
        return ce
    url = f"{url}&flag=clash"
    result = requests.get(url, allow_redirects=True).text
    # 尝试使用 base64 解码
    proxies = yaml.safe_load(result).get('proxies', [])  # 添加默认值防止key不存在
    cache.set(urlmd5, proxies, timeout=300)
    return proxies


EX = ['剩余', '套餐', '官网', '流量', '群组']
PROXIES = {'name': '', 'type': 'url-test', 'url': 'http://www.gstatic.com/generate_204',
           'interval': 300, 'tolerance': 50, 'proxies': []}


@app.route('/', methods=['GET'])
def index():
    proxies_group = {}
    data = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "Rule",
        "log-level": "info",
        "external-controller": ":9090",
        "proxies": [],
        "proxy-groups": []
    }

    url_base64 = request.args.get('url')
    url = base64.b64decode(url_base64).decode('utf-8').split('\n')

    _nodes = []
    for i in url:
        _nodes.extend(get_nodes(i))
    # 去重
    nodes = []
    for i in _nodes:
        if not any(_ex in i['name'] for _ex in EX):  # 使用any函数简化代码
            nodes.append(i)

    _nodes = [json.dumps(i) for i in nodes]
    nodes = [json.loads(i) for i in list(set(_nodes))]
    for i in nodes:
        _ip = i['server']
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', i['server']):
            _ip = get_ip_by_dnspython(i['server'])
        try:
            response = reader.country(_ip)
            # 修改: 保留name字段
            proxy_group = PROXIES.copy()
            proxy_group['name'] = response.country.iso_code
            proxy_group['proxies'].append(i['name'])
            proxies_group.setdefault(response.country.iso_code, proxy_group)[
                'proxies'].append(i['name'])
        except:
            # 修改: 保留name字段
            proxy_group = PROXIES.copy()
            proxy_group['name'] = '其他'
            proxy_group['proxies'].append(i['name'])
            proxies_group.setdefault('其他', proxy_group)[
                'proxies'].append(i['name'])

    data['proxies'] = nodes

    # 创建预定义的代理组
    proxies_group_2 = {
        "🚀 地区选择": {"name": "🚀 地区选择", "type": "select", "proxies": [] + list(proxies_group.keys())},
        "♻️ 自动选择": {"name": "♻️ 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50, "proxies": [] + list(proxies_group.keys())},
        "🔯 故障转移": {"name": "🔯 故障转移", "type": "fallback", "url": "http://www.gstatic.com/generate_204", "interval": 180, "proxies": [] + list(proxies_group.keys())},
        "🔮 负载均衡": {"name": "🔮 负载均衡", "type": "load-balance", "strategy": "consistent-hashing", "url": "http://www.gstatic.com/generate_204", "interval": 180, "proxies": [] + list(proxies_group.keys())},
        "🎯 全球直连": {"name": "🎯 全球直连", "type": "select", "proxies": ["DIRECT", "🚀 节点选择", "♻️ 自动选择"]},
        "🛑 全球拦截": {"name": "🛑 全球拦截", "type": "select", "proxies": ["REJECT", "DIRECT"]},
        "🐟 漏网之鱼": {"name": "🐟 漏网之鱼", "type": "select", "proxies": ["DIRECT", "🚀 节点选择", "♻️ 自动选择"]}
    }
    # proxies_group_3 =  [
    #     {"name": "🚀 节点选择", "type": "select",
    #         "proxies": [i['name'] for i in nodes] + data['proxy-groups']}
    # ]
    data['proxy-groups'] = list(proxies_group_2.values()) + \
        list(proxies_group.values())
    _node_select = []
    for i in data['proxy-groups']:
        print(i['name'])
        if not any(_ex in i['name'] for _ex in ['漏网之鱼', '全球拦截', '全球直连']):  # 使用any函数简化代码
            _node_select.append(i['name'])

    data['proxy-groups'] = [
        {"name": "🚀 节点选择", "type": "select",
            "proxies": _node_select + [i['name'] for i in data['proxies']]}
    ] + data['proxy-groups']
    with open("rules.yaml", "r") as yaml_file:
        data['rules'] = yaml.safe_load(yaml_file)
    return yaml.dump(data, allow_unicode=True)


# 确保你的 GeoIP2 City 数据库文件路径是正确的

# 创建一个 Reader 对象
reader = Reader(f'{BASE_DIR}/GeoLite2-Country.mmdb')


def get_ip_by_dnspython(domain):
    try:
        # 创建一个DNS解析器对象
        resolver = dns.resolver.Resolver()
        # 使用解析器查询域名的A记录
        answers = resolver.resolve(domain, 'A')
        # 提取IP地址列表
        ip_list = [answer.to_text() for answer in answers][0]
        return ip_list
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
        # DNS解析失败
        return


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
