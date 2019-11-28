# -*- coding:utf-8 -*-
from __future__ import unicode_literals
import time
import pyecharts.options as opts
from pyecharts.charts import Pie
import re
from urllib.parse import urlparse
import masscan
import requests
import socket
import datetime
ImgTxt = '-'.join(str(datetime.datetime.now()).replace(' ','-').replace(':','-').split('.')[0].split('-'))+'.txt'
ImgHtml = '-'.join(str(datetime.datetime.now()).replace(' ','-').replace(':','-').split('.')[0].split('-'))+'.html'

def Log(x):
    with open('../LangNetWorkTopoLog.txt','a+',encoding='utf-8')as a:
        a.write(str( '-'.join(str(datetime.datetime.now()).replace(' ','-').replace(':','-').split('.')[0].split('-')))+'    '+x+'\n')

from concurrent.futures import ThreadPoolExecutor
requests.packages.urllib3.disable_warnings()
Alive_Status = [200,301,302,400,404]

def get_title(r):
    title = '获取失败'
    try:
        title_pattern = b'<title>(.*?)</title>'
        title = re.search(title_pattern, r, re.S | re.I).group(1)
        try:
            title = title.decode().replace('\n', '').strip()
            return title
        except:
            try:
                title = title.decode('gbk').replace('\n', '').strip()
                return title
            except:
                return title
    except:
        return title
    finally:
        return title
def Requests(url):
    headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36'}
    url1 = 'http://'+url
    url2 = 'https://'+url
    title = '获取失败'
    title1 = '获取失败'
    title2 = '获取失败'
    content1 = None
    content2 = None
    try:
        r = requests.get(url='http://'+url,headers=headers,verify=False,timeout=20)
        if b'text/html' in r.content or b'<title>' in r.content or b'</html>' in r.content:
            content1 = r.content
        if r.status_code in Alive_Status:
            u = urlparse(str(r.url))
            title1 = get_title(r.content)
            url1 = u.scheme + '://' + u.netloc
    except Exception as e:
        pass
    try:
        r = requests.get(url='https://'+url,headers=headers,verify=False,timeout=20)
        if b'text/html' in r.content or b'<title>' in r.content or b'</html>' in r.content:
            content2 = r.content
        if r.status_code in Alive_Status:
            u = urlparse(str(r.url))
            title2 = get_title(r.content)
            url2 = u.scheme + '://' + u.netloc
    except Exception as e:
        pass
    if title1 != '获取失败':
        return {url1: title1}
    if title2 != '获取失败':
        return {url2: title2}
    if content1 != None:
        return {url1:title}
    if content2 != None:
        return {url2:title}

def Get_Alive_Url(urls):
    '''
    如果想要获取 IP 段内存活web服务
        hosts = IPy.IP('118.24.1.0/24')
        urls = []
        for host in hosts:
            urls.append('http://{}:{}'.format(host,80))
            urls.append('https://{}:{}'.format(host,443))
        Get_Alive_Url(urls)
        返回结果是一个列表，列表内数据为字典 多个自带你 {网址：标题}
    '''
    with ThreadPoolExecutor(max_workers=8) as p:
        future_tasks = [p.submit(Requests, i) for i in urls]
    result = [obj.result() for obj in future_tasks if obj.result() is not None]
    return result


from tinydb import TinyDB, where
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware
from collections import namedtuple
import os
Port = namedtuple("Port", ["name", "port", "protocol", "description"])

__BASE_PATH__ = os.path.dirname(os.path.abspath(__file__))
__DATABASE_PATH__ = os.path.join(__BASE_PATH__, 'ports.json')
__DB__ = TinyDB(__DATABASE_PATH__, storage=CachingMiddleware(JSONStorage))


def GetPortInfo(port, like=False):
    """
    判断端口服务，传入参数为 字符串类型的数字
    返回服务名称  'http'，没有则返回  '检测失效'

    """
    where_field = "port" if port.isdigit() else "name"
    if like:
        ports = __DB__.search(where(where_field).search(port))
    else:
        ports = __DB__.search(where(where_field) == port)
    try:
        return ports[0]['name']  # flake8: noqa (F812)
    except:
        return '识别端口异常'



class IpInfoScan:
    def __init__(self,ip):
        self.ip = ip
        # 传入的数据是网段哦  192.168.0.0/24
        self.Banner = {b'http': [b'^HTTP/.*\nServer: Apache/2',b'HTTP/'], b'ssh': [b'^SSH-.*openssh'], b'netbios': [b'\xc2\x83\x00\x00\x01\xc2\x8f'], b'backdoor-fxsvc': [b'^500 Not Loged in'], b'backdoor-shell': [b'^sh[$#]'], b'bachdoor-shell': [b'[a-z]*sh: .* command not found'], b'backdoor-cmdshell': [b'^Microsoft Windows .* Copyright .*>'], b'db2': [b'.*SQLDB2RA'], b'db2jds': [b'^N\x00'], b'dell-openmanage': [b'^N\x00\r'], b'finger': [b'finger: GET: '], b'ftp': [b'^220 .* UserGate'], b'http-iis': [b'^<h1>Bad Request .Invalid URL.</h1>'], b'http-jserv': [b'^HTTP/.*Cookie.*JServSessionId'], b'http-tomcat': [b'.*Servlet-Engine'], b'http-weblogic': [b'^HTTP/.*Cookie.*WebLogicSession'], b'http-vnc': [b'^HTTP/.*RealVNC/'], b'ldap': [b'^0E'], b'smb': [b'^\x00\x00\x00.\xc3\xbfSMBr\x00\x00\x00\x00.*'], b'msrdp': [b'^\x03\x00\x00\x0b\x06\xc3\x90\x00\x004\x12\x00'], b'msrdp-proxy': [b'^nmproxy: Procotol byte is not 8\n$'], b'msrpc': [b'\x05\x00\r\x03\x10\x00\x00\x00\x18\x00\x00\x00....\x04\x00\x01\x05\x00\x00\x00\x00$'], b'mssql': [b';MSSQLSERVER;'], b'telnet': [b'^\xc3\xbf\xc3\xbe'], b'mysql': [b"whost '"], b'mysql-blocked': [b'^\\(\x00\x00'], b'mysql-secured': [b'this MySQL'], b'mongodb': [b'^.*version.....([\\.\\d]+)'], b'nagiosd': [b'Sorry, you \\(.*are not among the allowed hosts...'], b'nessus': [b'< NTP 1.2 >\nUser:'], b'oracle-tns-listener': [b'\\(ADDRESS=\\(PROTOCOL='], b'oracle-dbsnmp': [b'^\x00\x0c\x00\x00\x04\x00\x00\x00\x00'], b'oracle-https': [b'^220- ora'], b'oracle-rmi': [b'^N\x00\t'], b'postgres': [b'^EFATAL'], b'rlogin': [b'^\x01Permission denied.\n'], b'rpc-nfs': [b'^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00'], b'rpc': [b'^\xc2\x80\x00\x00'], b'rsync': [b'^@RSYNCD:.*'], b'smux': [b'^A\x01\x02\x00'], b'snmp-public': [b'public\xc2\xa2'], b'snmp': [b'A\x01\x02'], b'socks': [b'^\x05[\x00-\x08]\x00'], b'ssl': [b'^\x16\x03\x00..\x02...\x03\x00'], b'sybase': [b'^\x04\x01\x00'], b'tftp': [b'^\x00[\x03\x05]\x00'], b'uucp': [b'^login: password: '], b'vnc': [b'^RFB.*'], b'webmin': [b'^0\\.0\\.0\\.0:.*:[0-9]'], b'websphere-javaw': [b'^\x15\x00\x00\x00\x02\x02\n']}

    def GetOpenPort(self,inport,rate):
        HostInfos = {}
        try:
            mas = masscan.PortScanner()
            #mas.scan(self.ip,ports='21,22,23,25,80,81,88,8080,8888,999,9999,7000,1433,1521,3306,3389,6379,7001,27017,27018')
            # 这里简单的扫一下普通端口即可
            if inport == '0':
                mas.scan(self.ip,arguments='--rate {}'.format(rate))
            else:
                mas.scan(self.ip,ports=inport,arguments='--rate {}'.format(rate))
            Results = mas.scan_result['scan']
            AliveHosts = list(Results.keys())
            if AliveHosts != []:
                for k, v in Results.items():
                    HostInfos[str(k)] = list(v['tcp'].keys())
            return HostInfos
        except Exception as e:
            Log('扫描IP出现异常:{}'.format(str(e)))
            pass
        return HostInfos

    def GetOneIPorts(self,ip,inport,rate):
        try:
            mas = masscan.PortScanner()
            if inport == '0':
                mas.scan(self.ip,arguments='--rate {}'.format(rate))
            else:
                mas.scan(self.ip,ports=inport,arguments='--rate {}'.format(rate))
            OpenPorts = mas.scan_result['scan'][ip]['tcp'].keys()
        except Exception as e:
            Log('获取扫描IP端口结果异常:{}'.format(str(e)))
            return None
        return {ip:OpenPorts}

    def GetBannerServer(self,ip,port):
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((ip,int(port)))
            s.send(b'langzi\r\n')
            SocketRecv = (s.recv(1024))
            for k,v in self.Banner.items():
                for b in v:
                    banner = re.search(b,SocketRecv,re.I)
                    if banner:
                        return k.decode()
            return '获取失败'
        except Exception as e:
            # Log('向端口发起连接异常:{}'.format(str(e)))
            return '获取失败'
        finally:
            s.close()

    def GetPoerInfos(self,ip,lis):
        # 传入参数为 开放的端口列表 [80,8888,3389]
        PortInfos = {}
        for li in lis:
            server = self.GetBannerServer(ip,li)
            if server == '获取失败':
                server = self.GetBannerServer(ip, li)
            PortInfos[str(li)] = server

        if PortInfos != {}:
            for k,v in PortInfos.items():
                if v == '获取失败':
                    PortInfos[k] = GetPortInfo(str(k))
        return PortInfos

    def GetResult(self,inport,rate):
        results = []
        print('[{}]  端口扫描 : {}'.format(str(datetime.datetime.now()).split('.')[0], self.ip))
        Log('开始扫描IP:{}'.format(self.ip))
        if '-' in self.ip or '/' in self.ip:
            openports = self.GetOpenPort(inport,rate)
        else:
            openports = self.GetOneIPorts(self.ip,inport,rate)
        #openports = [80,3389]
        if openports != {} and openports != None:
            for k,v in openports.items():
                retuls = {}
                print('[{}]  主机 {} 开放端口 {} 个'.format(str(datetime.datetime.now()).split('.')[0], k,len(v)))
                Log('主机 {} 开放端口 {} '.format(k,str(v)))
                res = self.GetPoerInfos(k,v)
                # {'80': 'http', '3389': 'ms-wbt-server'}
                urls = []
                for port in v:
                    urls.append('{}:{}'.format(k, port))
                AliveUrls = Get_Alive_Url(urls)
                retuls['ip']=k
                retuls['alive']=True
                retuls['ports']=list(res.keys())
                retuls['server']=list(res.values())
                retuls['services']=res
                retuls['urls']=AliveUrls
                retuls['time']=str(datetime.datetime.now()).replace(' ','-').replace(':','-').split('.')[0]
                results.append(retuls)
        Log(str(results))
        return results


def WriteImgTxt(IPdata,filename):
    alivehosts = len(IPdata)
    openports = 0
    weburls = 0
    portdict = {}
    servicedict = {}
    for i in IPdata:
        weburls += (len(i.get('urls')))
        openports += (len(i.get('ports')))
        service = (i.get('services'))
        for k, v in service.items():
            portdict[k] = 0
            servicedict[v.upper()] = 0
    for i in IPdata:
        service = (i.get('services'))
        for k, v in service.items():
            portdict[k] = portdict[k] + 1
            servicedict[v.upper()] = servicedict[v.upper()] + 1
    inner_x_data = ["存活主机", "开放端口", "部署网站"]
    inner_y_data = [alivehosts, openports, weburls]
    inner_data_pair = [list(z) for z in zip(inner_x_data, inner_y_data)]
    mid_data_pair = list(portdict.items())

    outer_data_pair = list(servicedict.items())
    c=(
        Pie(init_opts=opts.InitOpts(width="1600px", height="800px"))
        .add(
            series_name="总体资产",
            data_pair=inner_data_pair,
            radius=[0, "20%"],
            label_opts=opts.LabelOpts(position="inner",formatter="{b}:{c}个"),
        )

            .add(
            series_name="开放端口",
            data_pair=mid_data_pair,
            radius=["25%", "50%"],
            label_opts=opts.LabelOpts(position="inner",formatter="端口:{b}|总数:{c}"),
        )

        .add(
            series_name="部署服务",
            radius=["55%", "80%"],
            data_pair=outer_data_pair,
            label_opts=opts.LabelOpts(formatter="{a}:{b}|占比:{d}%"),
        )
        .set_global_opts(legend_opts=opts.LegendOpts(pos_left="mid", orient="vertical"))
        .set_series_opts(
            tooltip_opts=opts.TooltipOpts(
                trigger="item", formatter="{a} <br/>{b}: {c} ({d}%)"
            )
        )
        .render(filename)
    )
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8')as a:
            res = re.search('<body>(.*?)</body>', a.read(), re.S | re.I).group(1)
        os.remove(filename)
        return res
    else:
        Log('生成效果图失败')


def CleanData(IPdata,txtfile,htmlfile):
    ImgData = WriteImgTxt(IPdata,txtfile)
    with open('../'+htmlfile,'a+',encoding='utf-8')as a:
        a.write('''
                <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>网络资产拓扑图</title>
        <link rel="stylesheet" href='https://cdn.bootcss.com/bootstrap/3.3.7/css/bootstrap-theme.min.css'>
        <link rel="stylesheet" href='https://cdn.bootcss.com/bootstrap/3.3.7/css/bootstrap.min.css'>
		 <script type="text/javascript" src="https://assets.pyecharts.org/assets/echarts.min.js"></script>
        </head>
		<h1> 网络资产拓扑图</h1><hr/>
        ''')
        a.write(ImgData)
        a.write('''
        			<hr />
			<h1> 网络资产详情表</h1><hr />
			<div class="col-md-3">
        ''')
        portips = {}
        serips = {}
        for i in IPdata:
            ports = i.get('ports')
            servs = i.get('server')
            for port in ports:
                portips[port] = []
            for serv in servs:
                serips[serv] = []
        for i in IPdata:
            ports = i.get('ports')
            servs = i.get('server')
            for port in ports:
                portips[port].append(i.get('ip'))
            for serv in servs:
                serips[serv].append(i.get('ip'))

        for k, v in serips.items():
            a.write('''
                            <div class="panel panel-default">
                    <div class="panel-body">
                         服务:{} 运行主机
                    </div></div>
            '''.format(k))
            for vv in v:
                a.write('''
                                            <div class="panel-footer">
                             {}
                        </div>
                '''.format(vv))
            a.write('<hr>')

        a.write('</div><div class="col-md-6">')
        for k in IPdata:
            ip = k.get('ip')
            ports = '|'.join(k.get('ports'))
            service = '|'.join(k.get('server'))
            weburls = k.get('urls')
            if weburls == []:
                weburl = '无部署网站'
            else:
                web = []
                for i in weburls:
                    for k1,v in i.items():
                        weburl = '<a href={}>{}</a>'.format(k1,v)
                        web.append(weburl)
                weburl = '<br>'.join(web)

            timen = k.get('time')
            a.write('''
            <div class="panel panel-primary">
               <div class="panel-heading">
                  主机:{}资产详情
               </div>
                <div class="panel-body">
                       <table class="table">
                  <tr><td>当前主机</td><td>{}</td></tr>
                  <tr><td>开放端口</td><td>{}</td></tr>
                  <tr><td>运行服务</td><td>{}</td></tr>
                  <tr><td>部署网站</td><td>{}</td></tr>
                  <tr><td>发现时间</td><td>{}</td></tr>
               </table>
                </div>
            </div>
            '''.format(ip,ip,ports,service,weburl,timen))
        a.write('''
                </div>
            </div>
			</div><div class="col-md-3">''')

        for k,v in portips.items():
            a.write('''
            				<div class="panel panel-default">
				    <div class="panel-body">
				         端口:{} 开放主机
				    </div></div>
            '''.format(k))
            for vv in v:
                a.write('''
                					        <div class="panel-footer">
					         {}
					    </div>
                '''.format(vv))
            a.write('<hr>')
        a.write('</div></body></html>')
if __name__ == '__main__':
    print('''

             _                           _
            | |                         (_)
            | |     __ _ _ __   __ _ _____
            | |    / _` | '_ \ / _` |_  / |
            | |___| (_| | | | | (_| |/ /| |
            |______\__,_|_| |_|\__, /___|_|
                                __/ |      
                               |___/       
                                           内网主机资产自动化拓扑
    ''')
    res = [
        {'ip': '118.24.1.227', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-14-39'},
        {'ip': '118.24.1.91', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-15-03'},
        {'ip': '118.24.1.107', 'alive': True, 'ports': ['25', '3389', '23'],
         'server': ['http', 'ms-wbt-server', 'http'], 'services': {'25': 'http', '3389': 'ms-wbt-server', '23': 'http'},
         'urls': [], 'time': '2019-11-17-11-15-25'},
        {'ip': '118.24.1.90', 'alive': True, 'ports': ['80', '22'], 'server': ['http', 'ssh'],
         'services': {'80': 'http', '22': 'ssh'}, 'urls': [{'http://118.24.1.90:80': 'Not Found'}],
         'time': '2019-11-17-11-15-26'},
        {'ip': '118.24.1.120', 'alive': True, 'ports': ['3306', '80'], 'server': ['mysql', 'http'],
         'services': {'3306': 'mysql', '80': 'http'}, 'urls': [{'http://118.24.1.120:80': '没有找到站点'}],
         'time': '2019-11-17-11-15-32'},
        {'ip': '118.24.1.123', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-15-53'},
        {'ip': '118.24.1.2', 'alive': True, 'ports': ['80', '21', '3389'], 'server': ['http', 'ftp', 'ms-wbt-server'],
         'services': {'80': 'http', '21': 'ftp', '3389': 'ms-wbt-server'},
         'urls': [{'http://118.24.1.2:80': 'PESCMS Team安装说明'}], 'time': '2019-11-17-11-16-15'},
        {'ip': '118.24.1.174', 'alive': True, 'ports': ['8080', '22'], 'server': ['http-alt', 'ssh'],
         'services': {'8080': 'http-alt', '22': 'ssh'}, 'urls': [], 'time': '2019-11-17-11-16-16'},
        {'ip': '118.24.1.28', 'alive': True, 'ports': ['25', '3389'], 'server': ['http', 'ms-wbt-server'],
         'services': {'25': 'http', '3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-16-38'},
        {'ip': '118.24.1.219', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-16-59'},
        {'ip': '118.24.1.160', 'alive': True, 'ports': ['21', '3306', '22', '80'],
         'server': ['ftp', 'db2jds', 'ssh', 'http'],
         'services': {'21': 'ftp', '3306': 'db2jds', '22': 'ssh', '80': 'http'},
         'urls': [{'http://118.24.1.160:80': '欢迎您使用OneinStack'}], 'time': '2019-11-17-11-17-00'},
        {'ip': '118.24.1.119', 'alive': True, 'ports': ['22', '80', '21', '8888', '3306'],
         'server': ['ssh', 'http', 'ftp', 'http', 'mysql'],
         'services': {'22': 'ssh', '80': 'http', '21': 'ftp', '8888': 'http', '3306': 'mysql'},
         'urls': [{'http://118.24.1.119:80': '没有找到站点'}, {'http://118.24.1.119:8888': '安全入口校验失败'}],
         'time': '2019-11-17-11-17-04'}, {'ip': '118.24.1.207', 'alive': True, 'ports': ['3389', '23', '25'],
                                          'server': ['ms-wbt-server', 'http', 'http'],
                                          'services': {'3389': 'ms-wbt-server', '23': 'http', '25': 'http'}, 'urls': [],
                                          'time': '2019-11-17-11-17-26'},
        {'ip': '118.24.1.231', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-17-47'},
        {'ip': '118.24.1.31', 'alive': True, 'ports': ['80', '3389'], 'server': ['http', 'ms-wbt-server'],
         'services': {'80': 'http', '3389': 'ms-wbt-server'}, 'urls': [{'http://118.24.1.31:80': 'IIS Windows Server'}],
         'time': '2019-11-17-11-18-09'},
        {'ip': '118.24.1.173', 'alive': True, 'ports': ['80', '3389'], 'server': ['http', 'ms-wbt-server'],
         'services': {'80': 'http', '3389': 'ms-wbt-server'},
         'urls': [{'http://118.24.1.173:80': 'IIS Windows Server'}], 'time': '2019-11-17-11-18-31'},
        {'ip': '118.24.1.205', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-18-52'},
        {'ip': '118.24.1.158', 'alive': True, 'ports': ['21', '3306', '3389', '80'],
         'server': ['mongodb', 'mysql', 'ms-wbt-server', 'http'],
         'services': {'21': 'mongodb', '3306': 'mysql', '3389': 'ms-wbt-server', '80': 'http'},
         'urls': [{'http://118.24.1.158:80': 'IIS Windows Server'}], 'time': '2019-11-17-11-19-18'},
        {'ip': '118.24.1.247', 'alive': True, 'ports': ['80', '22', '21'], 'server': ['http', 'ssh', 'ftp'],
         'services': {'80': 'http', '22': 'ssh', '21': 'ftp'}, 'urls': [{'http://118.24.1.247:80': 'error'}],
         'time': '2019-11-17-11-19-18'},
        {'ip': '118.24.1.170', 'alive': True, 'ports': ['8888', '3306', '22'], 'server': ['http', 'mysql', 'ssh'],
         'services': {'8888': 'http', '3306': 'mysql', '22': 'ssh'}, 'urls': [], 'time': '2019-11-17-11-19-19'},
        {'ip': '118.24.1.198', 'alive': True, 'ports': ['25', '3389', '8888'],
         'server': ['http', 'ms-wbt-server', 'ddi-tcp-1'],
         'services': {'25': 'http', '3389': 'ms-wbt-server', '8888': 'ddi-tcp-1'}, 'urls': [],
         'time': '2019-11-17-11-19-40'},
        {'ip': '118.24.1.109', 'alive': True, 'ports': ['80', '21'], 'server': ['http', 'ftp'],
         'services': {'80': 'http', '21': 'ftp'}, 'urls': [], 'time': '2019-11-17-11-19-41'},
        {'ip': '118.24.1.51', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-20-02'},
        {'ip': '118.24.1.159', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-20-24'},
        {'ip': '118.24.1.25', 'alive': True, 'ports': ['3389', '23', '25'], 'server': ['ms-wbt-server', 'http', 'http'],
         'services': {'3389': 'ms-wbt-server', '23': 'http', '25': 'http'}, 'urls': [], 'time': '2019-11-17-11-20-45'},
        {'ip': '118.24.1.50', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-21-06'},
        {'ip': '118.24.1.144', 'alive': True, 'ports': ['21', '3306', '22', '80'],
         'server': ['ftp', 'mysql', 'ssh', 'http'],
         'services': {'21': 'ftp', '3306': 'mysql', '22': 'ssh', '80': 'http'},
         'urls': [{'http://118.24.1.144:80': '成都圣都装饰官网|成都装修公司|成都别墅设计|成都装饰公司哪家好|成都装修公司|成都圣都'}],
         'time': '2019-11-17-11-21-07'},
        {'ip': '118.24.1.140', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-21-32'},
        {'ip': '118.24.1.45', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-21-53'},
        {'ip': '118.24.1.49', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-22-14'},
        {'ip': '118.24.1.92', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-22-36'},
        {'ip': '118.24.1.199', 'alive': True, 'ports': ['80', '1433', '3389'],
         'server': ['http', 'ms-sql-s', 'ms-wbt-server'],
         'services': {'80': 'http', '1433': 'ms-sql-s', '3389': 'ms-wbt-server'},
         'urls': [{'http://118.24.1.199:80': 'IIS7'}], 'time': '2019-11-17-11-22-57'},
        {'ip': '118.24.1.137', 'alive': True, 'ports': ['6379', '22'], 'server': ['redis', 'ssh'],
         'services': {'6379': 'redis', '22': 'ssh'}, 'urls': [], 'time': '2019-11-17-11-23-18'},
        {'ip': '118.24.1.238', 'alive': True, 'ports': ['25', '3389'], 'server': ['http', 'ms-wbt-server'],
         'services': {'25': 'http', '3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-23-39'},
        {'ip': '118.24.1.56', 'alive': True, 'ports': ['22', '80'], 'server': ['ssh', 'http'],
         'services': {'22': 'ssh', '80': 'http'}, 'urls': [{'http://118.24.1.56:80': '悟空源码分享网'}],
         'time': '2019-11-17-11-23-39'},
        {'ip': '118.24.1.35', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-24-01'},
        {'ip': '118.24.1.148', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-24-22'},
        {'ip': '118.24.1.184', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-24-44'},
        {'ip': '118.24.1.79', 'alive': True, 'ports': ['3389', '8080', '80'],
         'server': ['ms-wbt-server', 'http', 'http'],
         'services': {'3389': 'ms-wbt-server', '8080': 'http', '80': 'http'},
         'urls': [{'http://118.24.1.79:80': '欢迎来到梦幻小翻班'}], 'time': '2019-11-17-11-25-05'},
        {'ip': '118.24.1.142', 'alive': True, 'ports': ['3389', '8888', '25'],
         'server': ['ms-wbt-server', 'ddi-tcp-1', 'http'],
         'services': {'3389': 'ms-wbt-server', '8888': 'ddi-tcp-1', '25': 'http'}, 'urls': [],
         'time': '2019-11-17-11-25-27'},
        {'ip': '118.24.1.181', 'alive': True, 'ports': ['80', '3389'], 'server': ['http', 'ms-wbt-server'],
         'services': {'80': 'http', '3389': 'ms-wbt-server'}, 'urls': [{'http://118.24.1.181:80': '易直买后台管理系统'}],
         'time': '2019-11-17-11-25-48'},
        {'ip': '118.24.1.83', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-26-09'},
        {'ip': '118.24.1.223', 'alive': True, 'ports': ['3389', '25', '23'],
         'server': ['ms-wbt-server', 'http', 'http'], 'services': {'3389': 'ms-wbt-server', '25': 'http', '23': 'http'},
         'urls': [], 'time': '2019-11-17-11-26-31'},
        {'ip': '118.24.1.103', 'alive': True, 'ports': ['80', '22'], 'server': ['http', 'ssh'],
         'services': {'80': 'http', '22': 'ssh'}, 'urls': [{'http://118.24.1.103:80': 'n-store'}],
         'time': '2019-11-17-11-26-31'},
        {'ip': '118.24.1.72', 'alive': True, 'ports': ['80', '3306', '22'], 'server': ['http', 'mysql', 'ssh'],
         'services': {'80': 'http', '3306': 'mysql', '22': 'ssh'}, 'urls': [{'http://118.24.1.72:80': '恒昌模具'}],
         'time': '2019-11-17-11-26-32'},
        {'ip': '118.24.1.168', 'alive': True, 'ports': ['22', '8888', '80', '3306', '21'],
         'server': ['ssh', 'http', 'http', 'mysql', 'ftp'],
         'services': {'22': 'ssh', '8888': 'http', '80': 'http', '3306': 'mysql', '21': 'ftp'},
         'urls': [{'http://118.24.1.168:8888': '拒绝访问'}, {'http://118.24.1.168:80': '没有找到站点'}],
         'time': '2019-11-17-11-26-38'},
        {'ip': '118.24.1.183', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-27-00'},
        {'ip': '118.24.1.125', 'alive': True, 'ports': ['80', '21', '3389'], 'server': ['http', 'ftp', 'ms-wbt-server'],
         'services': {'80': 'http', '21': 'ftp', '3389': 'ms-wbt-server'},
         'urls': [{'http://118.24.1.125:80': '站点创建成功-phpstudy for windows'}], 'time': '2019-11-17-11-27-21'},
        {'ip': '118.24.1.132', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-27-21'}, {'ip': '118.24.1.166', 'alive': True, 'ports': ['80', '8888', '21', '22'],
                                          'server': ['http', 'http', 'ftp', 'ssh'],
                                          'services': {'80': 'http', '8888': 'http', '21': 'ftp', '22': 'ssh'},
                                          'urls': [{'http://118.24.1.166:80': '没有找到站点'},
                                                   {'http://118.24.1.166:8888': '拒绝访问'}],
                                          'time': '2019-11-17-11-27-22'},
        {'ip': '118.24.1.176', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-27-22'},
        {'ip': '118.24.1.3', 'alive': True, 'ports': ['25', '23', '3389'], 'server': ['http', 'http', 'ms-wbt-server'],
         'services': {'25': 'http', '23': 'http', '3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-27-44'},
        {'ip': '118.24.1.23', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-28-06'},
        {'ip': '118.24.1.192', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-28-27'},
        {'ip': '118.24.1.108', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-28-48'},
        {'ip': '118.24.1.59', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-29-10'},
        {'ip': '118.24.1.10', 'alive': True, 'ports': ['21', '8888', '80', '22'],
         'server': ['ftp', 'http', 'http', 'ssh'], 'services': {'21': 'ftp', '8888': 'http', '80': 'http', '22': 'ssh'},
         'urls': [{'http://118.24.1.10:8888': '404 Not Found'}, {'http://118.24.1.10:80': '没有找到站点'}],
         'time': '2019-11-17-11-29-10'},
        {'ip': '118.24.1.33', 'alive': True, 'ports': ['3306', '80', '22'], 'server': ['mysql', 'http', 'ssh'],
         'services': {'3306': 'mysql', '80': 'http', '22': 'ssh'}, 'urls': [{'http://118.24.1.33:80': '朱大头'}],
         'time': '2019-11-17-11-29-12'},
        {'ip': '118.24.1.66', 'alive': True, 'ports': ['80', '22'], 'server': ['http', 'ssh'],
         'services': {'80': 'http', '22': 'ssh'}, 'urls': [{'http://118.24.1.66:80': 'Welcome to nginx!'}],
         'time': '2019-11-17-11-29-12'},
        {'ip': '118.24.1.64', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-29-12'},
        {'ip': '118.24.1.200', 'alive': True, 'ports': ['3389', '3306'], 'server': ['ms-wbt-server', 'mysql'],
         'services': {'3389': 'ms-wbt-server', '3306': 'mysql'}, 'urls': [], 'time': '2019-11-17-11-29-35'},
        {'ip': '118.24.1.129', 'alive': True, 'ports': ['80', '3306'], 'server': ['http', 'mysql'],
         'services': {'80': 'http', '3306': 'mysql'},
         'urls': [{'http://118.24.1.129:80': 'Apache2 Debian Default Page: It works'}], 'time': '2019-11-17-11-29-49'},
        {'ip': '118.24.1.67', 'alive': True, 'ports': ['80'], 'server': ['http'], 'services': {'80': 'http'},
         'urls': [{'http://118.24.1.67:80': 'Test Page for the Nginx HTTP Server on EPEL'}],
         'time': '2019-11-17-11-29-49'},
        {'ip': '118.24.1.189', 'alive': True, 'ports': ['3389', '25'], 'server': ['ms-wbt-server', 'http'],
         'services': {'3389': 'ms-wbt-server', '25': 'http'}, 'urls': [], 'time': '2019-11-17-11-30-11'},
        {'ip': '118.24.1.81', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-30-11'}, {'ip': '118.24.1.253', 'alive': True, 'ports': ['80', '1433', '3389'],
                                          'server': ['http', 'ms-sql-s', 'ms-wbt-server'],
                                          'services': {'80': 'http', '1433': 'ms-sql-s', '3389': 'ms-wbt-server'},
                                          'urls': [{'http://118.24.1.253:80': 'Not Found'}],
                                          'time': '2019-11-17-11-30-32'},
        {'ip': '118.24.1.130', 'alive': True, 'ports': ['8888', '80', '3389', '3306'],
         'server': ['ddi-tcp-1', 'http', 'ms-wbt-server', 'db2jds'],
         'services': {'8888': 'ddi-tcp-1', '80': 'http', '3389': 'ms-wbt-server', '3306': 'db2jds'},
         'urls': [{'http://118.24.1.130:8888': '入口校验失败'}, {'http://118.24.1.130:80': '山顶洞影院'}],
         'time': '2019-11-17-11-30-54'},
        {'ip': '118.24.1.29', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-31-16'},
        {'ip': '118.24.1.251', 'alive': True, 'ports': ['3306', '8080', '80'], 'server': ['db2jds', 'http', 'http'],
         'services': {'3306': 'db2jds', '8080': 'http', '80': 'http'},
         'urls': [{'http://118.24.1.251:8080': 'Apache Tomcat/7.0.64'},
                  {'http://118.24.1.251:80': 'Apache Tomcat/7.0.64'}], 'time': '2019-11-17-11-31-17'},
        {'ip': '118.24.1.114', 'alive': True, 'ports': ['80', '3306', '22'], 'server': ['http', 'mysql', 'ssh'],
         'services': {'80': 'http', '3306': 'mysql', '22': 'ssh'}, 'urls': [{'http://118.24.1.114:80': '没有找到站点'}],
         'time': '2019-11-17-11-31-17'}, {'ip': '118.24.1.116', 'alive': True, 'ports': ['3306', '22', '8080', '80'],
                                          'server': ['mysql', 'ssh', 'http', 'http'],
                                          'services': {'3306': 'mysql', '22': 'ssh', '8080': 'http', '80': 'http'},
                                          'urls': [{'http://118.24.1.116:8080': 'Welcome to nginx!'}, {
                                              'http://118.24.1.116:80': '&#x751F;&#x4EA7;&#x6570;&#x636E;&#x62A5;&#x9001;&#x7CFB;&#x7EDF;-&#x6E56;&#x5357;&#x7A7A;&#x6E2F;&#x5B9E;&#x4E1A;&#x80A1;&#x4EFD;&#x6709;&#x9650;&#x516C;&#x53F8;'}],
                                          'time': '2019-11-17-11-31-33'},
        {'ip': '118.24.1.20', 'alive': True, 'ports': ['3389', '23', '25'], 'server': ['ms-wbt-server', 'http', 'http'],
         'services': {'3389': 'ms-wbt-server', '23': 'http', '25': 'http'}, 'urls': [], 'time': '2019-11-17-11-31-57'},
        {'ip': '118.24.1.154', 'alive': True, 'ports': ['7000', '22'], 'server': ['afs3-fileserver', 'ssh'],
         'services': {'7000': 'afs3-fileserver', '22': 'ssh'}, 'urls': [], 'time': '2019-11-17-11-31-59'},
        {'ip': '118.24.1.222', 'alive': True, 'ports': ['21', '80', '3389'], 'server': ['ftp', 'http', 'ms-wbt-server'],
         'services': {'21': 'ftp', '80': 'http', '3389': 'ms-wbt-server'},
         'urls': [{'http://118.24.1.222:80': 'WAMPSERVER Homepage'}], 'time': '2019-11-17-11-32-20'},
        {'ip': '118.24.1.135', 'alive': True, 'ports': ['25', '8888', '3389'],
         'server': ['http', 'ddi-tcp-1', 'ms-wbt-server'],
         'services': {'25': 'http', '8888': 'ddi-tcp-1', '3389': 'ms-wbt-server'}, 'urls': [],
         'time': '2019-11-17-11-32-42'},
        {'ip': '118.24.1.229', 'alive': True, 'ports': ['3389', '7000'], 'server': ['ms-wbt-server', 'afs3-fileserver'],
         'services': {'3389': 'ms-wbt-server', '7000': 'afs3-fileserver'}, 'urls': [], 'time': '2019-11-17-11-33-04'},
        {'ip': '118.24.1.75', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-33-25'},
        {'ip': '118.24.1.76', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-33-25'},
        {'ip': '118.24.1.36', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-33-47'},
        {'ip': '118.24.1.239', 'alive': True, 'ports': ['23', '25', '3389'],
         'server': ['http', 'http', 'ms-wbt-server'], 'services': {'23': 'http', '25': 'http', '3389': 'ms-wbt-server'},
         'urls': [], 'time': '2019-11-17-11-34-07'},
        {'ip': '118.24.1.212', 'alive': True, 'ports': ['25', '8888', '3389'],
         'server': ['http', 'ddi-tcp-1', 'ms-wbt-server'],
         'services': {'25': 'http', '8888': 'ddi-tcp-1', '3389': 'ms-wbt-server'}, 'urls': [],
         'time': '2019-11-17-11-34-29'},
        {'ip': '118.24.1.164', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-34-29'},
        {'ip': '118.24.1.97', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-34-51'},
        {'ip': '118.24.1.178', 'alive': True, 'ports': ['21', '8888', '22', '80'],
         'server': ['ftp', 'http', 'ssh', 'http'], 'services': {'21': 'ftp', '8888': 'http', '22': 'ssh', '80': 'http'},
         'urls': [{'http://118.24.1.178:8888': '安全入口校验失败'}, {'http://118.24.1.178:80': '没有找到站点'}],
         'time': '2019-11-17-11-34-51'},
        {'ip': '118.24.1.190', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-35-13'},
        {'ip': '118.24.1.100', 'alive': True, 'ports': ['80', '21', '8888'], 'server': ['http', 'ftp', 'http'],
         'services': {'80': 'http', '21': 'ftp', '8888': 'http'},
         'urls': [{'http://118.24.1.100:80': '没有找到站点'}, {'http://118.24.1.100:8888': '安全入口校验失败'}],
         'time': '2019-11-17-11-35-13'},
        {'ip': '118.24.1.113', 'alive': True, 'ports': ['8080', '3389'], 'server': ['http', 'ms-wbt-server'],
         'services': {'8080': 'http', '3389': 'ms-wbt-server'},
         'urls': [{'http://118.24.1.113:8080': 'Apache Tomcat/9.0.8'}], 'time': '2019-11-17-11-35-35'},
        {'ip': '118.24.1.156', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-35-35'},
        {'ip': '118.24.1.80', 'alive': True, 'ports': ['8888', '80', '22'], 'server': ['http', 'http', 'ssh'],
         'services': {'8888': 'http', '80': 'http', '22': 'ssh'},
         'urls': [{'http://118.24.1.80:8888': '404 Not Found'}, {'http://118.24.1.80:80': '没有找到站点'}],
         'time': '2019-11-17-11-35-35'}, {'ip': '118.24.1.145', 'alive': True, 'ports': ['23', '3389', '25'],
                                          'server': ['http', 'ms-wbt-server', 'http'],
                                          'services': {'23': 'http', '3389': 'ms-wbt-server', '25': 'http'}, 'urls': [],
                                          'time': '2019-11-17-11-35-57'},
        {'ip': '118.24.1.54', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-35-57'},
        {'ip': '118.24.1.12', 'alive': True, 'ports': ['81', '80', '3389'], 'server': ['http', 'http', 'ms-wbt-server'],
         'services': {'81': 'http', '80': 'http', '3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-36-19'},
        {'ip': '118.24.1.70', 'alive': True, 'ports': ['3389', '25'], 'server': ['ms-wbt-server', 'http'],
         'services': {'3389': 'ms-wbt-server', '25': 'http'}, 'urls': [], 'time': '2019-11-17-11-36-40'},
        {'ip': '118.24.1.161', 'alive': True, 'ports': ['80', '22'], 'server': ['http', 'ssh'],
         'services': {'80': 'http', '22': 'ssh'}, 'urls': [{'http://118.24.1.161:80': 'LNMP一键安装包 by Licess'}],
         'time': '2019-11-17-11-36-40'},
        {'ip': '118.24.1.133', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-37-02'},
        {'ip': '118.24.1.43', 'alive': True, 'ports': ['23', '3389', '25'], 'server': ['http', 'ms-wbt-server', 'http'],
         'services': {'23': 'http', '3389': 'ms-wbt-server', '25': 'http'}, 'urls': [], 'time': '2019-11-17-11-37-23'},
        {'ip': '118.24.1.152', 'alive': True, 'ports': ['80', '8080', '22'], 'server': ['http', 'http', 'ssh'],
         'services': {'80': 'http', '8080': 'http', '22': 'ssh'}, 'urls': [{'http://118.24.1.152:8080': '梧桐中医'}],
         'time': '2019-11-17-11-37-24'},
        {'ip': '118.24.1.187', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-37-45'},
        {'ip': '118.24.1.32', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-38-06'},
        {'ip': '118.24.1.188', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-38-28'},
        {'ip': '118.24.1.194', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-38-49'},
        {'ip': '118.24.1.180', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-39-30'},
        {'ip': '118.24.1.242', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-40-00'},
        {'ip': '118.24.1.37', 'alive': True, 'ports': ['3389', '80'], 'server': ['ms-wbt-server', 'http'],
         'services': {'3389': 'ms-wbt-server', '80': 'http'}, 'urls': [{'http://118.24.1.37:80': '点点滴滴'}],
         'time': '2019-11-17-11-40-22'}, {'ip': '118.24.1.18', 'alive': True, 'ports': ['21', '3389', '80'],
                                          'server': ['mongodb', 'ms-wbt-server', 'http'],
                                          'services': {'21': 'mongodb', '3389': 'ms-wbt-server', '80': 'http'},
                                          'urls': [{'http://118.24.1.18:80': '广州烧腊世家培训'}],
                                          'time': '2019-11-17-11-40-43'},
        {'ip': '118.24.1.78', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-41-05'},
        {'ip': '118.24.1.96', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-41-05'}, {'ip': '118.24.1.136', 'alive': True, 'ports': ['25', '3389', '8888'],
                                          'server': ['http', 'ms-wbt-server', 'ddi-tcp-1'],
                                          'services': {'25': 'http', '3389': 'ms-wbt-server', '8888': 'ddi-tcp-1'},
                                          'urls': [], 'time': '2019-11-17-11-41-27'},
        {'ip': '118.24.1.169', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-41-48'},
        {'ip': '118.24.1.111', 'alive': True, 'ports': ['80', '6379', '22'], 'server': ['http', 'redis', 'ssh'],
         'services': {'80': 'http', '6379': 'redis', '22': 'ssh'},
         'urls': [{'http://118.24.1.111:80': 'Welcome to nginx!'}], 'time': '2019-11-17-11-42-08'},
        {'ip': '118.24.1.112', 'alive': True, 'ports': ['3306', '22', '80'], 'server': ['mysql', 'ssh', 'http'],
         'services': {'3306': 'mysql', '22': 'ssh', '80': 'http'}, 'urls': [{'http://118.24.1.112:80': '宅宅新闻-首页'}],
         'time': '2019-11-17-11-42-09'},
        {'ip': '118.24.1.53', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-42-31'},
        {'ip': '118.24.1.62', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-42-31'},
        {'ip': '118.24.1.55', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-42-52'},
        {'ip': '118.24.1.175', 'alive': True, 'ports': ['80'], 'server': ['http'], 'services': {'80': 'http'},
         'urls': [{'http://118.24.1.175:80': 'Welcome to nginx!'}], 'time': '2019-11-17-11-42-53'},
        {'ip': '118.24.1.243', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-43-14'},
        {'ip': '118.24.1.134', 'alive': True, 'ports': ['21', '80', '22', '3306'],
         'server': ['ftp', 'http', 'ssh', 'mysql'],
         'services': {'21': 'ftp', '80': 'http', '22': 'ssh', '3306': 'mysql'},
         'urls': [{'http://118.24.1.134:80': 'OneinStack - PHP/JAVA环境一键部署工具'}], 'time': '2019-11-17-11-43-15'},
        {'ip': '118.24.1.124', 'alive': True, 'ports': ['3389', '7000'], 'server': ['ms-wbt-server', 'afs3-fileserver'],
         'services': {'3389': 'ms-wbt-server', '7000': 'afs3-fileserver'}, 'urls': [], 'time': '2019-11-17-11-43-57'},
        {'ip': '118.24.1.233', 'alive': True, 'ports': ['80', '8080'], 'server': ['http', 'http'],
         'services': {'80': 'http', '8080': 'http'},
         'urls': [{'http://118.24.1.233:80': '400 Bad Request'}, {'http://118.24.1.233:8080': '400 Bad Request'}],
         'time': '2019-11-17-11-43-57'},
        {'ip': '118.24.1.14', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-43-58'},
        {'ip': '118.24.1.19', 'alive': True, 'ports': ['80', '22', '3306'], 'server': ['http', 'ssh', 'mysql'],
         'services': {'80': 'http', '22': 'ssh', '3306': 'mysql'}, 'urls': [], 'time': '2019-11-17-11-43-58'},
        {'ip': '118.24.1.232', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-44-20'},
        {'ip': '118.24.1.58', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-44-41'},
        {'ip': '118.24.1.121', 'alive': True, 'ports': ['3306', '22'], 'server': ['mysql', 'ssh'],
         'services': {'3306': 'mysql', '22': 'ssh'}, 'urls': [], 'time': '2019-11-17-11-44-42'},
        {'ip': '118.24.1.101', 'alive': True, 'ports': ['8888', '80', '22'], 'server': ['http', 'http', 'ssh'],
         'services': {'8888': 'http', '80': 'http', '22': 'ssh'},
         'urls': [{'http://118.24.1.101:8888': '安全入口校验失败'}, {'http://118.24.1.101:80': '没有找到站点'}],
         'time': '2019-11-17-11-44-43'},
        {'ip': '118.24.1.85', 'alive': True, 'ports': ['22', '80'], 'server': ['ssh', 'http'],
         'services': {'22': 'ssh', '80': 'http'}, 'urls': [{'http://118.24.1.85:80': 'JoyiSpace访客登记'}],
         'time': '2019-11-17-11-44-43'},
        {'ip': '118.24.1.234', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-45-05'},
        {'ip': '118.24.1.22', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-45-26'},
        {'ip': '118.24.1.252', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-45-47'},
        {'ip': '118.24.1.77', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-46-09'},
        {'ip': '118.24.1.224', 'alive': True, 'ports': ['25', '3389'], 'server': ['http', 'ms-wbt-server'],
         'services': {'25': 'http', '3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-46-30'},
        {'ip': '118.24.1.86', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-46-51'},
        {'ip': '118.24.1.95', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-47-13'},
        {'ip': '118.24.1.193', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-47-34'},
        {'ip': '118.24.1.7', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-47-34'},
        {'ip': '118.24.1.153', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-47-56'},
        {'ip': '118.24.1.13', 'alive': True, 'ports': ['23', '3389', '8888', '25'],
         'server': ['http', 'ms-wbt-server', 'ddi-tcp-1', 'http'],
         'services': {'23': 'http', '3389': 'ms-wbt-server', '8888': 'ddi-tcp-1', '25': 'http'}, 'urls': [],
         'time': '2019-11-17-11-48-17'},
        {'ip': '118.24.1.139', 'alive': True, 'ports': ['80'], 'server': ['http'], 'services': {'80': 'http'},
         'urls': [], 'time': '2019-11-17-11-48-18'},
        {'ip': '118.24.1.147', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-48-39'},
        {'ip': '118.24.1.197', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-48-39'},
        {'ip': '118.24.1.149', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-49-01'},
        {'ip': '118.24.1.202', 'alive': True, 'ports': ['80'], 'server': ['http'], 'services': {'80': 'http'},
         'urls': [], 'time': '2019-11-17-11-49-01'},
        {'ip': '118.24.1.221', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-49-22'},
        {'ip': '118.24.1.146', 'alive': True, 'ports': ['80', '22'], 'server': ['http', 'ssh'],
         'services': {'80': 'http', '22': 'ssh'}, 'urls': [{'http://118.24.1.146:80': 'Welcome to nginx on Debian!'}],
         'time': '2019-11-17-11-49-22'}, {'ip': '118.24.1.203', 'alive': True, 'ports': ['3389', '1433', '80'],
                                          'server': ['ms-wbt-server', 'ms-sql-s', 'http'],
                                          'services': {'3389': 'ms-wbt-server', '1433': 'ms-sql-s', '80': 'http'},
                                          'urls': [{
                                                       'http://118.24.1.203:80': b'\r\n\tEnRP|\xcd\xa8\xd3\xc3\xd1\xa7\xcf\xb0\xc6\xbd\xcc\xa8\r\n'}],
                                          'time': '2019-11-17-11-50-04'},
        {'ip': '118.24.1.216', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-50-25'},
        {'ip': '118.24.1.143', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-50-26'},
        {'ip': '118.24.1.241', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-51-07'},
        {'ip': '118.24.1.218', 'alive': True, 'ports': ['80'], 'server': ['http'], 'services': {'80': 'http'},
         'urls': [{'https://blog.wuqii.com': 'Lionel的博客'}], 'time': '2019-11-17-11-51-08'},
        {'ip': '118.24.1.157', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-51-29'},
        {'ip': '118.24.1.82', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-51-50'},
        {'ip': '118.24.1.93', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-52-12'},
        {'ip': '118.24.1.99', 'alive': True, 'ports': ['3306', '3389', '80'],
         'server': ['mysql', 'ms-wbt-server', 'http'],
         'services': {'3306': 'mysql', '3389': 'ms-wbt-server', '80': 'http'},
         'urls': [{'http://118.24.1.99:80': '恭喜，站点创建成功！'}], 'time': '2019-11-17-11-52-34'},
        {'ip': '118.24.1.206', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-52-55'},
        {'ip': '118.24.1.38', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-53-17'},
        {'ip': '118.24.1.63', 'alive': True, 'ports': ['3306', '22', '80'], 'server': ['db2jds', 'ssh', 'http'],
         'services': {'3306': 'db2jds', '22': 'ssh', '80': 'http'}, 'urls': [], 'time': '2019-11-17-11-53-17'},
        {'ip': '118.24.1.217', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-53-39'},
        {'ip': '118.24.1.65', 'alive': True, 'ports': ['25', '3389'], 'server': ['http', 'ms-wbt-server'],
         'services': {'25': 'http', '3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-54-00'},
        {'ip': '118.24.1.44', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-54-21'},
        {'ip': '118.24.1.87', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-54-22'},
        {'ip': '118.24.1.8', 'alive': True, 'ports': ['80', '8080'], 'server': ['http', 'http'],
         'services': {'80': 'http', '8080': 'http'},
         'urls': [{'http://118.24.1.8:80': 'Test Page for the Nginx HTTP Server on Fedora'},
                  {'http://118.24.1.8:8080': '康明斯 情绪统计'}], 'time': '2019-11-17-11-54-22'},
        {'ip': '118.24.1.209', 'alive': True, 'ports': ['80', '3389'], 'server': ['http', 'ms-wbt-server'],
         'services': {'80': 'http', '3389': 'ms-wbt-server'},
         'urls': [{'http://118.24.1.209:80': ':: Love Miss Inn ::'}], 'time': '2019-11-17-11-54-43'},
        {'ip': '118.24.1.150', 'alive': True, 'ports': ['3389', '80'], 'server': ['ms-wbt-server', 'http'],
         'services': {'3389': 'ms-wbt-server', '80': 'http'}, 'urls': [{'http://118.24.1.150:80': 'Not Found'}],
         'time': '2019-11-17-11-55-05'},
        {'ip': '118.24.1.215', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-55-05'},
        {'ip': '118.24.1.131', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-55-26'},
        {'ip': '118.24.1.235', 'alive': True, 'ports': ['80', '3389'], 'server': ['http', 'ms-wbt-server'],
         'services': {'80': 'http', '3389': 'ms-wbt-server'}, 'urls': [{'http://118.24.1.235:80': '口袋日报'}],
         'time': '2019-11-17-11-55-48'},
        {'ip': '118.24.1.155', 'alive': True, 'ports': ['80'], 'server': ['http'], 'services': {'80': 'http'},
         'urls': [], 'time': '2019-11-17-11-56-08'},
        {'ip': '118.24.1.106', 'alive': True, 'ports': ['9999'], 'server': ['http'], 'services': {'9999': 'http'},
         'urls': [], 'time': '2019-11-17-11-56-08'},
        {'ip': '118.24.1.39', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-56-12'},
        {'ip': '118.24.1.185', 'alive': True, 'ports': ['80', '3389'], 'server': ['http', 'ms-wbt-server'],
         'services': {'80': 'http', '3389': 'ms-wbt-server'}, 'urls': [{'http://118.24.1.185:80': '萤火虫'}],
         'time': '2019-11-17-11-56-33'},
        {'ip': '118.24.1.122', 'alive': True, 'ports': ['8080'], 'server': ['http'], 'services': {'8080': 'http'},
         'urls': [{'http://118.24.1.122:8080': 'Laravel'}], 'time': '2019-11-17-11-56-33'},
        {'ip': '118.24.1.46', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-56-55'},
        {'ip': '118.24.1.249', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-57-16'},
        {'ip': '118.24.1.208', 'alive': True, 'ports': ['80'], 'server': ['http'], 'services': {'80': 'http'},
         'urls': [{'https://git.quicknown.com': 'Sign in · GitLab'}], 'time': '2019-11-17-11-57-17'},
        {'ip': '118.24.1.89', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-57-17'},
        {'ip': '118.24.1.73', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-57-17'},
        {'ip': '118.24.1.179', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-57-38'},
        {'ip': '118.24.1.228', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-58-00'},
        {'ip': '118.24.1.177', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-58-21'},
        {'ip': '118.24.1.127', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-58-21'},
        {'ip': '118.24.1.110', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-58-22'},
        {'ip': '118.24.1.41', 'alive': True, 'ports': ['80'], 'server': ['http'], 'services': {'80': 'http'},
         'urls': [{'http://118.24.1.41:80': 'Welcome to nginx!'}], 'time': '2019-11-17-11-58-22'},
        {'ip': '118.24.1.52', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-58-43'},
        {'ip': '118.24.1.24', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-58-44'},
        {'ip': '118.24.1.48', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-58-44'},
        {'ip': '118.24.1.213', 'alive': True, 'ports': ['3389'], 'server': ['ms-wbt-server'],
         'services': {'3389': 'ms-wbt-server'}, 'urls': [], 'time': '2019-11-17-11-59-05'},
        {'ip': '118.24.1.201', 'alive': True, 'ports': ['22'], 'server': ['ssh'], 'services': {'22': 'ssh'}, 'urls': [],
         'time': '2019-11-17-11-59-05'},
        {'ip': '118.24.1.98', 'alive': True, 'ports': ['8080'], 'server': ['http'], 'services': {'8080': 'http'},
         'urls': [{'http://118.24.1.98:8080': 'Not Found'}], 'time': '2019-11-17-11-59-06'}]

    CleanData(IPdata=res, txtfile=ImgTxt, htmlfile=ImgHtml)
    # time.sleep(5)
    # inp = input('导入IP文本:')
    # ips = [x.replace('\n','').strip() for x in open(inp,'r',encoding='utf-8').readlines()]
    # por = input('输入扫描端口(21,22,8-888,6379,27017):')
    # rat = input('设置每秒发包量(1000-5000):')
    # try:
    #     if 0<int(rat)<50000:
    #         pass
    # except:
    #     print('发包量设置错误')
    # # ips = ['118.10.56.0/24','118.11.23.0/24','118.12.23.0/24']
    # res = []
    # for ip in ips:
    #     a = IpInfoScan(ip)
    #     res.extend(a.GetResult(por.replace('，',','),rat))
    # if res == []:
    #     print('扫描完毕~无存活IP~')
    # else:
    #     CleanData(IPdata=res,txtfile=ImgTxt,htmlfile=ImgHtml)
    #     print('扫描完毕~')
    # while 1:
    #     time.sleep(500)