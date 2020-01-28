# -*- coding:utf-8 -*-
from __future__ import unicode_literals
import string
import sys
import time
import pyecharts.options as opts
from pyecharts.charts import Pie
import re
from urllib.parse import urlparse
import masscan
import requests
import socket
import datetime
import os
import random
import xlsxwriter
from concurrent.futures import ThreadPoolExecutor
requests.packages.urllib3.disable_warnings()
# from pyecharts.charts import Page, WordCloud
from multiprocessing import Pool
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

def Log(x):
    with open('../LangNetWorkTopoLog.txt','a+',encoding='utf-8')as a:
        a.write(str( '-'.join(str(datetime.datetime.now()).replace(' ','-').replace(':','-').split('.')[0].split('-')))+'    '+str(x)+'\n')


# Alive_Status = [200,204,206,301,302,304,401,402,403,404,500,501,502,503]
Alive_Status = range(1000)

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
        r = requests.get(url='http://'+url,headers=headers,verify=False,timeout=5)
        if b'text/html' in r.content or b'<title>' in r.content or b'</html>' in r.content:
            content1 = r.content
            if int(r.status_code) in Alive_Status:
                u = urlparse(str(r.url))
                title1 = get_title(r.content)
                url1 = u.scheme + '://' + u.netloc
        else:
            try:
                s = socket.socket()
                s.settimeout(1)
                s.connect((url.split(':')[0], int(url.split(':')[1])))
                s.send(b'langzi\n\n')
                rec = s.recv(1024)
                s.close()
                if b'HTTP' in rec:
                    u = urlparse(str(r.url))
                    title1 = get_title(rec)+'|通过TCP连接端口方式获取信息'
                    url1 = u.scheme + '://' + u.netloc
            except Exception as e:
                pass
            finally:
                s.close()
    except Exception as e:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((url.split(':')[0], int(url.split(':')[1])))
            s.send(b'langzi\n\n')
            rec = s.recv(1024)
            s.close()
            if b'HTTP' in rec:
                u = urlparse(str('http://'+url))
                title1 = get_title(rec)+'|通过TCP连接端口方式获取信息'
                url1 = u.scheme + '://' + u.netloc
        except Exception as e:
            pass
        finally:
            s.close()
    try:
        r = requests.get(url='https://'+url,headers=headers,verify=False,timeout=5)
        if b'text/html' in r.content or b'<title>' in r.content or b'</html>' in r.content:
            content2 = r.content
            u = urlparse(str(r.url))
            title2 = get_title(r.content)
            url2 = u.scheme + '://' + u.netloc
        else:
            try:
                s = socket.socket()
                s.settimeout(1)
                s.connect((url.split(':')[0], int(url.split(':')[1])))
                s.send(b'langzi\n\n')
                rec = s.recv(1024)
                s.close()
                if b'HTTP' in rec:
                    u = urlparse(str(r.url))
                    title2 = get_title(rec) +'|通过TCP连接端口方式获取信息'
                    url2 = u.scheme + '://' + u.netloc
            except Exception as e:
                pass
            finally:
                s.close()
    except Exception as e:
        pass
    if title1 != '获取失败' and title2 == '获取失败':
        return [{url1: title1}]
    if title2 != '获取失败' and title1 == '获取失败':
        return [{url2: title2}]
    if title1 != '获取失败' and title2 != '获取失败':
        return [{url1: title1},{url2: title2}]
    if content1 != None:
        return [{url1:title}]
    if content2 != None:
        return [{url2:title}]
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
    result = [y for x in result  for y in x]
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
        # self.Banner = {b'http': [b'^HTTP/.*\nServer: Apache/2',b'HTTP/'], b'ssh': [b'^SSH-.*openssh'], b'netbios': [b'\xc2\x83\x00\x00\x01\xc2\x8f'], b'backdoor-fxsvc': [b'^500 Not Loged in'], b'backdoor-shell': [b'^sh[$#]'], b'bachdoor-shell': [b'[a-z]*sh: .* command not found'], b'backdoor-cmdshell': [b'^Microsoft Windows .* Copyright .*>'], b'db2': [b'.*SQLDB2RA'], b'db2jds': [b'^N\x00'], b'dell-openmanage': [b'^N\x00\r'], b'finger': [b'finger: GET: '], b'ftp': [b'^220 .* UserGate'], b'http-iis': [b'^<h1>Bad Request .Invalid URL.</h1>'], b'http-jserv': [b'^HTTP/.*Cookie.*JServSessionId'], b'http-tomcat': [b'.*Servlet-Engine'], b'http-weblogic': [b'^HTTP/.*Cookie.*WebLogicSession'], b'http-vnc': [b'^HTTP/.*RealVNC/'], b'ldap': [b'^0E'], b'smb': [b'^\x00\x00\x00.\xc3\xbfSMBr\x00\x00\x00\x00.*'], b'msrdp': [b'^\x03\x00\x00\x0b\x06\xc3\x90\x00\x004\x12\x00'], b'msrdp-proxy': [b'^nmproxy: Procotol byte is not 8\n$'], b'msrpc': [b'\x05\x00\r\x03\x10\x00\x00\x00\x18\x00\x00\x00....\x04\x00\x01\x05\x00\x00\x00\x00$'], b'mssql': [b';MSSQLSERVER;'], b'telnet': [b'^\xc3\xbf\xc3\xbe'], b'mysql': [b"whost '"], b'mysql-blocked': [b'^\\(\x00\x00'], b'mysql-secured': [b'this MySQL'], b'mongodb': [b'^.*version.....([\\.\\d]+)'], b'nagiosd': [b'Sorry, you \\(.*are not among the allowed hosts...'], b'nessus': [b'< NTP 1.2 >\nUser:'], b'oracle-tns-listener': [b'\\(ADDRESS=\\(PROTOCOL='], b'oracle-dbsnmp': [b'^\x00\x0c\x00\x00\x04\x00\x00\x00\x00'], b'oracle-https': [b'^220- ora'], b'oracle-rmi': [b'^N\x00\t'], b'postgres': [b'^EFATAL'], b'rlogin': [b'^\x01Permission denied.\n'], b'rpc-nfs': [b'^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00'], b'rpc': [b'^\xc2\x80\x00\x00'], b'rsync': [b'^@RSYNCD:.*'], b'smux': [b'^A\x01\x02\x00'], b'snmp-public': [b'public\xc2\xa2'], b'snmp': [b'A\x01\x02'], b'socks': [b'^\x05[\x00-\x08]\x00'], b'ssl': [b'^\x16\x03\x00..\x02...\x03\x00'], b'sybase': [b'^\x04\x01\x00'], b'tftp': [b'^\x00[\x03\x05]\x00'], b'uucp': [b'^login: password: '], b'vnc': [b'^RFB.*'], b'webmin': [b'^0\\.0\\.0\\.0:.*:[0-9]'], b'websphere-javaw': [b'^\x15\x00\x00\x00\x02\x02\n']}
        self.Banner = {b'http': [b'^HTTP/.*\nServer: Apache/2', b'HTTP', b'http/1.1', b'http/1.0'], b'ssh': [b'^SSH-.*openssh', b'^ssh-', b'connection refused by remote host.'], b'netbios': [b'\xc2\x83\x00\x00\x01\xc2\x8f', b'^y\x08.*browse', b'^y\x08.\x00\x00\x00\x00', b'^\x05\x00\r\x03', b'^\x82\x00\x00\x00', b'\x83\x00\x00\x01\x8f'], b'backdoor-fxsvc': [b'^500 Not Loged in'], b'backdoor-shell': [b'^sh[$#]'], b'bachdoor-shell': [b'[a-z]*sh: .* command not found'], b'backdoor-cmdshell': [b'^Microsoft Windows .* Copyright .*>'], b'db2': [b'.*SQLDB2RA', b'.*sqldb2ra'], b'db2jds': [b'^N\x00', b'^n\x00'], b'dell-openmanage': [b'^N\x00\r'], b'finger': [b'finger: GET: ', b'^\r\n\tline\t  user', b'line\t user', b'login name: ', b'login.*name.*tty.*idle', b'^no one logged on', b'^\r\nwelcome', b'^finger:', b'^must provide username', b'finger: get: '], b'ftp': [b'^220 .* UserGate', b'^220.*\n331', b'^220.*\n530', b'^220.*ftp', b'^220 .* microsoft .* ftp', b'^220 inactivity timer', b'^220 .* usergate', b'^220.*filezilla server', b'^220-', b'^220.*?ftp', b'^220.*?filezilla'], b'http-iis': [b'^<h1>Bad Request .Invalid URL.</h1>'], b'http-jserv': [b'^HTTP/.*Cookie.*JServSessionId'], b'http-tomcat': [b'.*Servlet-Engine'], b'http-weblogic': [b'^HTTP/.*Cookie.*WebLogicSession'], b'http-vnc': [b'^HTTP/.*RealVNC/'], b'ldap': [b'^0E', b'^0\x0c\x02\x01\x01a', b'^02\x02\x01', b'^03\x02\x01', b'^08\x02\x01', b'^0\x84', b'^0e'], b'smb': [b'^\x00\x00\x00.\xc3\xbfSMBr\x00\x00\x00\x00.*', b'^\x00\x00\x00.\xffsmbr\x00\x00\x00\x00.*', b'^\x83\x00\x00\x01\x8f'], b'msrdp': [b'^\x03\x00\x00\x0b\x06\xc3\x90\x00\x004\x12\x00'], b'msrdp-proxy': [b'^nmproxy: Procotol byte is not 8\n$'], b'msrpc': [b'\x05\x00\r\x03\x10\x00\x00\x00\x18\x00\x00\x00....\x04\x00\x01\x05\x00\x00\x00\x00$', b'^\x05\x00\r\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00', b'\x05\x00\r\x03\x10\x00\x00\x00\x18\x00\x00\x00....\x04\x00\x01\x05\x00\x00\x00\x00$'], b'mssql': [b';MSSQLSERVER;', b'^\x05n\x00', b'^\x04\x01', b';mssqlserver;', b'mssqlserver'], b'telnet': [b'^\xc3\xbf\xc3\xbe', b'telnet', b'^\xff[\xfa-\xff]', b'^\r\n%connection closed by remote host!\x00$'], b'mysql': [b"whost '", b'mysql_native_password', b'^\x19\x00\x00\x00\n', b'^,\x00\x00\x00\n', b"hhost '", b"khost '", b'mysqladmin', b"whost '", b'^[.*]\x00\x00\x00\n.*?\x00', b'this mysql server', b'mariadb server', b'\x00\x00\x00\xffj\x04host'], b'mysql-blocked': [b'^\\(\x00\x00'], b'mysql-secured': [b'this MySQL'], b'mongodb': [b'^.*version.....([\\.\\d]+)', b'mongodb'], b'nagiosd': [b'Sorry, you \\(.*are not among the allowed hosts...', b'sorry, you \\(.*are not among the allowed hosts...'], b'nessus': [b'< NTP 1.2 >\nUser:', b'< ntp 1.2 >\nuser:'], b'oracle-tns-listener': [b'\\(ADDRESS=\\(PROTOCOL=', b'\\(error_stack=\\(error=\\(code=', b'\\(address=\\(protocol='], b'oracle-dbsnmp': [b'^\x00\x0c\x00\x00\x04\x00\x00\x00\x00', b'^\x00\x0c\x00\x00\x04\x00\x00\x00\x00'], b'oracle-https': [b'^220- ora', b'^220- ora'], b'oracle-rmi': [b'^N\x00\t'], b'postgres': [b'^EFATAL'], b'rlogin': [b'^\x01Permission denied.\n', b'login: ', b'rlogind: ', b'^\x01permission denied.\n'], b'rpc-nfs': [b'^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00', b'^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00'], b'rpc': [b'^\xc2\x80\x00\x00', b'\x01\x86\xa0', b'\x03\x9beb\x00\x00\x00\x01', b'^\x80\x00\x00'], b'rsync': [b'^@RSYNCD:.*', b'^@rsyncd:', b'@rsyncd:'], b'smux': [b'^A\x01\x02\x00', b'^a\x01\x02\x00'], b'snmp-public': [b'public\xc2\xa2', b'public\xa2'], b'snmp': [b'A\x01\x02', b'a\x01\x02'], b'socks': [b'^\x05[\x00-\x08]\x00', b'^\x05[\x00-\x08]\x00'], b'ssl': [b'^\x16\x03\x00..\x02...\x03\x00', b'^..\x04\x00.\x00\x02', b'^\x16\x03\x01..\x02...\x03\x01', b'^\x16\x03\x00..\x02...\x03\x00', b'ssl.*get_client_hello', b'^-err .*tls_start_servertls', b'^\x16\x03\x00\x00j\x02\x00\x00f\x03\x00', b'^\x16\x03\x00..\x02\x00\x00f\x03\x00', b'^\x15\x03\x00\x00\x02\x02\\.*', b'^\x16\x03\x01..\x02...\x03\x01', b'^\x16\x03\x00..\x02...\x03\x00'], b'sybase': [b'^\x04\x01\x00', b'^\x04\x01\x00'], b'tftp': [b'^\x00[\x03\x05]\x00', b'^\x00[\x03\x05]\x00'], b'uucp': [b'^login: password: ', b'^login: password: '], b'vnc': [b'^RFB.*', b'^rfb'], b'webmin': [b'^0\\.0\\.0\\.0:.*:[0-9]', b'.*miniserv', b'^0\\.0\\.0\\.0:.*:[0-9]'], b'websphere-javaw': [b'^\x15\x00\x00\x00\x02\x02\n', b'^\x15\x00\x00\x00\x02\x02\n'], b'xmpp': [b"^\\<\\?xml version='1.0'\\?\\>"], b'backdoor': [b'^500 not loged in', b'get: command', b'sh: get:', b'^bash[$#]', b'^sh[$#]', b'^microsoft windows'], b'bachdoor': [b'*sh: .* command not found'], b'rdp': [b'^\x00\x01\x00.*?\r\n\r\n$', b'^\x03\x00\x00\x0b', b'^\x03\x00\x00\x11', b'^\x03\x00\x00\x0b\x06\xd0\x00\x00\x12.\x00$', b'^\x03\x00\x00\x17\x08\x02\x00\x00z~\x00\x0b\x05\x05@\x06\x00\x08\x91j\x00\x02x$', b'^\x03\x00\x00\x11\x08\x02..}\x08\x03\x00\x00\xdf\x14\x01\x01$', b'^\x03\x00\x00\x0b\x06\xd0\x00\x00\x03.\x00$', b'^\x03\x00\x00\x0b\x06\xd0\x00\x00\x00\x00\x00', b'^\x03\x00\x00\x0e\t\xd0\x00\x00\x00[\x02\xa1]\x00\xc0\x01\n$', b'^\x03\x00\x00\x0b\x06\xd0\x00\x004\x12\x00'], b'rdp-proxy': [b'^nmproxy: procotol byte is not 8\n$'], b'rmi': [b'\x00\x00\x00vinva', b'^n\x00\t'], b'postgresql': [b'invalid packet length', b'^efatal'], b'imap': [b'^\\* ok.*?imap'], b'pop': [b'^\\+ok.*?'], b'smtp': [b'^220.*?smtp', b'^554 smtp'], b'rtsp': [b'^rtsp/'], b'sip': [b'^sip/'], b'nntp': [b'^200 nntp'], b'sccp': [b'^\x01\x00\x00\x00$'], b'squid': [b'x-squid-error'], b'vmware': [b'vmware'], b'iscsi': [b'\x00\x02\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'], b'redis': [b'^-err unknown command', b'^-err wrong number of arguments', b'^-denied redis is running'], b'memcache': [b'^error\r\n'], b'websocket': [b'server: websocket'], b'https': [b'instead use the https scheme to accesshttps', b'http request to an https server', b'location: https'], b'svn': [b'^\\( success \\( 2 2 \\( \\) \\( edit-pipeline svndiff1'], b'dubbo': [b'^unsupported command'], b'elasticsearch': [b'cluster_name.*elasticsearch'], b'rabbitmq': [b'^amqp\x00\x00\t\x01'], b'zookeeper': [b'^zookeeper version: ']}

    def GetOpenPort(self,inport,rate):
        Ret = []
        try:
            mas = masscan.PortScanner()
            #mas.scan(self.ip,ports='21,22,23,25,80,81,88,8080,8888,999,9999,7000,1433,1521,3306,3389,6379,7001,27017,27018')
            # 这里简单的扫一下普通端口即可
            mas.scan(self.ip, ports=inport, arguments='--rate {}'.format(rate))
            Results = mas.scan_result['scan']
            AliveHosts = list(Results.keys())
            if AliveHosts != []:
                for k, v in Results.items():
                    HostInfos = {}
                    HostInfos[str(k)] = list(v['tcp'].keys())
                    Ret.append(HostInfos)
        except Exception as e:
            Log('扫描IP出现异常:{}'.format(str(e)))
        return list(Ret)

    def GetOneIPorts(self,ip,inport,rate):
        try:
            mas = masscan.PortScanner()
            mas.scan(self.ip, ports=inport, arguments='--rate {}'.format(rate))
            # if inport == '0':
            #     mas.scan(self.ip,arguments='--rate {}'.format(rate))
            # else:
            #     mas.scan(self.ip,ports=inport,arguments='--rate {}'.format(rate))
            OpenPorts = mas.scan_result['scan'][ip]['tcp'].keys()
        except Exception as e:
            Log('获取扫描IP端口结果异常:{}'.format(str(e)))
            return None
        return [{ip:OpenPorts}]

    def GetBannerServer(self,ip,port):
        try:
            s = socket.socket()
            s.settimeout(0.7)
            s.connect((ip,int(port)))
            s.send(b'langzi\r\n')
            SocketRecv = (s.recv(1024))
            s.close()
            for k,v in self.Banner.items():
                for b in v:
                    banner = re.search(b,SocketRecv,re.I|re.S)
                    if banner:
                        return k.decode()
            return '获取失败'
        except Exception as e:
            # Log('向端口发起连接异常:{}'.format(str(e)))
            return '获取失败'
        finally:
            s.close()

    def CheckPortOpen(self,ip,port):
        # 该函数用来对masscan扫描端口进行复检，巧妙之处在于socket连接识别完banner，剩下无法识别连
        # 使用本地指纹库识别之前进行二次复检，节省许多不必要复检的端口任务数
        try:
            s = socket.socket()
            s.settimeout(0.5)
            r =s.connect_ex((ip,int(port)))
            if r == 0:
                return True
            else:
                return False
        except:
            return False
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
                    Cpo = self.CheckPortOpen(ip,k)
                    # 进一步复检，提升准确率
                    if Cpo == True:
                        PortInfos[k] = GetPortInfo(str(k))
                    else:
                        del PortInfos[k]
        return PortInfos

    def FeatureResult(self,openport):
        retuls = {}
        for k, v in openport.items():
            res = self.GetPoerInfos(k, v)
            # {'80': 'http', '3389': 'ms-wbt-server'}
            urls = []
            for port in v:
                urls.append('{}:{}'.format(k, port))
            AliveUrls = Get_Alive_Url(urls)
            retuls['ip'] = k
            retuls['alive'] = True
            retuls['ports'] = list(res.keys())
            retuls['server'] = list(res.values())
            retuls['services'] = res
            retuls['urls'] = AliveUrls
            print('[{}]  主机:{} 开放端口:{} 个 部署网站:{} 个 运行服务:{}'.format(str(datetime.datetime.now()).split('.')[0], k.ljust(15),
                                                                   len(v), len(AliveUrls), '/'.join(list(res.values()))))
            Log('主机:{} 开放端口:{} 个 部署网站:{} 个 运行服务:{} 开放端口:{}'.format( k.ljust(15),
                                                                   len(v), len(AliveUrls), '/'.join(list(res.values())),str(list(res.keys()))))
            retuls['time'] = str(datetime.datetime.now()).replace(' ', '-').replace(':', '-').split('.')[0]
            return retuls

    def GetResult(self,inport,rate,Portfolio):
        try:
            print('\n[{}]  端口扫描 : {}\n'.format(str(datetime.datetime.now()).split('.')[0], self.ip))
            Log('开始扫描IP:{}'.format(self.ip))
            stat = time.time()
            if '-' in self.ip or '/' in self.ip:
                openports = self.GetOpenPort(inport,rate)
            else:
                openports = self.GetOneIPorts(self.ip,inport,rate)
            #openports = {'192.168.1.1':[22,23,25]}
            #openports = {'192.168.1.1':[22,23,25],'192.168.1.2':[80,8080]}
            if openports != {} and openports != None:
                if len(openports) !=0:
                    try:
                        TIMES = str(int(str(time.time() - stat).split('.')[0]))+'秒'
                        print('\n[{}]  主机资产:{} 相关端口扫描完毕 发现存活主机共:{} 个 耗时:{}\n'.format(str(datetime.datetime.now()).split('.')[0],self.ip.ljust(15) ,
                                                                       len(openports),TIMES))
                        time.sleep(2)
                    except:
                        pass
                for ZHRNDAA in openports:
                    for k, v in ZHRNDAA.items():
                        Log('主机 {} 开放端口 {} '.format(k, str(v)))
                        with open(os.path.join(Portfolio, 'AliveHosts') + '.txt', 'a+', encoding='utf-8')as b:
                            b.write(k + '\n')
                with ThreadPoolExecutor() as pool:
                    results = pool.map(self.FeatureResult,openports)
                return list(results)
        except Exception as e:
            print('[{}]  端口扫描 : {} 出现异常，异常原因 : {}'.format(str(datetime.datetime.now()).split('.')[0], self.ip,str(e)))
            Log('端口扫描 : {} 出现异常，异常原因 : {}'.format(self.ip,str(e)))
        return []


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
        Pie(init_opts=opts.InitOpts(width="2200px", height="900px"))
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
    # words = mid_data_pair + outer_data_pair
    # c = (
    #     WordCloud(init_opts=opts.InitOpts(width="1200px", height="800px"))
    #     .add("", words, word_size_range=[30, 80])
    #     # .set_global_opts(title_opts=opts.TitleOpts(title="WordCloud-基本示例"))
    # ).render('test.txt')


    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8')as a:
            res1 = re.search('(<body>.*?</body>)', a.read(), re.S | re.I).group(1)
        os.remove(filename)
        return res1
        # with open('test.txt', 'r', encoding='utf-8')as a:
        #     res2 = re.search('(<body>.*?</body>)', a.read(), re.S | re.I).group(1)
        # os.remove('test.txt')
        # res3 = '<div class="col-sm-6">{}</div><div class="col-sm-6">{}</div>'.format(res1,res2)
        # return res3
    else:
        Log('生成效果图失败')


def CleanData(IPdata,txtfile,htmlfile,Portfolio):
    Btn_Class = ['btn btn-danger', 'btn btn-warning', 'btn btn-info', 'btn btn-primary', 'btn btn-default',
                 'btn btn-success']
    AllResultFiles = set()
    AllResultFiles.add('AliveHosts')
    AllResultFiles.add('AliveUrls')
    for i in IPdata:
        service = (i.get('services'))
        for k, v in service.items():
            AllResultFiles.add(k)
            AllResultFiles.add(v)
        AliveUrls = i.get('urls')
        if AliveUrls != []:
            for urls in AliveUrls:
                for u, t in urls.items():
                    with open(os.path.join(Portfolio, 'AliveUrls') + '.txt', 'a+', encoding='utf-8')as b:
                        b.write(u + '\n')
    ImgData = WriteImgTxt(IPdata,txtfile)
    with open('../'+htmlfile,'a+',encoding='utf-8')as a:
        a.write('''
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>网络资产拓扑-LangNetworkTopology3</title>
        <link rel="stylesheet" href='{}'>
        <link rel="stylesheet" href='{}'>
		 <script type="text/javascript" src="{}"></script>
		 <script type="text/javascript" src="{}"></script>
        </head>
		<h1> 主机资产分布图</h1><hr/>

        '''.format(os.path.join(os.path.abspath(''),'static','bootstrap-theme.min.css'),os.path.join(os.path.abspath(''),'static','bootstrap.min.css'),
                   os.path.join(os.path.abspath(''),'static','echarts.min.js'),os.path.join(os.path.abspath(''),'static','echarts-wordcloud.min.js')))
        a.write(ImgData)
        a.write('''
                			<hr />
        			<h1> 主机资产整理表</h1><hr />
        			<div class='btn-toolbar'> 
                ''')

        for file in AllResultFiles:
            a.write('''<a href="{}.txt" target="_blank"><button class="{}">{}</button></a>'''.format(os.path.join(os.path.abspath(''),Portfolio,file).replace('/','\\'),random.choice(Btn_Class),file))

        a.write('''
        </div>
        			<hr />
			<h1> 主机资产详情表</h1><hr />
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
                with open(os.path.join(Portfolio, k) + '.txt', 'a+', encoding='utf-8')as b:
                    b.write(vv+'\n')
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
                        weburl = '<a href="{}" target="_blank">{}</a>'.format(k1,v)
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
                with open(os.path.join(Portfolio, k) + '.txt', 'a+', encoding='utf-8')as b:
                    b.write(vv+'\n')
            a.write('<hr>')
        a.write('</div></body></html>')


def WritePortsServicesIp(datas,filename):
    try:
        workbook = xlsxwriter.Workbook('../'+filename)
        worksheet = workbook.add_worksheet('主机端口表')
        headings = ['主机IP', '开放端口']  # 设置表头
        worksheet.write_row('A1', headings)
        bold = workbook.add_format({'bold': True})
        worksheet.set_column(0, 10, 20, bold)
        worksheet.set_column(1, 500, 10, bold)
        row = 1
        col = 0
        for data in datas:
            worksheet.write(row, col, data.get('ip'))
            worksheet.write_row(row, col + 1, data.get('ports'))
            row += 1

        portips = {}
        serips = {}
        urlips = {}
        for i in datas:
            ports = i.get('ports')
            servs = i.get('server')
            for port in ports:
                portips[port] = []
            for serv in servs:
                serips[serv] = []

        for i in datas:
            ports = i.get('ports')
            servs = i.get('server')
            weburls = i.get('urls')
            for port in ports:
                portips[port].append(i.get('ip'))
            for serv in servs:
                serips[serv].append(i.get('ip'))
            if weburls != []:
                urlips[i.get('ip')] = [str(x + '|' + y) for z in weburls for x, y in z.items()]



        worksheet = workbook.add_worksheet('端口主机表')
        bold = workbook.add_format({'bold': True})
        worksheet.set_column(0, 10, 20, bold)
        worksheet.set_column(1, 50, 20, bold)
        col = 0
        row = 0
        for port, hosts in portips.items():
            worksheet.write(row, col, '端口:'+port+' 开放主机')
            for host in hosts:
                row +=1
                worksheet.write(row, col, host)
            row = 0
            col +=1
        worksheet = workbook.add_worksheet('服务主机表')
        bold = workbook.add_format({'bold': True})
        worksheet.set_column(0, 10, 25, bold)
        worksheet.set_column(1, 50, 25, bold)
        col = 0
        row = 0
        for port, hosts in serips.items():
            worksheet.write(row, col, '服务:'+port+' 运行主机')
            for host in hosts:
                row +=1
                worksheet.write(row, col, host)
            row = 0
            col +=1


        worksheet = workbook.add_worksheet('网站主机表')
        headings = ['主机IP', '部署网站']  # 设置表头
        worksheet.write_row('A1', headings)
        bold = workbook.add_format({'bold': True})
        worksheet.set_column(0, 10, 20, bold)
        worksheet.set_column(1, 500, 50, bold)
        row = 1
        col = 0
        for port, hosts in urlips.items():
            cel = 0
            worksheet.write(row, col, port)
            for host in hosts:
                worksheet.write_url(row, col + 1 + cel, url=host.split('|')[0],
                                    string=host.split('|')[0] + '|' + host.split('|')[1])
                cel += 1
            row += 1
        worksheet = workbook.add_worksheet('主机资产表')
        headings = ['主机IP', '开放端口', '运行服务', '部署网站']  # 设置表头
        bold = workbook.add_format({'bold': True})
        worksheet.set_column(0, 10, 20, bold)
        worksheet.set_column(1, 10, 60, bold)
        worksheet.write_row('A1', headings)
        row = 1
        col = 0
        for data in datas:
            worksheet.write(row, col, data.get('ip'))
            worksheet.write(row, col + 1, ','.join(data.get('ports')))
            worksheet.write(row, col + 2, ','.join(data.get('server')))
            weburls = data.get('urls')
            dic = dict()
            for url in weburls:
                dic.update(url)
            if dic != {}:
                e = 0
                for x, y in dic.items():
                    worksheet._write_url(row, col + 3 + e, url=x, string=x + '|' + y)
                    e += 1
            row += 1
        workbook.close()
    except Exception as e:
        print('生成xlsx文件失败,失败原因:{}'.format(str(e)))

if __name__ == '__main__':
    multiprocessing.freeze_support()
    Portfolio = 'CleanData/' + '-'.join(
        str(datetime.datetime.now()).replace(' ', '-').replace(':', '-').split('.')[0].split('-'))
    os.makedirs(Portfolio)

    ImgTxt = '-'.join(
        str(datetime.datetime.now()).replace(' ', '-').replace(':', '-').split('.')[0].split('-')) + '.txt'
    ImgHtml = '-'.join(
        str(datetime.datetime.now()).replace(' ', '-').replace(':', '-').split('.')[0].split('-')) + '.html'

    Xlsx = '-'.join(
        str(datetime.datetime.now()).replace(' ', '-').replace(':', '-').split('.')[0].split('-')) + '.xlsx'

    print('''

         _                           _
        | |                         (_)
        | |     __ _ _ __   __ _ _____
        | |    / _` | '_ \ / _` |_  / |
        | |___| (_| | | | | (_| |/ /| |
        |______\__,_|_| |_|\__, /___|_|
                            __/ |
                           |___/

    ''')

    list_jindu = string.ascii_letters + string.digits + '.' + '_' + ' '+'['+']'+'*'
    jindu = ' [*] LangNetworkTopology3 Start...'
    jindud = ''
    for xx in jindu:
        for x in list_jindu:
            sys.stdout.write(jindud + "\r")
            if xx == x:
                jindud = jindud + x
                sys.stdout.write(jindud + "\r")
                time.sleep(0.01)
                break
            else:
                sys.stdout.write(jindud + x + "\r")
                time.sleep(0.01)
                sys.stdout.flush()
            sys.stdout.write(jindud + "\r")
    sys.stdout.write(jindud + '\r')
    print()
    print('\n')
    time.sleep(1)
    inp = input('导入预扫描IP文本(可拖拽):')
    ips = list(set([x.replace('\n','').strip() for x in open(inp.replace('"',''),'r',encoding='utf-8').readlines()]))
    por = input('设置扫描端口(21,22,80-888,6379,27017):')
    rat = input('设置每秒发包量(100-2000):')
    pol = input('设置扫描进程数(1-4):')

    try:
        if 0<int(pol)<5:
            pass
        else:
            print('进程数设置过大，CPU配置较差情况下会导致masscan无响应')
        if int(rat)>2000:
            print('发包量设置过大，可能会丢包导致误报')
    except:
        print('发包量或进程数设置错误')
        time.sleep(600)
    time.sleep(3)
    res = []
    if por == '0':
        por = '69,2375,993,995,136,162,161,123,1098,68,135,50030,27018,7777,5353,502,520,500,8090,49152,1900,8099,873,514,8888,6002,4444,9110,4899,9200,1435,7000,27019,8161,9090,11211,1521,8093,3306,67,137,999,9991,4950,1099,8087,50070,6371,88,7003,1434,89,9999,513,87,2601,8009,9300,5632,1080,9043,512,8649,6000,22,8889,5900,9001,2049,9990,6001,8089,50000,81,53,888,2439,9111,8088,1423,8873,23,8083,1527,1001,1723,21,80,6003,525,3888,9000,631,30015,1433,389,27017,2888,8000,2638,2181,7001,111,6372,25,4445,3389,139,5631,8080,6379,445,7002,161,2100'.replace('.',',').replace('。',',').replace('，',',')
    if por == '1':
        por = "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144," \
        "146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458," \
        "464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687," \
        "691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990," \
        "992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138," \
        "1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218," \
        "1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417," \
        "1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688," \
        "1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972," \
        "1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107," \
        "2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383," \
        "2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725," \
        "2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3050," \
        "3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372," \
        "3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814," \
        "3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111," \
        "4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009," \
        "5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280," \
        "5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730," \
        "5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952," \
        "5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547," \
        "6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019," \
        "7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921," \
        "7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222," \
        "8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994," \
        "9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485," \
        "9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9943-9944,9968,9998-10004,10009-10010,10012," \
        "10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174," \
        "12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016," \
        "16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005," \
        "20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201," \
        "30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443," \
        "44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103," \
        "51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"

    print('\n-----------------------------\n扫描设置参数如下:\n\n扫描端口为:{}\n\n每秒发包量为:{}\n\n扫描进程数为:{}\n\n-----------------------------'.format(por,rat,pol))
    time.sleep(2)
    start_time = time.time()

    por = por.replace('，',',').replace(' ',',').replace(',,',',').replace('，，',',')
    print('\n')
    results = []
    p = Pool(int(pol))
    try:
        for ip in ips:
            a = IpInfoScan(ip)
            results.append(p.apply_async(func=a.GetResult, args=(por,rat,Portfolio)))
        p.close()
        p.join()
    except Exception as e:
        Log('扫描出现错误:{}'.format(str(e)))
        print('扫描出现异常:{}'.format(str(e)))


    res = [y for x in results for y in x.get()]

    res = [x for x in res if x!=None]

    TIME = str(int(str(time.time() - start_time).split('.')[0]) / 60).split('.')[0] + '分钟'
    if res == [] or res == None:
        print('\n扫描完毕~无存活IP~')
    else:
        CleanData(IPdata=res,txtfile=ImgTxt,htmlfile=ImgHtml,Portfolio=Portfolio)
        chk = WritePortsServicesIp(res,Xlsx)
        print('\n扫描完毕~耗时:{}~发现存活主机总数:{}台\nhtml结果保存在:{}\nxlsx结果保存在:{}'.format(TIME,len(res),os.path.join(os.path.abspath('..'),ImgHtml),os.path.join(os.path.abspath('..'),Xlsx)))
    while 1:
        time.sleep(500)