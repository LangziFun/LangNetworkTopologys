# -*- coding:utf-8 -*-

import re
from urllib.parse import urlparse
import masscan
import requests
import socket
import datetime
filenames = '-'.join(str(datetime.datetime.now()).replace(' ','-').replace(':','-').split('.')[0].split('-'))+'.txt'
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
        r = requests.get(url='http://'+url,headers=headers,verify=False,timeout=5)
        if b'Unauthorized' in r.content and b'MAC Address' in r.content and b'IP Address' in r.content:
            return None
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
                if b'Unauthorized' in rec and b'MAC Address' in rec and b'IP Address' in rec:
                    return None
                if b'HTTP' in rec:
                    u = urlparse(str(r.url))
                    title1 = get_title(rec)+'--通过TCP连接端口方式获取信息'
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
            if b'Unauthorized' in rec and b'MAC Address' in rec and b'IP Address' in rec:
                return None
            if b'HTTP' in rec:
                u = urlparse(str('http://'+url))
                title1 = get_title(rec)+'--通过TCP连接端口方式获取信息'
                url1 = u.scheme + '://' + u.netloc
        except Exception as e:
            pass
        finally:
            s.close()
    try:
        r = requests.get(url='https://'+url,headers=headers,verify=False,timeout=5)
        if b'Unauthorized' in r.content and b'MAC Address' in r.content and b'IP Address' in r.content:
            return None
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
                if b'Unauthorized' in rec and b'MAC Address' in rec and b'IP Address' in rec:
                    return None
                if b'HTTP' in rec:
                    u = urlparse(str(r.url))
                    title2 = get_title(rec) +'--通过TCP连接端口方式获取信息'
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
    try:
        result = [y for x in result  for y in x]
        return result
    except:
        return []

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
        #self.Banner = {b'http': [b'^HTTP/.*\nServer: Apache/2',b'HTTP/'], b'ssh': [b'^SSH-.*openssh'], b'netbios': [b'\xc2\x83\x00\x00\x01\xc2\x8f'], b'backdoor-fxsvc': [b'^500 Not Loged in'], b'backdoor-shell': [b'^sh[$#]'], b'bachdoor-shell': [b'[a-z]*sh: .* command not found'], b'backdoor-cmdshell': [b'^Microsoft Windows .* Copyright .*>'], b'db2': [b'.*SQLDB2RA'], b'db2jds': [b'^N\x00'], b'dell-openmanage': [b'^N\x00\r'], b'finger': [b'finger: GET: '], b'ftp': [b'^220 .* UserGate'], b'http-iis': [b'^<h1>Bad Request .Invalid URL.</h1>'], b'http-jserv': [b'^HTTP/.*Cookie.*JServSessionId'], b'http-tomcat': [b'.*Servlet-Engine'], b'http-weblogic': [b'^HTTP/.*Cookie.*WebLogicSession'], b'http-vnc': [b'^HTTP/.*RealVNC/'], b'ldap': [b'^0E'], b'smb': [b'^\x00\x00\x00.\xc3\xbfSMBr\x00\x00\x00\x00.*'], b'msrdp': [b'^\x03\x00\x00\x0b\x06\xc3\x90\x00\x004\x12\x00'], b'msrdp-proxy': [b'^nmproxy: Procotol byte is not 8\n$'], b'msrpc': [b'\x05\x00\r\x03\x10\x00\x00\x00\x18\x00\x00\x00....\x04\x00\x01\x05\x00\x00\x00\x00$'], b'mssql': [b';MSSQLSERVER;'], b'telnet': [b'^\xc3\xbf\xc3\xbe'], b'mysql': [b"whost '"], b'mysql-blocked': [b'^\\(\x00\x00'], b'mysql-secured': [b'this MySQL'], b'mongodb': [b'^.*version.....([\\.\\d]+)'], b'nagiosd': [b'Sorry, you \\(.*are not among the allowed hosts...'], b'nessus': [b'< NTP 1.2 >\nUser:'], b'oracle-tns-listener': [b'\\(ADDRESS=\\(PROTOCOL='], b'oracle-dbsnmp': [b'^\x00\x0c\x00\x00\x04\x00\x00\x00\x00'], b'oracle-https': [b'^220- ora'], b'oracle-rmi': [b'^N\x00\t'], b'postgres': [b'^EFATAL'], b'rlogin': [b'^\x01Permission denied.\n'], b'rpc-nfs': [b'^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00'], b'rpc': [b'^\xc2\x80\x00\x00'], b'rsync': [b'^@RSYNCD:.*'], b'smux': [b'^A\x01\x02\x00'], b'snmp-public': [b'public\xc2\xa2'], b'snmp': [b'A\x01\x02'], b'socks': [b'^\x05[\x00-\x08]\x00'], b'ssl': [b'^\x16\x03\x00..\x02...\x03\x00'], b'sybase': [b'^\x04\x01\x00'], b'tftp': [b'^\x00[\x03\x05]\x00'], b'uucp': [b'^login: password: '], b'vnc': [b'^RFB.*'], b'webmin': [b'^0\\.0\\.0\\.0:.*:[0-9]'], b'websphere-javaw': [b'^\x15\x00\x00\x00\x02\x02\n']}
        # self.Banner = {b'http': [b'^HTTP/.*\nServer: Apache/2', b'HTTP', b'http/1.1', b'http/1.0'], b'ssh': [b'^SSH-.*openssh', b'^ssh-', b'connection refused by remote host.'], b'netbios': [b'\xc2\x83\x00\x00\x01\xc2\x8f', b'^y\x08.*browse', b'^y\x08.\x00\x00\x00\x00', b'^\x05\x00\r\x03', b'^\x82\x00\x00\x00', b'\x83\x00\x00\x01\x8f'], b'backdoor-fxsvc': [b'^500 Not Loged in'], b'backdoor-shell': [b'^sh[$#]'], b'bachdoor-shell': [b'[a-z]*sh: .* command not found'], b'backdoor-cmdshell': [b'^Microsoft Windows .* Copyright .*>'], b'db2': [b'.*SQLDB2RA', b'.*sqldb2ra'], b'db2jds': [b'^N\x00', b'^n\x00'], b'dell-openmanage': [b'^N\x00\r'], b'finger': [b'finger: GET: ', b'^\r\n\tline\t  user', b'line\t user', b'login name: ', b'login.*name.*tty.*idle', b'^no one logged on', b'^\r\nwelcome', b'^finger:', b'^must provide username', b'finger: get: '], b'ftp': [b'^220 .* UserGate', b'^220.*\n331', b'^220.*\n530', b'^220.*ftp', b'^220 .* microsoft .* ftp', b'^220 inactivity timer', b'^220 .* usergate', b'^220.*filezilla server', b'^220-', b'^220.*?ftp', b'^220.*?filezilla'], b'http-iis': [b'^<h1>Bad Request .Invalid URL.</h1>'], b'http-jserv': [b'^HTTP/.*Cookie.*JServSessionId'], b'http-tomcat': [b'.*Servlet-Engine'], b'http-weblogic': [b'^HTTP/.*Cookie.*WebLogicSession'], b'http-vnc': [b'^HTTP/.*RealVNC/'], b'ldap': [b'^0E', b'^0\x0c\x02\x01\x01a', b'^02\x02\x01', b'^03\x02\x01', b'^08\x02\x01', b'^0\x84', b'^0e'], b'smb': [b'^\x00\x00\x00.\xc3\xbfSMBr\x00\x00\x00\x00.*', b'^\x00\x00\x00.\xffsmbr\x00\x00\x00\x00.*', b'^\x83\x00\x00\x01\x8f'], b'msrdp': [b'^\x03\x00\x00\x0b\x06\xc3\x90\x00\x004\x12\x00'], b'msrdp-proxy': [b'^nmproxy: Procotol byte is not 8\n$'], b'msrpc': [b'\x05\x00\r\x03\x10\x00\x00\x00\x18\x00\x00\x00....\x04\x00\x01\x05\x00\x00\x00\x00$', b'^\x05\x00\r\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00', b'\x05\x00\r\x03\x10\x00\x00\x00\x18\x00\x00\x00....\x04\x00\x01\x05\x00\x00\x00\x00$'], b'mssql': [b';MSSQLSERVER;', b'^\x05n\x00', b'^\x04\x01', b';mssqlserver;', b'mssqlserver'], b'telnet': [b'^\xc3\xbf\xc3\xbe', b'telnet', b'^\xff[\xfa-\xff]', b'^\r\n%connection closed by remote host!\x00$'], b'mysql': [b"whost '", b'mysql_native_password', b'^\x19\x00\x00\x00\n', b'^,\x00\x00\x00\n', b"hhost '", b"khost '", b'mysqladmin', b"whost '", b'^[.*]\x00\x00\x00\n.*?\x00', b'this mysql server', b'mariadb server', b'\x00\x00\x00\xffj\x04host'], b'mysql-blocked': [b'^\\(\x00\x00'], b'mysql-secured': [b'this MySQL'], b'mongodb': [b'^.*version.....([\\.\\d]+)', b'mongodb'], b'nagiosd': [b'Sorry, you \\(.*are not among the allowed hosts...', b'sorry, you \\(.*are not among the allowed hosts...'], b'nessus': [b'< NTP 1.2 >\nUser:', b'< ntp 1.2 >\nuser:'], b'oracle-tns-listener': [b'\\(ADDRESS=\\(PROTOCOL=', b'\\(error_stack=\\(error=\\(code=', b'\\(address=\\(protocol='], b'oracle-dbsnmp': [b'^\x00\x0c\x00\x00\x04\x00\x00\x00\x00', b'^\x00\x0c\x00\x00\x04\x00\x00\x00\x00'], b'oracle-https': [b'^220- ora', b'^220- ora'], b'oracle-rmi': [b'^N\x00\t'], b'postgres': [b'^EFATAL'], b'rlogin': [b'^\x01Permission denied.\n', b'login: ', b'rlogind: ', b'^\x01permission denied.\n'], b'rpc-nfs': [b'^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00', b'^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00'], b'rpc': [b'^\xc2\x80\x00\x00', b'\x01\x86\xa0', b'\x03\x9beb\x00\x00\x00\x01', b'^\x80\x00\x00'], b'rsync': [b'^@RSYNCD:.*', b'^@rsyncd:', b'@rsyncd:'], b'smux': [b'^A\x01\x02\x00', b'^a\x01\x02\x00'], b'snmp-public': [b'public\xc2\xa2', b'public\xa2'], b'snmp': [b'A\x01\x02', b'a\x01\x02'], b'socks': [b'^\x05[\x00-\x08]\x00', b'^\x05[\x00-\x08]\x00'], b'ssl': [b'^\x16\x03\x00..\x02...\x03\x00', b'^..\x04\x00.\x00\x02', b'^\x16\x03\x01..\x02...\x03\x01', b'^\x16\x03\x00..\x02...\x03\x00', b'ssl.*get_client_hello', b'^-err .*tls_start_servertls', b'^\x16\x03\x00\x00j\x02\x00\x00f\x03\x00', b'^\x16\x03\x00..\x02\x00\x00f\x03\x00', b'^\x15\x03\x00\x00\x02\x02\\.*', b'^\x16\x03\x01..\x02...\x03\x01', b'^\x16\x03\x00..\x02...\x03\x00'], b'sybase': [b'^\x04\x01\x00', b'^\x04\x01\x00'], b'tftp': [b'^\x00[\x03\x05]\x00', b'^\x00[\x03\x05]\x00'], b'uucp': [b'^login: password: ', b'^login: password: '], b'vnc': [b'^RFB.*', b'^rfb'], b'webmin': [b'^0\\.0\\.0\\.0:.*:[0-9]', b'.*miniserv', b'^0\\.0\\.0\\.0:.*:[0-9]'], b'websphere-javaw': [b'^\x15\x00\x00\x00\x02\x02\n', b'^\x15\x00\x00\x00\x02\x02\n'], b'xmpp': [b"^\\<\\?xml version='1.0'\\?\\>"], b'backdoor': [b'^500 not loged in', b'get: command', b'sh: get:', b'^bash[$#]', b'^sh[$#]', b'^microsoft windows'], b'bachdoor': [b'*sh: .* command not found'], b'rdp': [b'^\x00\x01\x00.*?\r\n\r\n$', b'^\x03\x00\x00\x0b', b'^\x03\x00\x00\x11', b'^\x03\x00\x00\x0b\x06\xd0\x00\x00\x12.\x00$', b'^\x03\x00\x00\x17\x08\x02\x00\x00z~\x00\x0b\x05\x05@\x06\x00\x08\x91j\x00\x02x$', b'^\x03\x00\x00\x11\x08\x02..}\x08\x03\x00\x00\xdf\x14\x01\x01$', b'^\x03\x00\x00\x0b\x06\xd0\x00\x00\x03.\x00$', b'^\x03\x00\x00\x0b\x06\xd0\x00\x00\x00\x00\x00', b'^\x03\x00\x00\x0e\t\xd0\x00\x00\x00[\x02\xa1]\x00\xc0\x01\n$', b'^\x03\x00\x00\x0b\x06\xd0\x00\x004\x12\x00'], b'rdp-proxy': [b'^nmproxy: procotol byte is not 8\n$'], b'rmi': [b'\x00\x00\x00vinva', b'^n\x00\t'], b'postgresql': [b'invalid packet length', b'^efatal'], b'imap': [b'^\\* ok.*?imap'], b'pop': [b'^\\+ok.*?'], b'smtp': [b'^220.*?smtp', b'^554 smtp'], b'rtsp': [b'^rtsp/'], b'sip': [b'^sip/'], b'nntp': [b'^200 nntp'], b'sccp': [b'^\x01\x00\x00\x00$'], b'squid': [b'x-squid-error'], b'vmware': [b'vmware'], b'iscsi': [b'\x00\x02\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'], b'redis': [b'^-err unknown command', b'^-err wrong number of arguments', b'^-denied redis is running'], b'memcache': [b'^error\r\n'], b'websocket': [b'server: websocket'], b'https': [b'instead use the https scheme to accesshttps', b'http request to an https server', b'location: https'], b'svn': [b'^\\( success \\( 2 2 \\( \\) \\( edit-pipeline svndiff1'], b'dubbo': [b'^unsupported command'], b'elasticsearch': [b'cluster_name.*elasticsearch'], b'rabbitmq': [b'^amqp\x00\x00\t\x01'], b'zookeeper': [b'^zookeeper version: ']}
        # 2019-12-30 更新指纹
        self.Banner = {b'http': [b'^HTTP/.*\nServer: Apach', b'^HTTP/.*\nServer: nginx', b'HTTP.*?text/html', b'http.*?</html>'], b'ssh': [b'^SSH-.*openssh', b'^ssh-', b'connection refused by remote host.'], b'netbios': [b'\xc2\x83\x00\x00\x01\xc2\x8f', b'^y\x08.*browse', b'^y\x08.\x00\x00\x00\x00', b'^\x05\x00\r\x03', b'^\x82\x00\x00\x00', b'\x83\x00\x00\x01\x8f'], b'backdoor-fxsvc': [b'^500 Not Loged in'], b'backdoor-shell': [b'^sh[$#]'], b'bachdoor-shell': [b'[a-z]*sh: .* command not found'], b'backdoor-cmdshell': [b'^Microsoft Windows .* Copyright .*>'], b'db2': [b'.*SQLDB2RA', b'.*sqldb2ra'], b'db2jds': [b'^N\x00', b'^n\x00'], b'dell-openmanage': [b'^N\x00\r'], b'finger': [b'finger: GET: ', b'^\r\n\tline\t  user', b'line\t user', b'login name: ', b'login.*name.*tty.*idle', b'^no one logged on', b'^\r\nwelcome', b'^finger:', b'^must provide username', b'finger: get: '], b'ftp': [b'^220 .* UserGate', b'^220.*\n331', b'^220.*\n530', b'^220.*ftp', b'^220 .* microsoft .* ftp', b'^220 inactivity timer', b'^220 .* usergate', b'^220.*filezilla server', b'^220-', b'^220.*?ftp', b'^220.*?filezilla'], b'http-iis': [b'^<h1>Bad Request .Invalid URL.</h1>'], b'http-jserv': [b'^HTTP/.*Cookie.*JServSessionId'], b'http-tomcat': [b'.*Servlet-Engine'], b'http-weblogic': [b'^HTTP/.*Cookie.*WebLogicSession'], b'http-vnc': [b'^HTTP/.*RealVNC/'], b'ldap': [b'^0E', b'^0\x0c\x02\x01\x01a', b'^02\x02\x01', b'^03\x02\x01', b'^08\x02\x01', b'^0\x84', b'^0e'], b'smb': [b'^\x00\x00\x00.\xc3\xbfSMBr\x00\x00\x00\x00.*', b'^\x00\x00\x00.\xffsmbr\x00\x00\x00\x00.*', b'^\x83\x00\x00\x01\x8f'], b'msrdp': [b'^\x03\x00\x00\x0b\x06\xc3\x90\x00\x004\x12\x00'], b'msrdp-proxy': [b'^nmproxy: Procotol byte is not 8\n$'], b'msrpc': [b'\x05\x00\r\x03\x10\x00\x00\x00\x18\x00\x00\x00....\x04\x00\x01\x05\x00\x00\x00\x00$', b'^\x05\x00\r\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00', b'\x05\x00\r\x03\x10\x00\x00\x00\x18\x00\x00\x00....\x04\x00\x01\x05\x00\x00\x00\x00$'], b'mssql': [b';MSSQLSERVER;', b'^\x05n\x00', b'^\x04\x01', b';mssqlserver;', b'mssqlserver'], b'telnet': [b'^\xc3\xbf\xc3\xbe', b'telnet', b'^\xff[\xfa-\xff]', b'^\r\n%connection closed by remote host!\x00$'], b'mysql': [b"whost '", b'mysql_native_password', b'^\x19\x00\x00\x00\n', b'^,\x00\x00\x00\n', b"hhost '", b"khost '", b'mysqladmin', b"whost '", b'^[.*]\x00\x00\x00\n.*?\x00', b'this mysql server', b'mariadb server', b'\x00\x00\x00\xffj\x04host'], b'mysql-blocked': [b'^\\(\x00\x00'], b'mysql-secured': [b'this MySQL'], b'mongodb': [b'^.*version.....([\\.\\d]+)', b'mongodb'], b'nagiosd': [b'Sorry, you \\(.*are not among the allowed hosts...', b'sorry, you \\(.*are not among the allowed hosts...'], b'nessus': [b'< NTP 1.2 >\nUser:', b'< ntp 1.2 >\nuser:'], b'oracle-tns-listener': [b'\\(ADDRESS=\\(PROTOCOL=', b'\\(error_stack=\\(error=\\(code=', b'\\(address=\\(protocol='], b'oracle-dbsnmp': [b'^\x00\x0c\x00\x00\x04\x00\x00\x00\x00', b'^\x00\x0c\x00\x00\x04\x00\x00\x00\x00'], b'oracle-https': [b'^220- ora', b'^220- ora'], b'oracle-rmi': [b'^N\x00\t'], b'postgres': [b'^EFATAL'], b'rlogin': [b'^\x01Permission denied.\n', b'login: ', b'rlogind: ', b'^\x01permission denied.\n'], b'rpc-nfs': [b'^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00', b'^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00'], b'rpc': [b'^\xc2\x80\x00\x00', b'\x01\x86\xa0', b'\x03\x9beb\x00\x00\x00\x01', b'^\x80\x00\x00'], b'rsync': [b'^@RSYNCD:.*', b'^@rsyncd:', b'@rsyncd:'], b'smux': [b'^A\x01\x02\x00', b'^a\x01\x02\x00'], b'snmp-public': [b'public\xc2\xa2', b'public\xa2'], b'snmp': [b'A\x01\x02', b'a\x01\x02'], b'socks': [b'^\x05[\x00-\x08]\x00', b'^\x05[\x00-\x08]\x00'], b'ssl': [b'^\x16\x03\x00..\x02...\x03\x00', b'^..\x04\x00.\x00\x02', b'^\x16\x03\x01..\x02...\x03\x01', b'^\x16\x03\x00..\x02...\x03\x00', b'ssl.*get_client_hello', b'^-err .*tls_start_servertls', b'^\x16\x03\x00\x00j\x02\x00\x00f\x03\x00', b'^\x16\x03\x00..\x02\x00\x00f\x03\x00', b'^\x15\x03\x00\x00\x02\x02\\.*', b'^\x16\x03\x01..\x02...\x03\x01', b'^\x16\x03\x00..\x02...\x03\x00'], b'sybase': [b'^\x04\x01\x00', b'^\x04\x01\x00'], b'tftp': [b'^\x00[\x03\x05]\x00', b'^\x00[\x03\x05]\x00'], b'uucp': [b'^login: password: ', b'^login: password: '], b'vnc': [b'^RFB.*', b'^rfb'], b'webmin': [b'^0\\.0\\.0\\.0:.*:[0-9]', b'.*miniserv', b'^0\\.0\\.0\\.0:.*:[0-9]'], b'websphere-javaw': [b'^\x15\x00\x00\x00\x02\x02\n', b'^\x15\x00\x00\x00\x02\x02\n'], b'xmpp': [b"^\\<\\?xml version='1.0'\\?\\>"], b'backdoor': [b'^500 not loged in', b'get: command', b'sh: get:', b'^bash[$#]', b'^sh[$#]', b'^microsoft windows'], b'bachdoor': [b'*sh: .* command not found'], b'rdp': [b'^\x00\x01\x00.*?\r\n\r\n$', b'^\x03\x00\x00\x0b', b'^\x03\x00\x00\x11', b'^\x03\x00\x00\x0b\x06\xd0\x00\x00\x12.\x00$', b'^\x03\x00\x00\x17\x08\x02\x00\x00z~\x00\x0b\x05\x05@\x06\x00\x08\x91j\x00\x02x$', b'^\x03\x00\x00\x11\x08\x02..}\x08\x03\x00\x00\xdf\x14\x01\x01$', b'^\x03\x00\x00\x0b\x06\xd0\x00\x00\x03.\x00$', b'^\x03\x00\x00\x0b\x06\xd0\x00\x00\x00\x00\x00', b'^\x03\x00\x00\x0e\t\xd0\x00\x00\x00[\x02\xa1]\x00\xc0\x01\n$', b'^\x03\x00\x00\x0b\x06\xd0\x00\x004\x12\x00'], b'rdp-proxy': [b'^nmproxy: procotol byte is not 8\n$'], b'rmi': [b'\x00\x00\x00vinva', b'^n\x00\t'], b'postgresql': [b'invalid packet length', b'^efatal'], b'imap': [b'^\\* ok.*?imap'], b'pop': [b'^\\+ok.*?'], b'smtp': [b'^220.*?smtp', b'^554 smtp'], b'rtsp': [b'^rtsp/'], b'sip': [b'^sip/'], b'nntp': [b'^200 nntp'], b'sccp': [b'^\x01\x00\x00\x00$'], b'squid': [b'x-squid-error'], b'vmware': [b'vmware'], b'iscsi': [b'\x00\x02\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'], b'redis': [b'^-err unknown command', b'^-err wrong number of arguments', b'^-denied redis is running'], b'memcache': [b'^error\r\n'], b'websocket': [b'server: websocket'], b'https': [b'instead use the https scheme to accesshttps', b'http request to an https server', b'location: https'], b'svn': [b'^\\( success \\( 2 2 \\( \\) \\( edit-pipeline svndiff1'], b'dubbo': [b'^unsupported command'], b'elasticsearch': [b'cluster_name.*elasticsearch'], b'rabbitmq': [b'^amqp\x00\x00\t\x01'], b'zookeeper': [b'^zookeeper version: ']}
        # 2020-01-29 更新指纹

    def GetOpenPort(self):
        HostInfos = {}
        try:
            mas = masscan.PortScanner()
            mas.scan(self.ip,ports='21,22,23,25,80,81,88,8080,8888,999,9999,7000,1433,1521,3306,3389,6379,7001,27017,27018')
            # 这里简单的扫一下普通端口即可
            Results = mas.scan_result['scan']
            AliveHosts = list(Results.keys())
            if AliveHosts != []:
                for k, v in Results.items():
                    HostInfos[str(k)] = list(v['tcp'].keys())
            return HostInfos
        except Exception as e:
            pass
        return HostInfos

    def GetOneIPorts(self,ip):
        try:
            mas = masscan.PortScanner()
            mas.scan(self.ip,ports='21,22,23,25,80,81,88,8080,8888,999,9999,7000,1433,1521,3306,3389,6379,7001,27017,27018')
            OpenPorts = mas.scan_result['scan'][ip]['tcp'].keys()
        except:
            return None
        return {ip:OpenPorts}
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
            for k in list(PortInfos.keys()):
                if PortInfos[k] == '获取失败':
                    Cpo = self.CheckPortOpen(ip,k)
                    # 进一步复检，提升准确率
                    if Cpo == True:
                        PortInfos[k] = GetPortInfo(str(k))
                    else:
                        del PortInfos[k]
        return PortInfos

    def GetResult(self):
        results = []
        print('[{}]  端口扫描 : {}'.format(str(datetime.datetime.now()).split('.')[0], self.ip))
        if '-' in self.ip or '/' in self.ip:
            openports = self.GetOpenPort()
        else:
            openports = self.GetOneIPorts(self.ip)
        #openports = [80,3389]
        if openports != {} and openports != None:
            for k,v in openports.items():
                retuls = {}
                print('[{}]  主机 {} 开放端口 {}个'.format(str(datetime.datetime.now()).split('.')[0], k,len(v)))
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
        return results


if __name__ == '__main__':
    ip = '118.24.11.235'
    a = IpInfoScan(ip)
    res = a.GetResult()
    print(res)
