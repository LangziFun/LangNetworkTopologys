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
from concurrent.futures import ThreadPoolExecutor
requests.packages.urllib3.disable_warnings()
# from pyecharts.charts import Page, WordCloud
from multiprocessing import Pool
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

def Log(x):
    with open('../LangNetWorkTopoLog.txt','a+',encoding='utf-8')as a:
        a.write(str( '-'.join(str(datetime.datetime.now()).replace(' ','-').replace(':','-').split('.')[0].split('-')))+'    '+x+'\n')


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
        r = requests.get(url='http://'+url,headers=headers,verify=False,timeout=20)
        if b'text/html' in r.content or b'<title>' in r.content or b'</html>' in r.content:
            content1 = r.content
        if int(r.status_code) in Alive_Status:
            u = urlparse(str(r.url))
            title1 = get_title(r.content)
            url1 = u.scheme + '://' + u.netloc
    except Exception as e:
        pass
    try:
        r = requests.get(url='https://'+url,headers=headers,verify=False,timeout=20)
        if b'text/html' in r.content or b'<title>' in r.content or b'</html>' in r.content:
            content2 = r.content
        if int(r.status_code) in Alive_Status:
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
        Ret = []
        try:
            mas = masscan.PortScanner()
            #mas.scan(self.ip,ports='21,22,23,25,80,81,88,8080,8888,999,9999,7000,1433,1521,3306,3389,6379,7001,27017,27018')
            # 这里简单的扫一下普通端口即可
            mas.scan(self.ip, ports=inport, arguments='--rate {}'.format(rate))
            # if inport == '0':
            #     mas.scan(self.ip,arguments='--rate {}'.format(rate))
            # else:
            #     mas.scan(self.ip,ports=inport,arguments='--rate {}'.format(rate))
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

            retuls['time'] = str(datetime.datetime.now()).replace(' ', '-').replace(':', '-').split('.')[0]
            return retuls

    def GetResult(self,inport,rate,Portfolio):
        print('[{}]  端口扫描 : {}'.format(str(datetime.datetime.now()).split('.')[0], self.ip))
        Log('开始扫描IP:{}'.format(self.ip))
        if '-' in self.ip or '/' in self.ip:
            openports = self.GetOpenPort(inport,rate)
        else:
            openports = self.GetOneIPorts(self.ip,inport,rate)
        #openports = {'192.168.1.1':[22,23,25]}
        #openports = {'192.168.1.1':[22,23,25],'192.168.1.2':[80,8080]}
        if openports != {} and openports != None:
            print('\n[{}]  主机:{} 端口扫描完毕 存活主机共:{} 个 开始端口运行服务探测'.format(str(datetime.datetime.now()).split('.')[0],self.ip.ljust(15) ,
                                                               len(openports)))
            for ZHRNDAA in openports:
                for k, v in ZHRNDAA.items():
                    Log('主机 {} 开放端口 {} '.format(k, str(v)))
                    with open(os.path.join(Portfolio, 'AliveHosts') + '.txt', 'a+', encoding='utf-8')as b:
                        b.write(k + '\n')
            with ThreadPoolExecutor() as pool:
                results = pool.map(self.FeatureResult,openports)

            return list(results)



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
        <link rel="stylesheet" href='{0}/static/bootstrap-theme.min.css'>
        <link rel="stylesheet" href='{0}/static/bootstrap.min.css'>
		 <script type="text/javascript" src="{0}/static/echarts.min.js"></script>
		 <script type="text/javascript" src="{0}/static/echarts-wordcloud.min.js"></script>
        </head>
		<h1> 主机资产分布图</h1><hr/>

        '''.format(os.path.abspath('')))
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
if __name__ == '__main__':
    multiprocessing.freeze_support()
    Portfolio = 'CleanData/' + '-'.join(
        str(datetime.datetime.now()).replace(' ', '-').replace(':', '-').split('.')[0].split('-'))
    os.makedirs(Portfolio)

    ImgTxt = '-'.join(
        str(datetime.datetime.now()).replace(' ', '-').replace(':', '-').split('.')[0].split('-')) + '.txt'
    ImgHtml = '-'.join(
        str(datetime.datetime.now()).replace(' ', '-').replace(':', '-').split('.')[0].split('-')) + '.html'


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
    jindu = ' [*] LangNetworkTopology3 Console Start...'
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
    time.sleep(5)
    inp = input('导入IP文本:')
    ips = [x.replace('\n','').strip() for x in open(inp.replace('"',''),'r',encoding='utf-8').readlines()]
    por = input('输入扫描端口(21,22,80-888,6379,27017):')
    rat = input('设置每秒发包量(1000-100000):')
    pol = input('设置扫描进程数(1-4):')
    try:
        if 0<int(rat)<500000:
            pass
        if 0<int(pol)<4:
            pass
        else:
            print('进程数设置错误或者过大，准备死机吧')
    except:
        print('发包量或进程数设置错误')
        time.sleep(600)
    res = []
    if por == '0':
        por = '2375,1098,135,50030,27018,7777,8090,8099,873,514,8888,6002,4444,9110,4899,9200,1435,7000,27019,8161,9090,11211,1521,8093,3306,137,999,4950,1099,50070,6371,88,7003,1434,89,9999,513,87,2601,8009,9300,5632,1080,9043,512,8649,6000,22,5900,9001,2049,9990,6001,8089,50000,81,53,888,2439,9111,8088,1423,8873,23,8083,1527,1001,21,80,6003,525,3888,9000,30015,1433,389,27017,2888,8000,2638,2181,7001,111,6372,25,4445,3389,139,5631,8080,6379,445,7002,161,2100'
    start_time = time.time()

    por = por.replace('，',',').replace(' ',',').replace(',,',',')
    print('\n')
    results = []
    p = Pool(int(pol))
    for ip in ips:
        a = IpInfoScan(ip)
        results.append(p.apply_async(func=a.GetResult, args=(por,rat,Portfolio)))
    p.close()
    p.join()

    res = [y for x in results for y in x.get()]
    # print(res)

    # for ip in ips:
    #     a = IpInfoScan(ip)
    #     res.extend(a.GetResult(por.replace('，',',').replace(' ',',').replace(',,',','),rat))
    TIME = str(int(str(time.time() - start_time).split('.')[0]) / 60).split('.')[0] + '分钟'
    if res == [] or res == None:
        print('\n扫描完毕~无存活IP~')
    else:
        CleanData(IPdata=res,txtfile=ImgTxt,htmlfile=ImgHtml,Portfolio=Portfolio)
        print('\n扫描完毕~耗时:{}~\n结果保存在:{}'.format(TIME,os.path.join(os.path.abspath('..'),ImgHtml)))
    while 1:
        time.sleep(500)