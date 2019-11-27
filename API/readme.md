# 网络资产自动化拓扑

实现对主机开放端口服务的自动化数据采集

# 需求

实现自动化的内网存活主机，开放端口，运行服务监控

# API设计

输入接口： 

	网段 192.168.0.0/24 
    独立IP 192.168.1.8
    
调用方法：    
  
    ip = '118.24.11.0/24'
    a = IpInfoScan(ip)
    res = a.GetResult()
    print(res)    

or:

    ip = '118.24.11.5'
    a = IpInfoScan(ip)
    res = a.GetResult()
    print(res)    

输出结果：

    [{
     ip:192.168.0.1,
     alive:True,
     ports:[22,80,8888,3306]
     server:['ssh','http','https','mysql'],
     services:{22:ssh,80:http.....},
     urls:{'http://192.168.0.1:80':后台管理系统}
     time:2019-11-20-13:15
    }]