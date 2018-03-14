#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import time
import logging
import urllib
import urllib2
import base64
import telnetlib
from logging.handlers import RotatingFileHandler

logger = None
route = {
    "input": {
		"item":"/route-optimize:rpc-bgp-msg/route-optimize:item[route-optimize:id='route-optimize']",
        "vrfNameList": [
            {
                "vrfName": "1"
            }
        ],
        "add": "1",
        "prefix": "8.8.8.8/24",
        "timestamp": "201170102104720570",
        "allTix": "1",
        "tixNameList": [
            {
                "tixName": "test"
            }
        ]
    }
}

def getRestHeader(username='admin', password='admin'):
    base64string = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
    headers = {'Content-Type': 'application/json', "Authorization" : "Basic %s" % base64string}
    return headers
    
def getDDosUrl(host):
    return 'http://{}:8181/restconf/operations/route-optimize:ddos-route-proc'.format(host)
    
def postReques(requestUrl, headers, data):
    request = urllib2.Request(url=requestUrl, headers=headers, data=json.dumps(route))
    result = urllib2.urlopen(request)
    return result.read()

def getIp(count, ip='1.1.1.1'):
    count = int(count)  
    ip2 = int(ip.split('.')[-2])  
    ip1 = int(ip.split('.')[-1])  
    ip_before = '%s.%s' % (ip.split('.')[0], ip.split('.')[1])
    ipList = []
    for i in range(0,count):  
            new_ip1 = ip1 + i  
            if  11 <= new_ip1 <= 254:  
                ipList.append('%s.%s.%s' % (ip_before, str(ip2), str(new_ip1)))   
            else:  
                new_ip2 = ip2 + int(new_ip1/254)  
                new_ip1 = new_ip1%254 + 1  
                ipList.append('%s.%s.%s' % (ip_before, str(new_ip2), str(new_ip1)))
    logger.debug("getIp result %s" % ipList)
    return list(set(ipList))
    
def addOrRemoveDDOSFrenquently(controllerIp, testCount=10):
    logger.info("start to test case addOrRemoveDDOSFrenquently, controllerIp %s testCount %s" % (controllerIp, testCount))
    headers = getRestHeader()
    
    startTime = time.clock()
    for num in range(1, testCount):
        if num % 2 == 1:
            route['input']['add'] = '1'
        else:
            route['input']['add'] = '0'
        
        try:
            result = postReques(getDDosUrl(controllerIp), headers, route)
            logger.debug("request data %s, result %s" % (route, result))
            if  result != '{"output":{"code":0}}':
                logger.warn("request to controllerIp %s error, data %s, result %s" % (controllerIp, route, result))
            else:
                logger.info("request to controllerIp %s successful" % controllerIp)
        except Exception, e:
            logger.error("request to controllerIp %s error, data %s, catch exception %s" % (controllerIp, route, str(e)))
            return
    endtime = time.clock()
    logger.info("addOrRemoveDDOS: Finish Test,  request %s count to controllerIp %s, time %s" % (num, controllerIp, (endtime-startTime)))

def operateDDOSRoutes(controllerIp, isAdd=True, addCount=10):
    logger.info("Start to test case addDDOSRoutes, controllerIp %s addCount %s" % (controllerIp, addCount))
    headers = getRestHeader()
    l = getIp(addCount, '1.1.1.1')

    opt = 'ADD'
    if isAdd:
        route['input']['add'] = "1"
    else:
        opt = 'DELETE'
        route['input']['add'] = "0"
    startTime = time.clock()
    for num in range(0, len(l)):
        '''
        if num % 2 == 1:
            route['input']['add'] = "1"
        else:
            route['input']['add'] = "0"
        '''
        route['input']['prefix'] = l[num] + "/32"
        prefix = route['input']['prefix'];
        try:
            result = postReques(getDDosUrl(controllerIp), headers, route)
            if  result != '{"output":{"code":0}}':
                logger.warn("opt: %s, request prefix %s to controllerIp %s error, data %s, result %s" % (opt, prefix, controllerIp, route, result))
            else:
                logger.info("opt: %s, request prefix %s to controllerIp %s successful" % (opt, prefix, controllerIp))
        except Exception, e:
            logger.error("opt: %s, request prefix %s to controllerIp %s error, data %s, catch exception %s" % (opt, prefix, controllerIp, route, str(e)))
            

    endtime = time.clock()
    logger.info("operateDDOS: Finish Test, request %s count to controllerIp %s, time %s" % (num, controllerIp, (endtime-startTime)))

def initLog(logName):
    global logger
    logger = logging.getLogger(logName)
    
    rthandler = RotatingFileHandler('bgp-test.log', maxBytes=10*1024*1024, backupCount=5)
    rthandler.setLevel(logging.INFO)
    
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
    logging.basicConfig(level=logging.INFO)
    rthandler.setFormatter(formatter)
    
    logger.addHandler(rthandler)

def sys_exit(msg=None, exit_code=1):
    if msg is not None:
        print msg

    sys.exit(exit_code)

def telnetLogin(host=None, username=None, password=None, command=None):
    if not host or not username or not password:
        logger.info("host %s or username %s or password %s should not be null" % (host, username, password))
        sys_exit("host should not be null")
    '''
        Telnet 远程登录
    '''
    # connect telnet server
    try:
        logger.info("loggin dev %s, usename %s" % (host, username))
        tn = telnetlib.Telnet(host, port=23, timeout=10)
    except Exception, e:
        logger.error("loggin dev %s, username %s failed, error %s." % (host, username, str(e)))
        sys_exit(str(e))

    tn.set_debuglevel(0)
    
    # input login name
    tn.read_until('Username:')
    tn.write(username + '\n')
    
    # input password
    tn.read_until('Password:')
    tn.write(password + '\n')
    
    '''
    # execute command
    tn.write(command + '\n')
    
    i = 1
    while (i > 0):
        expectResult = tn.expect([' --More'], timeout=3)
        # print "%s %s" % (i, expectResult)
        if (len(expectResult) > 2) and expectResult[1]:
            tn.write(' ' + '\n')
            expectResult = None
        else:
            break;
    '''
    # tn.read_eager()
    logger.info("loggin %s successful." % host)
    return tn

def matchCmdResult(matchStr, result):
    if not matchStr or not result:
        return False
        
    logger.debug("Context %s , match string %s" % (result, matchStr))
    p = re.compile(matchStr.replace('.', '\.'))
    ret = p.search(result)
    if ret is not None:
        logger.debug("matchStr %s is matched, group %s.",  matchStr, ret.group())
        return True
    return False

def checkExcuteResult(ips, devResult, isRevert=False):
    if not isRevert:
        for ip in ips:
            if matchCmdResult(ip, devResult):
                continue
            else:
                logger.warn("CheckResult: ip %s not found in device" % ip)
    else:
        for ip in ips:
            if not matchCmdResult(ip, devResult):
                continue
            else:
                logger.warn("CheckResult: ip %s found in device" % ip)
    logger.info("Test OK............")
    
def executCommand(instance, command, isList=True):
    if not instance:
        return None
    
    logger.info("execute cmd %s" % command)
    cmdResult = ''
    instance.write(command + "\n")
    
    i = 1
    while i > 0:
        expectResult = instance.expect([' --More*'], timeout=3)
        # print "%s %s" % (i, expectResult)
        cmdResult += expectResult[2]
        if (len(expectResult) > 2) and expectResult[1]:
            instance.write(' ' + '\n')
            expectResult = None
        else:
            break;
    
    logger.info("cmd %s execute complete, cmdResult %s" % (command, cmdResult))
    
    if isList:
        return cmdResult.replace('\r', '').strip().splitlines()
    else:
        return cmdResult.replace('\r', '').strip()

def telnetLogout(telnetInstance):
    if not telnetInstance:
        return
    try:
        telnetInstance.close()
    except Exception, e:
        sys_exit(str(e))
    
def main():
    clusterIps = ['172.18.34.243', '172.18.34.244', '172.18.34.245']
    devIps = ['192.168.23.191', '172.18.106.204']
    testCount = 101
    requestIp = clusterIps[0]
    operateSleepTime = 2
    
    initLog('bgp-test')

    tn = telnetLogin(devIps[0], 'adm', 'adm')
    tn1 = telnetLogin(devIps[1], 'ruijie', 'ruijie')
    telnetInstances = {devIps[0]: tn, devIps[1]: tn1}

    print "--"*20
    print getIp(testCount)
    print telnetInstances
    print "--"*20
    
    '''
    print "--"*20
    print executCommand(tn, "show bgp all")
    print "--"*20
    print executCommand(tn, "show ip bgp neighbors 192.168.23.240 routes")
    print "--"*20
    '''
    # 100 0000
    for i in range(0, 1000000):
        '''
            add and delete frequently.
        '''
        addOrRemoveDDOSFrenquently(requestIp, testCount)
        time.sleep(operateSleepTime)
        l = ['8.8.8.8']
        for key in telnetInstances.keys():
            logger.info("addOrRemoveDDOS: get route from dev %s", key)
            telInstance = telnetInstances.get(key)
            for clusterIp in clusterIps:
                test1Result = executCommand(telInstance, "show ip bgp neighbors %s routes" % clusterIp, False)
                print "--"*20
                print test1Result
                print "+"*20
                checkExcuteResult(l, test1Result, True)
                print "+"*20
                print "--"*20
        
        '''
            add route
        '''
        operateDDOSRoutes(requestIp, True, testCount)
        time.sleep(operateSleepTime)
        for key in telnetInstances.keys():
            logger.info("operateDDOS: get route from dev %s", key)
            telInstance = telnetInstances.get(key)
            for clusterIp in clusterIps:
                test2Result = executCommand(telInstance, "show ip bgp neighbors %s routes" % clusterIp, False)
                print "--"*20
                print test2Result
                print "+"*20
                checkExcuteResult(getIp(testCount), test2Result)
                print "+"*20
                print "--"*20
        
        '''
            delete route
        '''
        operateDDOSRoutes(requestIp, False, testCount)
        time.sleep(operateSleepTime)
        for key in telnetInstances.keys():
            logger.info("operateDDOS: get route from dev %s", key)
            telInstance = telnetInstances.get(key)
            for clusterIp in clusterIps:
                test3Result = executCommand(telInstance, "show ip bgp neighbors %s routes" % clusterIp, False)
                print "--"*20
                print test3Result
                print "+"*20
                checkExcuteResult(getIp(testCount), test3Result, True)
                print "+"*20
                print "--"*20
            
        time.sleep(5)
    
    telnetLogout(tn)
    telnetLogout(tn1)
    

if __name__ == "__main__":
    main()
    
