import urllib;
import urllib2;
import json

def get(url):
    username="admin"
    password="admin"
    auth=urllib2.HTTPDigestAuthHandler()
    auth.add_password("R Open Networking Platform", url, username, password)
    opener=urllib2.build_opener(auth)
    urllib2.install_opener(opener)
    res_data=urllib2.urlopen(url)
    res=res_data.read()
    print res

def post(requrl, data):
    username="admin"
    password="admin"
    reqdata = json.dumps(data)
    auth=urllib2.HTTPDigestAuthHandler()
    auth.add_password("R Open Networking Platform", requrl, username, password)
    opener=urllib2.build_opener(auth)
    headers = {"Content-type": "application/json","Accept": "application/json"}
    req = urllib2.Request(url=requrl,data=reqdata, headers=headers)
    urllib2.install_opener(opener)
    try:
        res_data=urllib2.urlopen(req)
        res=res_data.read()
        f.write(res +'\n')
        
    except urllib2.URLError as e:
        if hasattr(e, 'code'):
            print 'Error code:',e.code
        elif hasattr(e, 'reason'):
            print 'Reason:',e.reason
    finally:
        if res_data:
            res_data.close()
        
    

if __name__ == "__main__":
#    get("http://172.18.106.32:9200/_all/log/_search")
#    file_object = open('data.txt')
#    try:
#       all_the_text = file_object.read()
#    finally:
#        file_object.close()
    
    data={}
    for i in range(1,100):
        res=post("http://172.18.34.43:8181/restconf/operations/route-optimize:get-ddos-community",data)
        
    
