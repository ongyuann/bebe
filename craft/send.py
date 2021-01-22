import requests
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def auth():
    burp0_url = "https://api.craft.htb:443/api/auth/login"
    burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
    
    r = requests.get(burp0_url, headers=burp0_headers, auth=HTTPBasicAuth('dinesh', '4aUh0A8PbVJxgd'), verify=False)
    j = r.json()
    
    return (j["token"])

token = auth().strip()
print ("[+] token: " + token)

def get():
    burp0_url = "https://api.craft.htb:443/api/brew/?page=1170&bool=true&per_page=2"
    burp0_headers = {
            "Accept": "application/json", 
            "X-Craft-Api-Token": "%s" % token
            }
    r = requests.get(burp0_url, headers=burp0_headers, verify=False)
    
    print ("[+] get response: \n")
    print (r.text)

    pass

def post():
    burp0_url = "https://api.craft.htb:443/api/brew/"
    burp0_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json", 
            "X-Craft-Api-Token": "%s" % token
            }

    burp0_json={
            "id": 2350,
            "brewer": "j4ck",
            "name": "j4ck",
            "style": "j4ck",
            "abv" : "0.1"
            }

    r = requests.post(burp0_url, headers=burp0_headers, json=burp0_json, verify = False)
 
    print ("[+] post response: \n")
    print (r.text)
    #print (token)
    pass

#post()
get()
