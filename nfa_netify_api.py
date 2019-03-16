import json
import urllib.request

def get_protocols(url):
    try:
        with urllib.request.urlopen(url) as ul:
            data = json.loads(ul.read().decode())
            print(data)
    except urllib.error.URLError as e:
        print("API request failed: %s" %(e.reason))
