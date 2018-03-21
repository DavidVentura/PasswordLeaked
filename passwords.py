#!/usr/bin/env python3
import ff_dec
import chrome
import requests
import hashlib

def memoize(f):
    memo = {}
    def helper(x):
        if x not in memo:            
            memo[x] = f(x)
        return memo[x]
    return helper

# password reuse is a thing
@memoize
def get_hashes(chunk):
    r = requests.get("https://api.pwnedpasswords.com/range/%s" % chunk)
    aux = [ line.split(':')[0] for line in r.text.splitlines()]
    return aux

def hacked_passwords(info):
    hacked = []
    for line in info:
        site, user, pwd = line
        _hash = hashlib.sha1(pwd.encode()).hexdigest().upper()
        _hash_chunk = _hash[:5]
    
        for _hash_item in get_hashes(_hash_chunk):
            if "%s%s" % (_hash_chunk, _hash_item) == _hash:
                hacked.append((site, user))
                break
    return hacked

def get_passwords(browser):
    if browser == "firefox":
        return ff_dec.main()
    elif browser == "chrome":
        return chrome.main()

#info = get_passwords("firefox")
info = get_passwords("chrome")
for item in hacked_passwords(info):
    print(item)
