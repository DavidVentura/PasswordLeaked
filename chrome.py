#!/usr/bin/env python3
import sys
import os
import sqlite3
def get_db():
    if sys.platform == "win32":
        return "%s/../Local/Google/Chrome/User Data/Default/Login Data" % os.environ['APPDATA']
    return "%s/Login Data" % os.environ['HOME'] # Testing on linux

def read_db(db):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("SELECT origin_url, username_value, password_value FROM logins")
    login_data = cur.fetchall()
    if sys.platform == "linux":
        return login_data

    import win32crypt
    ret = []
    for url, user, pwd in login_data:
        pwd = win32crypt.CryptUnprotectData(pwd, None, None, None, 0)[1]
        ret.append((url, user, pwd))
    return ret

def get_passwords():
    return read_db(get_db())

if __name__ == '__main__':
    from pprint import pprint
    pprint(get_passwords())
