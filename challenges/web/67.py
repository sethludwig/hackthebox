#!/usr/bin/env python3
import hashlib
import sys
import json
import requests
import argparse
from bs4 import BeautifulSoup
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument('url', help='Target URL with http(s)://')
args = parser.parse_args()

base_url = args.url
if base_url.startswith('http://') or base_url.startswith('https://'):
    pass
else:
    print('[-] Include http:// or https:// in the URL!')
    sys.exit()
if base_url.endswith('/'):
    base_url = base_url[:-1]

session = requests.Session()

def banner():
    print('-'*50)
    print('--- Hack the Box ---------------------------------')
    print('--- Emdee five for life --------------------------')
    print('--- https://app.hackthebox.eu/challenges/67 ------')
    print('-'*50)
    print('[>] @sethludwig | https://berserker-security.com\n')


def show_info():
    print('[*] Target  : ' + base_url)


def connect():
    print('[!] Trying to connect...')
    try:
        connect_req = session.get(base_url, verify=False)
    except Exception as exc:
        print('\n[-] Exception : ' + str(exc))
        sys.exit()

    base_sc = connect_req.status_code
    if base_sc == 200:
        connect_resp = connect_req.text
        print('[+] Connected to challenge!')
        soup = BeautifulSoup(connect_resp, 'html.parser')
        challenge_string = soup.find('h3')
        challenge_string = challenge_string.string
        print('[+] Challenge string retrieved!\n')
        print(challenge_string)
        challenge_string = challenge_string.encode('utf-8')
        
        print('\n[!] Converting to MD5...')
        md5_hash = hashlib.md5(challenge_string)
        md5_hash = md5_hash.hexdigest()
        print('[+] MD5 Hash\n')
        print(md5_hash)                

    else:
        print('[-] Status : ' + str(connect_req.status_code))
        sys.exit()
        
    submit_data = {
        'hash': md5_hash,
    }

    submit_req = session.post(base_url, data=submit_data, allow_redirects=False)
    print('\n[+] Sending response!')
    print('[!] Status : ' + str(submit_req.status_code))
    submit_resp = submit_req.text
    soup = BeautifulSoup(submit_resp, 'html.parser')
    flag = soup.find('p')
    flag = flag.string
    print('[+] Flag retrieved! Launch script again if it failed.\n')
    print(flag)


try:
    banner()
    show_info()
    connect()

except KeyboardInterrupt:
    print('\n[-] Keyboard Interrupt')
    sys.exit()
