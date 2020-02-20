from fabric import Connection
import re
import pylru
import sys
import pickle
from invoke import env
import os
from pprint import pprint

sys.setrecursionlimit(50000)
cwd = os.path.dirname(os.path.realpath(__file__))
purge_type = sys.argv[1]
target_subnet = sys.argv[2]


print(cwd)

#Load cache
try:
    cachehandler = open(cwd+'/cache.pkl', 'rb')
    cache = pickle.load(cachehandler)
    cachehandler.close()
except Exception as e:
    print(e)
    exit(1)

#load os cache
try:
    os_cachehandler = open(cwd+'/os_cache.pkl', 'rb')
    os_cache = pickle.load(os_cachehandler)
    os_cachehandler.close()
except Exception as e:
    print("[-] Error loading OS cache")
    exit(1)

#rectify cache
for i in range(1, 254):
    current_host=target_subnet+"."+str(i)
    try:
        if purge_type == "all":
            del cache[current_host]
            del os_cache[current_host]
            print("[+] Full erase undergoing : "+current_host)
        elif purge_type == "undiscovered":
            if(cache[current_host]==None):
                del cache[current_host]
                del os_cache[current_host]
                print("[+] Deleting undiscovered "+current_host)
    except Exception as e:
        continue

#write cache
print("[ ~ ] Attempting to re-writing caches.")
try:
    cachehandler = open(cwd+'/cache.pkl', 'wb')
    pickle.dump(cache, cachehandler)
    cachehandler.close()
    os_cachehandler = open(cwd+'/os_cache.pkl', 'wb')
    pickle.dump(os_cache, os_cachehandler)
    os_cachehandler.close()
except Exception as e:
    print("[ ! ] WARNING: failed to write lru cache, program exited with error")
    exit(1)
print("[ + ] Cache written.")
exit(0)
