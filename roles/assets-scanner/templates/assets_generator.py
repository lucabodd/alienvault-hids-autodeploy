import re
import pylru
import sys
import pickle
import os
import socket
from fabric import Connection
from invoke import env
from ansible_vault import Vault

def try_login(current_host, default_user, user_pass ,itadm_password, root_password,fallback_itadm_password):
    try:
        conn = Connection(
            host=default_user+"@"+current_host,
            connect_timeout=1,
            connect_kwargs={"password": user_pass}
        )
        conn.open()
        return conn
    except Exception as e:
        try:
            conn = Connection(
                host="itadm@"+current_host,
                connect_timeout=1,
                connect_kwargs={"password": itadm_password}
            )
            conn.open()
            return conn
        except Exception as e:
            try:
                conn = Connection(
                    host="itadm@"+current_host,
                    connect_timeout=1,
                    connect_kwargs={"password": fallback_itadm_password}
                )
                conn.open()
                return conn
            except Exception as e:
                try:
                    conn = Connection(
                        host="root@" + current_host,
                        connect_timeout=1,
                        connect_kwargs={"password": root_password}
                    )
                    conn.open()
                    return conn
                except Exception as e:
                    try:
                        conn = Connection(
                            host="itadm@"+current_host,
                            connect_timeout=1,
                            port=8567,
                            connect_kwargs={"password": itadm_password}
                        )
                        conn.open()
                        return conn
                    except Exception as e:
                        try:
                            conn = Connection(
                                host="itadm@"+current_host,
                                connect_timeout=1,
                                port=8567,
                                connect_kwargs={"password": fallback_itadm_password}
                            )
                            conn.open()
                            return conn
                        except Exception as e:
                            try:
                                conn = Connection(
                                    host="root@" + current_host,
                                    connect_timeout=1,
                                    port=8567,
                                    connect_kwargs={"password": root_password}
                                )
                                conn.open()
                                return conn
                            except Exception as e:
                                return None

sys.setrecursionlimit(50000)

target_subnet = sys.argv[1]
cwd = sys.argv[2]
site_latitude = sys.argv[3]
site_longitude = sys.argv[4]
ping = sys.argv[5]

crypted_default_user = {{ crypted_username.stdout }}
crypted_user_pass = {{ crypted_user_pass.stdout }}
crypted_itadm_password = {{ crypted_itadm_password.stdout }}
crypted_fallback_itadm_password = {{ crypted_fallback_itadm_password.stdout }}
crypted_root_password = {{ crypted_root_password.stdout }}

# vars decryption
vault = Vault(os.popen('date +%M | head -c 1 ; date +-%H-%d-%m-%y | md5sum | awk "{print $1}"').read().split(" ")[0])
default_user = vault.load(crypted_default_user)
user_pass = vault.load(crypted_user_pass)
itadm_password = vault.load(crypted_itadm_password)
fallback_itadm_password = vault.load(crypted_fallback_itadm_password)
root_password = vault.load(crypted_itadm_password)

#open assets file
fassets = open(cwd+'/Assets.csv', 'a+')
#write file header if file is empty or if file does not exists
try:
    if(os.stat(cwd+'/Assets.csv').st_size < 5):
        fassets.write('"IPs";"Hostname";"FQDNs";"Description";"Asset Value";"Operating System";"Latitude";"Longitude";"Host ID";"External Asset";"Device Type"')
except Exception as e:
    fassets.write('"IPs";"Hostname";"FQDNs";"Description";"Asset Value";"Operating System";"Latitude";"Longitude";"Host ID";"External Asset";"Device Type"')

#Load cache
try:
    cachehandler = open(cwd+'/cache.pkl', 'rb')
    cache = pickle.load(cachehandler)
    cachehandler.close()
except Exception as e:
    cache = pylru.lrucache(1000)

try:
    os_cachehandler = open(cwd+'/os_cache.pkl', 'rb')
    os_cache = pickle.load(os_cachehandler)
    os_cachehandler.close()
except Exception as e:
    os_cache = pylru.lrucache(1000)

i=1

#scan hosts
while(i<254):
    current_host=target_subnet+'.'+str(i)
    print("\n| === SCANNING: "+current_host+" === |")
    if(current_host in cache):
        if(cache[current_host] != None):
            print("[ + ] Host "+current_host+" "+cache[current_host]+" is cached, previously detected as a "+os_cache[current_host]+" machine")
        else:
            print("[ - ] No host is running at "+current_host+", if this is an error, please clean up cache")
    else:
        if ping=="Y":
             print("[ ~ ] checking if "+current_host+" host is up")
             host_alive  = True if os.system("ping -c 1 -W 5 "+current_host+" > /dev/null") is 0 else False
        else:
             print("[ ~ ] ping probe inhibited")
             host_alive = True

        if host_alive == False:
            print("[ - ] Host "+current_host+" is unreachable, skipping ...")
            cache[current_host]=None
            os_cache[current_host]=None
        else:
            print("[ + ] Host "+current_host+" is up")
            print("[ ~ ] looking for PTR record")
            try:
                reversed_dns=None
                reversed_dns = socket.gethostbyaddr(current_host)
                cache[current_host]=reversed_dns[0].split(".")[0]
                print("[ + ] PTR record found, host is: "+cache[current_host])
            except Exception as e:
                print("[ - ] Host not found in PTR, falling back to SSH...")
            conn = try_login(current_host, default_user, user_pass ,itadm_password, root_password,fallback_itadm_password)
            if(conn == None):
                if(reversed_dns==None):
                    cache[current_host]=None
                    os_cache[current_host]=None
                else:
                    os_cache[current_host]=""
            else:
                if(conn.is_connected==True):
                    operative_system = conn.run("uname -s", hide=True)
                    print(operative_system)
                    os_cache[current_host]=operative_system.stdout.strip()
                    if (re.search("OpenBSD", str(operative_system)) != None):
                        hostname = conn.run("cat /etc/myname | awk -F '.' '{print $1}'", hide=True)
                    else :
                        hostname = conn.run("uname -n", hide=True)
                    conn.close()
                    hostname = hostname.stdout.strip()
                    print("[ + ] "+current_host + " known as " + hostname)
                    cache[current_host] = hostname
                else:
                    print("[ - ] Broken connection: "+conn)
    i=i+1

print("[ ~ ] Attempting to writing caches")
try:
    cachehandler = open(cwd+'/cache.pkl', 'wb')
    pickle.dump(cache, cachehandler)
    cachehandler.close()
    os_cachehandler = open(cwd+'/os_cache.pkl', 'wb')
    pickle.dump(os_cache, os_cachehandler)
    os_cachehandler.close()
except Exception as e:
    print("[ ! ] WARNING: failed to write lru cache, program exited with error:")

for i in range(1,254):
    current_host=target_subnet+'.'+str(i)
    if(cache[current_host] == None):
        print("[ - ] No host found at"+ current_host)
    else:
        print("[ + ] Result: "+cache[current_host]+" "+current_host+" ")
        fassets.write('\n"'+current_host+'";"'+cache[current_host]+'";"";"";"2";"'+os_cache[current_host]+'";"'+site_latitude+'";"'+site_longitude+'";"";"";""')
fassets.close()
exit(0)
