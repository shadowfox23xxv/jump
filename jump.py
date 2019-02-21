#!/usr/bin/python
'''

SSH Management System
Automates SSH connections to VPS and Dedicated servers from desktop

Author:  Bleakbriar
Last modified 02/21/2019

'''

import requests
import argparse
import os

#=== List of dedicated server prefixes ============================
dedicatedPrefixes=["ded", "advanced", "elite", "cc"]
#=== User credentials =============================================
# Jumpstation
jsUser = ""
jsIP = ""
# cpJump
authUser = ""
authPW = ""
#==================================================================

requests.packages.urllib3.disable_warnings()

def isVPS(server):
    return server.lower().startswith("vps")

def isDedi(server):
    for serverType in dedicatedPrefixes:
	if(server.lower().startswith(serverType)):
	    return True
    return False

def vpsJump(server, flag):
    print("\t[+] Connecting through JumpStation...\n\n")
    jsCommand = "vpsfind " + server[3:] + " " + flag
    os.system('ssh -t ' + jsUser + '@' + jsIP + ' "' + jsCommand + '"')

def dediJump(server, port):
    print("\t[+] Setting up root key....")
    payload = {"server" : server, "port" : port}
    r = requests.post("https://cpjump.inmotionhosting.com/dedtmpkeys/process-dedkey.php", data=payload, auth=(authUser, authPW), verify=False)
    raw_input("\t[+] Press enter once key setup has been confirmed...")
    os.system("ssh -o StrictHostKeyChecking=no -p " + port + " root@" + server + ".inmotionhosting.com")


def main(args):
    print("\n\n[+] SSH connection to " + args.server + ":" + args.port + " in process")
    if(isVPS(args.server)):
	if( not jsUser and not jsIP):
	    print("[!] Invalid operation")
	    print("\t[!] No jumpstation credentials configured\n")
	else:
	    if(args.gotoNode):
		vpsJump(args.server, "n")
	    else:
		vpsJump(args.server, "v")
    elif(isDedi(args.server)):
	if(not authUser and not authPW):
	    print("[!] Invalid operation")
	    print("\t[!] No cpJump credentials configured\n")
	else:
	    dediJump(args.server, args.port)
    else:
	print("[!] Invalid server name\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SSH Manager')
    parser.add_argument("server")
    parser.add_argument('port', nargs='?', default='22')
    parser.add_argument("-n", "--node", help="connect to VPS node rather than container", action="store_true", dest='gotoNode', default=False)
    args = parser.parse_args()
    main(args)
