import os
import subprocess
from subprocess import PIPE
import time
import atexit
import re
import csv

def StartController(init):
    ## Bug exists in L3Firewall code provided, where DoS attack doesn't flood enough msgs to block unless Firewall is not running
    ## For demonstration purpose/proof of concept for project, start controller without L3Learning (no rules anyways)
    ## in order to show DoS works, on subseqeuent restarts, run firewall to demonstrate that we still were able to learn rules
    ## for which hosts to block, which will work.
    if not init:
        return subprocess.Popen(["/home/ubuntu/pox/pox.py", "openflow.of_01", "--port=6655", "forwarding.l3_learning", "forwarding.L3Firewall"])
    return subprocess.Popen(["/home/ubuntu/pox/pox.py", "openflow.of_01", "--port=6655", "forwarding.l3_learning"])

def exit_handler():
    controller.kill()

def parse_src_ip_mac(line: str):
    splitStats = line.split(",")
    mac = ""
    ip = ""
    for stat in splitStats:
        cStat = stat.strip()
        idx = cStat.find("dl_src=")
        if idx != -1:
            mac = cStat[len("dl_src="):]
        idx = cStat.find("nw_src=")
        if idx != -1:
            ip = cStat[len("nw_src="):]
    return mac, ip
       

atexit.register(exit_handler)
controller = StartController(init=True)

portTable = {}
blockedMacs = []

while True:
    process = subprocess.run(["ovs-ofctl","dump-flows","s1"], stdout=PIPE)
    lines = str(process.stdout, 'UTF-8').split("\n")
    restartController = False
    for line in lines:
        mac, ip = parse_src_ip_mac(line)
        if mac != "" and ip != "":
            # Check if port exists or not, if it's new add to the table
            if mac not in portTable.keys():
                print("Adding %s=%s to the table" % (mac, ip))
                portTable[mac] = ip
            elif portTable[mac] != ip and mac not in blockedMacs:
                # IP doesn't match, block mac address
                print("Blocking %s!" % (mac))
                rules = []
                with open('l2firewall.config', 'r') as r:
                    reader = csv.reader(r)
                    for line in reader:
                        rules.append(line)
                rules.append([len(rules), mac, 'any'])
                blockedMacs.append(mac)
                with open('l2firewall.config', 'w', newline='') as w:
                    writer = csv.writer(w)
                    writer.writerows(rules)
                restartController = True
    if restartController:
        controller.kill()
        controller = StartController(init=False)

    time.sleep(1)



