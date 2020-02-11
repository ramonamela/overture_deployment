#!/usr/bin/env python3

from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
import pyone
import sys
from enum import Enum
import ipaddress
import base64
from os import chmod
from Crypto.PublicKey import RSA
from time import sleep
from fabric import Connection
from fabric import transfer
import paramiko
from collections import OrderedDict
from io import StringIO

if __name__ == "__main__":
    print("Waiting until the machine is reachable by ssh", end="")
    sys.stdout.flush()
    public_ip_login_node = "192.168.21.116"
    private_ip_node = "192.168.21.116"
    username="ramela"
    conn1 = Connection(host=public_ip_login_node, user=username,
                       forward_agent=True)
    command_add_known_hosts = "ssh-keyscan -H " + private_ip_node + " >> ~/.ssh/known_hosts"
    command_to_run = "'pid=$(ps -elfa | grep apt | grep lock_is_held | grep -v grep | awk \'{ print $4 }\' | xargs -i echo {});" \
                     "while [ -e /proc/${pid} ]; do sleep 0.1; done; " \
                     "sudo apt-get update; sudo apt-get -y --no-install-recommends install nfs-common autofs'"
    command_to_run = "\"eval $\'ssh -oStrictHostKeyChecking=no " + username + "@" + private_ip_node + " <<\'EOF\'\npid=$(ps -elfa | grep apt | grep lock_is_held | grep -v grep | awk '{ print $4 }');while [ -e /proc/\${pid} ]; do sleep 0.1; done;apt-get update; apt-get -y --no-install-recommends install nfs-common autofs\nEOF'\""
    command_to_run = "eval $'ssh -oStrictHostKeyChecking=no " + username + "@" + private_ip_node + " <<\\'EOF\\'\npid=$(ps -elfa | grep ramela | tail -n1 | awk \\'{ print $4 }\\'); echo $((pid +1))\nEOF'"
    command_to_run = "eval $'ssh -oStrictHostKeyChecking=no " + username + "@" + private_ip_node + " <<\\'EOF\\'\npid=$(ps -elfa | grep apt | grep lock_is_held | grep -v grep | awk \\'{ print $4 }\\' | xargs -i echo {}); echo $((pid +1));while [[ ! -z \"${pid}\" && -e /proc/${pid} ]]; do sleep 0.1; done\nEOF'"

    stdout = StringIO()
    stderr = StringIO()
    conn1.run(command_to_run)