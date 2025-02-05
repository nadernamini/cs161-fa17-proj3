#!/usr/bin/env python

# It is OK to replace this file with your own version to run on your
# own system if you want to avoid VMs, but we will GRADE using the
# VM.

import subprocess


def interfaces():
    msg = subprocess.check_output('ifconfig')
    interfaces = {}
    interface = ""
    ethernets = {}
    for line in msg.split('\n'):
        if line.strip() == "":
            pass
        elif line.startswith("\t") or line.startswith(" "):
            line = line.strip().split()
            if line[0] == 'inet':
                interfaces[interface] = (line[1].split(':')[1],
                                         line[-1].split(':')[1])
        else:
            interface = line.split(':')[0].split(' ')[0]
            interfaces[interface] = ""
            ethernets[interface] = line.split()[len(line.split()) - 1]
    check = []
    for i in interfaces:
        if interfaces[i] != "" and interfaces[i][0] != "127.0.0.1":
            check.append((i, interfaces[i], ethernets[i]))
    check.sort()
    return check[len(check) - 1]


if __name__ == "__main__":
    print interfaces()
