#!/usr/bin/env python

import time
import threading
from scapy.all import *
import sys
import socket
import json
import random
import string
import Queue
import interfaces

# TCP-Flags
FIN = 0x01
SYN = 0x02
RST = 0x4
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80
maxhop = 25

# A request that will trigger the great firewall but will NOT cause
# the web server to process the connection.  You probably want it here

triggerfetch = "GET /search?q=Falun+Gong HTTP/1.1\r\nHost: www.google.com\r\n\r\n"


# Get the size of a string in bytes
def utf8len(s):
    return len(s.encode('utf-8'))


# A couple useful functions that take scapy packets
def isRST(p):
    return (TCP in p) and (p[IP][TCP].flags & RST != 0)


def isICMP(p):
    return ICMP in p


def isTimeExceeded(p):
    return ICMP in p and p[IP][ICMP].type == 11


# A general python object to handle a lot of this stuff...
#
# Use this to implement the actual functions you need.
class PacketUtils:
    def __init__(self, dst=None):
        # Get one's SRC IP & interface
        i = interfaces.interfaces()
        self.src = i[1][0]
        self.iface = i[0]
        self.netmask = i[1][1]
        self.enet = i[2]
        self.dst = dst
        sys.stderr.write("SIP IP %s, iface %s, netmask %s, enet %s\n" %
                         (self.src, self.iface, self.netmask, self.enet))
        # A queue where received packets go.  If it is full
        # packets are dropped.
        self.packetQueue = Queue.Queue(100000)
        self.dropCount = 0
        self.idcount = 0

        self.ethrdst = ""

        # Get the destination ethernet address with an ARP
        self.arp()

        # You can add other stuff in here to, e.g. keep track of
        # outstanding ports, etc.

        # Start the packet sniffer
        t = threading.Thread(target=self.run_sniffer)
        t.daemon = True
        t.start()
        time.sleep(.1)

    # generates an ARP request
    def arp(self):
        e = Ether(dst="ff:ff:ff:ff:ff:ff",
                  type=0x0806)
        gateway = ""
        srcs = self.src.split('.')
        netmask = self.netmask.split('.')
        for x in range(4):
            nm = int(netmask[x])
            addr = int(srcs[x])
            if x == 3:
                gateway += "%i" % ((addr & nm) + 1)
            else:
                gateway += ("%i" % (addr & nm)) + "."
        sys.stderr.write("Gateway %s\n" % gateway)
        a = ARP(hwsrc=self.enet,
                pdst=gateway)
        p = srp1([e / a], iface=self.iface, verbose=0)
        self.etherdst = p[Ether].src
        sys.stderr.write("Ethernet destination %s\n" % (self.etherdst))

    # A function to send an individual packet.
    def send_pkt(self, payload=None, ttl=32, flags="",
                 seq=None, ack=None,
                 sport=None, dport=80, ipid=None,
                 dip=None, debug=False):
        if sport == None:
            sport = random.randint(1024, 32000)
        if seq == None:
            seq = random.randint(1, 31313131)
        if ack == None:
            ack = random.randint(1, 31313131)
        if ipid == None:
            ipid = self.idcount
            self.idcount += 1
        t = TCP(sport=sport, dport=dport,
                flags=flags, seq=seq, ack=ack)
        ip = IP(src=self.src,
                dst=self.dst,
                id=ipid,
                ttl=ttl)
        p = ip / t
        if payload:
            p = ip / t / payload
        else:
            pass
        e = Ether(dst=self.etherdst,
                  type=0x0800)
        # Have to send as Ethernet to avoid interface issues
        sendp([e / p], verbose=1, iface=self.iface)
        # Limit to 20 PPS.
        time.sleep(.05)
        # And return the packet for reference
        return p

    # Has an automatic 5 second timeout.
    def get_pkt(self, timeout=5):
        try:
            return self.packetQueue.get(True, timeout)
        except Queue.Empty:
            return None

    # The function that actually does the sniffing
    def sniffer(self, packet):
        try:
            # non-blocking: if it fails, it fails
            self.packetQueue.put(packet, False)
        except Queue.Full:
            if self.dropCount % 1000 == 0:
                sys.stderr.write("*")
                sys.stderr.flush()
            self.dropCount += 1

    def run_sniffer(self):
        sys.stderr.write("Sniffer started\n")
        rule = "src net %s or icmp" % self.dst
        sys.stderr.write("Sniffer rule \"%s\"\n" % rule)
        sniff(prn=self.sniffer,
              filter=rule,
              iface=self.iface,
              store=0)

    # Sends the message to the target in such a way
    # that the target receives the msg without
    # interference by the Great Firewall.
    #
    # ttl is a ttl which triggers the Great Firewall but is before the
    # server itself (from a previous traceroute incantation)
    def evade(self, target, msg, ttl):
        # Handshake #

        port = random.randint(2000, 30000)
        # SYN sent
        pckt = self.send_pkt(flags="S", sport=port)
        s_seq = pckt[TCP].seq
        # SYN/ACK received?
        get = self.get_pkt()
        if not get or TCP not in get or get[TCP].flags != (SYN | ACK):  # check for syn/ack flag
            return "DEAD"
        d_seq = get[TCP].seq
        d_ack = get[TCP].ack
        # check if ACK == Seq + 1
        if d_ack != s_seq + 1:
            return "DEAD"
        # ACK sent
        pckt = self.send_pkt(flags="A", sport=port, seq=s_seq + 1, ack=d_seq + 1)

        for i in range(len(msg)):
            print(i)
            ran_ch = random.choice(string.ascii_lowercase)
            pckt = self.send_pkt(flags="A" if i != len(msg) - 1 else "PA", payload=triggerfetch,
                                 sport=port, seq=d_ack + i, ack=d_seq + 1, ttl=ttl + 2)
            ran_pckt = self.send_pkt(flags="A", payload=ran_ch, sport=port, seq=d_ack + i, ack=d_seq + 1, ttl=ttl - 2)

        timeout = time.time() + 5
        rv = []
        rp = self.get_pkt(max(0, timeout - time.time()))
        while rp:
            rv.append(rp)
            print rp
            rp = self.get_pkt(max(0, timeout - time.time()))
        return rv



    # Returns "DEAD" if server isn't alive,
    # "LIVE" if the server is alive,
    # "FIREWALL" if it is behind the Great Firewall
    def ping(self, target):

        port = random.randint(2000, 30000)
        # SYN sent
        pckt = self.send_pkt(flags="S", sport=port)
        s_seq = pckt[TCP].seq
        # SYN/ACK received?
        get = self.get_pkt()
        if not get or TCP not in get or get[TCP].flags != (SYN | ACK):  # check for syn/ack flag
            return "DEAD"
        d_seq = get[TCP].seq
        d_ack = get[TCP].ack
        # check if ACK == Seq + 1
        if d_ack != s_seq + 1:
            return "DEAD"
        # ACK sent
        pckt = self.send_pkt(flags="A", sport=port, seq=s_seq + 1, ack=d_seq + 1)

        # rv, = self.hndsk(target)
        # if rv == "DEAD":
        #     return rv
        # else:
        #     port, d_ack, d_seq = rv
        pckt = self.send_pkt(flags="PA", payload=triggerfetch, sport=port, seq=d_ack, ack=d_seq + 1)
        get = self.get_pkt()
        while get:
            if isRST(get):
                return "FIREWALL"
            get = self.get_pkt()
        return "LIVE"

    def hndsk(self, target, timeout=5):
        port = random.randint(2000, 30000)
        # SYN sent
        pckt = self.send_pkt(flags="S", sport=port)
        s_seq = pckt[TCP].seq
        # SYN/ACK received?
        get = self.get_pkt(timeout=timeout)
        cond1 = not get
        if not cond1:
            cond2 = TCP not in get
        else:
            cond2 = True
        if not cond1 and not cond2:
            cond3 = get[TCP].flags != (SYN | ACK)
            if isRST(get):
                return "RST", get[IP].src
        else:
            cond3 = True
        print "1:", cond1, "2:", cond2, "3:", cond3
        if cond1 or cond2 or cond3:  # check for syn/ack flag
            return "DEAD", None
        d_seq = get[TCP].seq
        d_ack = get[TCP].ack
        # check if ACK == Seq + 1
        if d_ack != s_seq + 1:
            return "DEAD", None
        # ACK sent
        pckt = self.send_pkt(flags="A", sport=port, seq=s_seq + 1, ack=d_seq + 1)
        return (port, d_ack, d_seq), None

    # Format is
    # ([], [])
    # The first list is the list of IPs that have a hop
    # or none if none
    # The second list is T/F 
    # if there is a RST back for that particular request
    def traceroute(self, target, hops):
        ips, trus = [], []

        for i in range(1, hops):
            print(i)
            port = random.randint(2000, 30000)
            # SYN sent
            pckt = self.send_pkt(flags="S", sport=port)
            s_seq = pckt[TCP].seq
            # SYN/ACK received?
            get = self.get_pkt(timeout=32)

            # if not get or get[TCP].flags != (SYN | ACK):  # check for syn/ack flag
            #     return "DEAD"
            if not get or TCP not in get:
                ipopo, reseto = None, False
                if get:
                    ipopo, reseto = get[IP].src if isTimeExceeded(get) else None, isRST(get)
                ips.append(ipopo)
                trus.append(reseto)
                continue
            d_seq = get[TCP].seq
            d_ack = get[TCP].ack
            # ACK sent
            pckt = self.send_pkt(flags="A", sport=port, seq=s_seq + 1, ack=d_seq + 1)

            c = 0
            while c < 3:
                flg = "PA"
                pckt = self.send_pkt(flags=flg, payload=triggerfetch, sport=port,
                                     seq=d_ack + c * utf8len(triggerfetch), ack=d_seq + 1, ttl=i)
                c += 1
            get = self.get_pkt(timeout=1)
            print self.packetQueue.qsize(), "start"
            found, ip = False, []
            while get:
                if IP in get or (TCP in get and get[TCP].sport == 80 and get[TCP].dport == port):
                    print "in", isRST(get)
                    cip = get[IP].src
                    if isRST(get):
                        found = True
                    if isTimeExceeded(get):
                        ip.append(cip)
                get = self.get_pkt(timeout=1)
            if not self.packetQueue.empty():
                self.packetQueue.empty()
                with self.packetQueue.mutex:
                    self.packetQueue.queue.clear()
            print self.packetQueue.qsize(), "end"
            trus.append(found)
            ips.append(ip[0] if ip else None)

        return ips, trus
