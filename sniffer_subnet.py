#!/usr/bin/python3
from scapy.all import *

def print_pkt(pkt):
  pkt.show()

pkt = sniff(filter='net 192.168.0.0/16', prn=print_pkt)

