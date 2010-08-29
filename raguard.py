#!/usr/bin/python

"""
Copyright 2010 (c) Craig Askings <craig@askings.com.au>
Licensed under the terms of the GNU GPL License version 3


This script listens for rogue IPv6 Router Advertisments.

"""
from scapy.all import *
from datetime import datetime

def ra_watch_callback(pkt):
  if ICMPv6NDOptPrefixInfo in pkt:
    details = pkt.sprintf("Spotted %Ether.src% %IPv6.src% advertising %ICMPv6NDOptPrefixInfo%")
    event_time = datetime.now()
    return event_time.strftime("%x, %X: \t")+details


sniff(filter="icmp6", store =0,  prn=ra_watch_callback)
