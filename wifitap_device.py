########################################
#
# Copyright (C) 2005 Cedric Blancher <sid@rstack.org>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
#########################################

import os,sys,getopt,struct,re,string,logging
import asyncore.file_dispatcher

import tuntap

logging.getLogger("scapy").setLevel(1)
from scapy.all import Raw,Ether,PrismHeader,Dot11,Dot11WEP,LLC,SNAP,sendp,conf

class WifiTapDevice

    def __init__(self, inf='wlan0', outf='wlan0', bssid='', mac='')
        self.inf = inf
        self.outf = outf
        self.bssid = bssid
        self.mac = mac

        self.tap = TunTap.new(mode=tuntap.IFF_TAP, name_format='wj%d')

        self.has_wep = 0

    def wep(self, key='', key_id=0)
        # Match and parse WEP key
        tmp_key = ""

        if re.match('^([0-9a-fA-F]{2}){5}$', key) or re.match ('^([0-9a-fA-F]{2}){13}$', key):
            tmp_key = key
        elif re.match('^([0-9a-fA-F]{2}[:]){4}[0-9a-fA-F]{2}$', key) or re.match('^([0-9a-fA-F]{2}[:]){12}[0-9a-fA-F]{2}$', key):
            tmp_key = re.sub(':', '', key)
        elif re.match ('^([0-9a-fA-F]{4}[-]){2}[0-9a-fA-F]{2}$', key) or re.match ('^([0-9a-fA-F]{4}[-]){6}[0-9a-fA-F]{2}$', key):
            tmp_key = re.sub('-', '', key)
        else:
            return

        g = lambda x: chr(int(tmp_key[::2][x],16)*16+int(tmp_key[1::2][x],16))

        for i in range(len(tmp_key)/2):
            self.wepkey += g(i)

        if key_id > 3 or key_id < 0:
            self.key_id = 0
        else:
            self.key_id = key_id

        self.has_wep = 1

class WifiTapReader(asyncore.file_dispatcher):
    def __init__(self, wifitap, map=None):
        self._tap = wifitap
        self.fd = wifitap.tap.fileno()
        asyncore.file_dispatcher.__init__(self, self.fd, map)

    def writable(self):
        return False

    def handle_read(self):
        # | 4 bytes | 4 bytes |   18 bytes   |     1500 bytes    |
        #     Tap       VLAN    Ether Header          Frame
        buf = self.read(1526)
        eth_rcvd_frame = Ether(buf[4:])

        if DEBUG:
            os.write(1,"Received from %s\n" % ifname)
            if VERB:
                os.write(1,"%s\n" % eth_rcvd_frame.summary())

        # Prepare Dot11 frame for injection
        dot11_sent_frame = Dot11(
            type = "Data",
            FCfield = "from-DS",
            addr1 = eth_rcvd_frame.getlayer(Ether).dst,
            addr2 = self._tap.bssid)

        # It doesn't seem possible to set tuntap interface MAC address
        # when we create it, so we set source MAC here
        if self._tap.mac == ''
            dot11_sent_frame.addr3 = eth_rcvd_frame.getlayer(Ether).src
        else:
            dot11_sent_frame.addr3 = self._tap.mac

        if self._tap.has_wep:
            dot11_sent_frame.FCfield |= 0x40
            dot11_sent_frame /= Dot11WEP(
                iv = "111",
                keyid = self._tap.key_id)

        dot11_sent_frame /= LLC(ctrl = 3)/SNAP(code=eth_rcvd_frame.getlayer(Ether).type)/eth_rcvd_frame.getlayer(Ether).payload

        if DEBUG:
            os.write(1,"Sending from-DS to %s\n" % OUT_IFACE)
            if VERB:
                os.write(1,"%s\n" % dot11_sent_frame.summary())

        # Frame injection :
        sendp(dot11_sent_frame,verbose=0) # Send from-DS frame

    def handle_except(self):
        pass

    def handle_close(self):
        self.close
