#! /usr/bin/env python

########################################
#
# tuntap.py --- A generic python class around tuntap
#
# Copyright (C) 2011 Daniel Smith <viscous.liquid@gmail.com>
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

import os,sys,struct,string

from fcntl  import ioctl


TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002

DEFAULT_MTU = 1500

class TunTap:
    ''' TunTap Object '''

    def __init__(self, mode=IFF_TUN, dev='/dev/net/tun', name_format=''):
        self.mode = mode

        if name_format == '':
            if self.mode == IFF_TUN:
                name_format = 'tun%d'
            elif self.mode == IFF_TAP:
                name_format = 'tap%d'
        elif name.endswith('%d'):
            name_format = name
        else:
            name_format = name_format + '%d'

        self.__fd__ = os.open(dev, os.O_RDWR)
        ifs = ioctl(self.__fd__, TUNSETIFF, struct.pack("16sH", name_format, TUNMODE))
        self.name = ifs[:16].strip("\x00")

        self.mtu = DEFAULT_MTU

        atexit.register(self.close)

    def fileno(self):
        return self.__fd__

    def close(self):
        os.close(self.__fd__)
