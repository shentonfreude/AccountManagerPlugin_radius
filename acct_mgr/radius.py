# -*- coding: utf-8 -*-
#
# Copyright (C) 2010 Chris Shenton <chris@koansys.com>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <trac@matt-good.net> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Matthew Good
#
# Author: Chris Shenton <chris@koansys.com>

from StringIO import StringIO

from trac.core import *
from trac.config import Option

from api import IPasswordStore

DICTIONARY = u"""
ATTRIBUTE User-Name     1 string
ATTRIBUTE User-Password 2 string encrypt=1
"""

class RadiusAuthStore(Component):
    implements(IPasswordStore)  # implements is method of Component

    radius_server   = Option('account-manager', 'radius_server')
    radius_authport = Option('account-manager', 'radius_authport')
    radius_secret   = Option('account-manager', 'radius_secret')

    def check_password(self, username, password):
        # Do import inside method so we can return 'None' on error
        try:
            import pyrad.packet
            from pyrad.client import Client, Timeout
            from pyrad.dictionary import Dictionary
        except ImportError, e:
            self.log.error("RADIUS could not import pyrad, need to install the egg: %s" , e)
            return None
        
        self.log.info("check_password radius_server=%s radius_authport=%s radius_secret=%s" % (
            self.radius_server, self.radius_authport, self.radius_secret))
        self.log.info("check_password username=%s password=%s" % (username, password))
                      
        # What's the encoding of the incoming username, passwd?
        username_utf8 = username.encode('utf-8')
        password_utf8 = password.encode('utf-8')
        try:
            radius_authport_int = int(self.radius_authport)
        except ValueError, e:
            self.log.error("radius_authport must be an integer, typically 1813 or 1645")
            return None
        radius_secret_utf8 = self.radius_secret.encode('utf-8')

        client = Client(server=self.radius_server,
                        authport=radius_authport_int,
                        secret=radius_secret_utf8,
                        dict=Dictionary(StringIO(DICTIONARY)),
                        )

        req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                      User_Name=username_utf8)
        req["User-Password"] = req.PwCrypt(password_utf8)
        self.log.warning("RADIUS authenticate sending packet req=%s" % req)
        try:
            reply = client.SendPacket(req)
        except Timeout, e:
            self.log.error("RADIUS Timeout contacting radius_server=% radius_authport=%s: %s" % (
                    self.radius_server, self.radius_authport, e))
            return None
        except Exception, e:    # TOO BROAD
            self.log.error("RADIUS Unknown error sending to radius_server=% radius_authport=%s: %s" % (
                    self.radius_server, self.radius_authport, e))
            return None

        self.log.warning("RADIUS authenticate check reply.code=%s" % reply.code)
        if reply.code == pyrad.packet.AccessAccept:
            self.log.warning("RADIUS Accept username=%s" % username)
            return True
        elif reply.code == pyrad.packet.AccessReject:
            self.log.warning("RADIUS Reject username=%s" % username)
            return None
        else:
            self.log.error("RADIUS returned unknown code for username=%s reply.code=%s" % (
                    username, reply.code))
        return None

    def get_users(self):
        return []

    def has_user(self, user):
        return False

