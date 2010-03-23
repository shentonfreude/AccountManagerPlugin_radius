# -*- coding: utf-8 -*-
#
# Copyright (C) 2010 Chris Shenton <chris@koansys.com>
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <chris@koansys.com> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   
#
# Author: Chris Shenton <chris@koansys.com>

from StringIO import StringIO

from trac.core import *
from trac.config import Option
from trac.config import IntOption

from api import IPasswordStore

DICTIONARY = u"""
ATTRIBUTE User-Name     1 string
ATTRIBUTE User-Password 2 string encrypt=1
"""

class RadiusAuthStore(Component):
    implements(IPasswordStore)  # 'implements' is method of Component

    radius_server   =    Option('account-manager', 'radius_server')
    radius_authport = IntOption('account-manager', 'radius_authport')
    radius_secret   =    Option('account-manager', 'radius_secret')

    def check_password(self, username, password):
        # do import inside method so we can fail (return None) if lacking pyrad
        try:
            import pyrad.packet
            from pyrad.client import Client, Timeout
            from pyrad.dictionary import Dictionary
        except ImportError, e:
            self.log.error("RADIUS could not import pyrad," +
                           " need to install the egg: %s" , e)
            return None
        
        self.log.debug("server=%s authport=%s secret=%s" % (
            self.radius_server, self.radius_authport, self.radius_secret))
        self.log.debug("username=%s password=%s" % (username, password))
                      
        username_utf8 = username.encode('utf-8')
        radius_secret_utf8 = self.radius_secret.encode('utf-8')

        client = Client(server=self.radius_server,
                        authport=self.radius_authport,
                        secret=radius_secret_utf8,
                        dict=Dictionary(StringIO(DICTIONARY)),
                        )

        req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                      User_Name=username_utf8)
        req["User-Password"] = req.PwCrypt(password)

        self.log.debug("RADIUS authenticate sending packet req=%s" % req)
        try:
            reply = client.SendPacket(req)
        except Timeout, e:
            self.log.error("Timeout contacting server=%s authport=%s: %s" % (
                    self.radius_server, self.radius_authport, e))
            return None
        except Exception, e:    # TOO BROAD
            self.log.error("Error sending to server=%s authport=%s: %s" % (
                    self.radius_server, self.radius_authport, e))
            return None
        self.log.debug("RADIUS authenticate check reply.code=%s" % reply.code)

        if reply.code == pyrad.packet.AccessAccept:
            self.log.debug("RADIUS Accept username=%s" % username)
            return True
        elif reply.code == pyrad.packet.AccessReject:
            self.log.warning("RADIUS Reject username=%s" % username)
            return None
        # Is there any way to alert the user their RSA token is in
        # Next Token mode so they know to fix it?
        elif reply.code == pyrad.packet.AccessChallenge:
            self.log.warning("RADIUS returned Challenge; on RSA servers this" +
                             "indicates Next Token mode. " +
                             "username=%s" % username)
            return None
        else:
            self.log.error("Unknown READIUS reply code for username=%s " +
                           " reply.code=%s" % (username, reply.code))
        return None

    def get_users(self):
        return []

    def has_user(self, user):
        return False

