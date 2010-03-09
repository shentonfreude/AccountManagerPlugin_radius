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

import logging

#from trac.core import *
from trac.core import Component
from trac.config import Option

from api import IPasswordStore

DICTIONARY = u"""
ATTRIBUTE User-Name     1 string
ATTRIBUTE User-Password 2 string encrypt=1
"""

class RadiusAuthStore(Component):
    implements(IPasswordStore)  # implements is method of Component

    radius_server   = Option('account-manager', 'radius_secret')
    radius_authport = Option('account-manager', 'radius_authport')
    radius_secret   = Option('account-manager', 'radius_secret')

    def check_password(self, username, password):
        # Do import inside method so we can return 'None' on error
        try:
            import pyrad.packet
            from pyrad.client import Client, Timeout
            from pyrad.dictionary import Dictionary
        except ImportError, e:
            logging.error("RADIUS could not import pyrad, need to install the egg: %s" , e)
            return None
        # What's the encoding of the incoming username, passwd?
        #username = username.encode('utf-8')
        #password = password.encode('utf-8')
        #radius_secret = radius_secret.encode('utf-8')

        client = Client(server=radius_server,
                        authport=radius_authport,
                        secret=radius_secret,
                        dict=Dictionary(StringIO(DICTIONARY)),
                        )

        req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                      User_Name=username)
        req["User-Password"] = req.PwCrypt(password)
        logging.warning("RADIUS authenticate sending packet req=%s" % req)
        try:
            reply = client.SendPacket(req)
        except Timeout, e:
            logging.error("RADIUS Timeout contacting radius_server=% radius_authport=%s: %s" % (
                    radius_server, radius_authport, e))
            return None
        except Exception, e:    # TOO BROAD
            logging.error("RADIUS Unknown error sending to radius_server=% radius_authport=%s: %s" % (
                    radius_server, radius_authport, e))
            return None

        logging.warning("RADIUS authenticate check reply.coe=%s" % reply.code)
        if reply.code == pyrad.pycat.AccessAccept:
            logging.warning("RADIUS Accept username=%s" % username)
            return True
        elif reply.code == pyrad.pycat.AccessReject:
            logging.warning("RADIUS Reject username=%s" % username)
            return None
        else:
            logging.error("RADIUS returned unknown code for username=%s reply.code=%s" % (
                    username, reply.code))
        return None

    def get_users(self):
        return []

    def has_user(self, user):
        return False

