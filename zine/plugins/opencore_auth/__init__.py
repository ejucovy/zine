# -*- coding: utf-8 -*-
"""
    zine.plugins.opencore_auth
    ~~~~~~~~~~~~~~~~~~~~~~~~~~

    Use OpenCore authentication instead of Zine's built-in authentication.
"""

from libopencore import auth
from zine.application import Request as RequestBase

class Request(BaseRequest):
    def get_user(self):
        app = self.app
        secret = app.cfg['opencore_shared_secret_filename']
        # ...

    def __init__(self, environ, app=None):
        RequestBase.__init__(self, environ)
        #self.user.request_groups.append(...)

def setup(app, plugin):
    app._request_class = Request
