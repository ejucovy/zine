# -*- coding: utf-8 -*-
"""
    zine.plugins.opencore_auth
    ~~~~~~~~~~~~~~~~~~~~~~~~~~

    Use OpenCore authentication instead of Zine's built-in authentication.
"""

from Cookie import BaseCookie
from libopencore import auth
from zine.application import Request as RequestBase
from zine.database import db
from zine.utils import forms
from zine.models import User

class Request(RequestBase):
    def get_user(self):
        app = self.app
        secret = app.cfg['opencore_auth/shared_secret_filename']
        secret = auth.get_secret(secret)
        try:
            morsel = BaseCookie(self.environ['HTTP_COOKIE'])['__ac']
            username, hash = auth.authenticate_from_cookie(
                morsel.value, secret)
        except (KeyError, auth.BadCookie, auth.NotAuthenticated):
            return None
        user = User.query.filter_by(username=username).first()
        if user is None:
            user = User(username, None, "test@example.com")
            db.session.add(user)
            db.commit()
        return user

    def __init__(self, environ, app=None):
        RequestBase.__init__(self, environ)
        #self.user.request_groups.append(...)

def setup(app, plugin):
    app._request_class = Request
    app.add_config_var('opencore_auth/shared_secret_filename',
                       forms.TextField(default=''))
