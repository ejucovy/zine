# -*- coding: utf-8 -*-
"""
    zine.plugins.opencore_auth
    ~~~~~~~~~~~~~~~~~~~~~~~~~~

    Use OpenCore authentication instead of Zine's built-in authentication.
"""

from Cookie import BaseCookie
from libopencore import auth
from libopencore import query_project
from topp.utils.memorycache import cache as memorycache
from zine.application import Request as RequestBase
from zine.database import db
from zine.utils import forms
from zine.models import User, Group

@memorycache(600)
def _fetch_policy(project, admin_filename, opencore_server):
    import elementtree.ElementTree as etree
    url = "%s/projects/%s/info.xml" % (
        opencore_server, project)
    admin_info = auth.get_admin_info(admin_filename)
    resp, content = query_project.admin_post(url, *admin_info)
    assert resp['status'] == '200'
    tree = etree.fromstring(content)
    policy = tree[0].text
    return policy     

@memorycache(600)
def _fetch_user_roles(project, admin_filename, opencore_server):
    admin_info = auth.get_admin_info(admin_filename)
    return query_project.get_users_for_project(
        project, opencore_server, admin_info)

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

    def get_project_user_roles(self):
        cfg = self.app.cfg
        return _fetch_user_roles(
            self.environ['HTTP_X_OPENPLANS_PROJECT'],
            cfg['opencore_auth/admin_info_filename'],
            cfg['opencore_auth/server_url'])

    def get_project_policy(self):
        cfg = self.app.cfg
        return _fetch_policy(
            self.environ['HTTP_X_OPENPLANS_PROJECT'],
            cfg['opencore_auth/admin_info_filename'],
            cfg['opencore_auth/server_url'])

    def __init__(self, environ, app=None):
        RequestBase.__init__(self, environ)
        request_groups = set()
        current_user = self.user
        if current_user.is_somebody:
            request_groups.add("Authenticated")
            for user in self.get_project_user_roles():
                if user['username'] == current_user.username:
                    request_groups.update(user['roles'])
        else:
            request_groups.add("Anonymous")
        _request_groups = []
        for group_name in request_groups:
            group = Group.query.filter_by(name=group_name).first()
            if group is None:
                group = Group(group_name)
                db.session.add(group)
            _request_groups.append(group)
        db.commit()
            
        self.user.request_groups = _request_groups

def setup(app, plugin):
    app._request_class = Request
    app.add_config_var('opencore_auth/shared_secret_filename',
                       forms.TextField(default=''))
    app.add_config_var('opencore_auth/admin_info_filename',
                       forms.TextField(default=''))
    app.add_config_var('opencore_auth/server_url',
                       forms.TextField(default='http://localhost:10000'))
