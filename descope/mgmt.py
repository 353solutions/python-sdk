from descope.auth import Auth
from descope.management.group import Group  # noqa: F401
from descope.management.jwt import JWT  # noqa: F401
from descope.management.permission import Permission  # noqa: F401
from descope.management.role import Role  # noqa: F401
from descope.management.sso_settings import SSOSettings  # noqa: F401
from descope.management.tenant import Tenant  # noqa: F401
from descope.management.user import User  # noqa: F401


class MGMT:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth
        self._tenant = Tenant(auth)
        self._user = User(auth)
        self._sso = SSOSettings(auth)
        self._jwt = JWT(auth)
        self._permission = Permission(auth)
        self._role = Role(auth)
        self._group = Group(auth)

    @property
    def tenant(self):
        return self._tenant

    @property
    def user(self):
        return self._user

    @property
    def sso(self):
        return self._sso

    @property
    def jwt(self):
        return self._jwt

    @property
    def permission(self):
        return self._permission

    @property
    def role(self):
        return self._role

    @property
    def group(self):
        return self._group
