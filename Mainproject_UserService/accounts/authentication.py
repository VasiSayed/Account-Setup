# accounts/authentication.py
import re
import jwt
from dataclasses import dataclass
from django.conf import settings
from django.db import connections
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions

from config.models import UserDatabase
from accounts.utils import decrypt_password
from UserService.db_router import set_current_tenant
from accounts.models import User as TenantUser


def _ensure_tenant_alias_registered(tenant_alias: str):
    if not tenant_alias:
        raise exceptions.AuthenticationFailed("Missing tenant alias.")
    if tenant_alias in settings.DATABASES:
        return
    m = re.match(r"^client_(\d+)$", tenant_alias)
    if not m:
        raise exceptions.AuthenticationFailed("Invalid tenant alias format.")
    user_id = int(m.group(1))
    row = UserDatabase.objects.filter(user_id=user_id).first()
    if not row:
        raise exceptions.AuthenticationFailed("Tenant not found.")
    real_pw = decrypt_password(row.db_password)
    cfg = {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": row.db_name,
        "USER": row.db_user,
        "PASSWORD": real_pw,
        "HOST": row.db_host,
        "PORT": row.db_port,
        "OPTIONS": {},
        "ATOMIC_REQUESTS": False,
        "AUTOCOMMIT": True,
        "TIME_ZONE":settings.TIME_ZONE,
        "CONN_HEALTH_CHECKS": False,
        "CONN_MAX_AGE": 0,
    }
    settings.DATABASES[tenant_alias] = cfg
    connections.databases[tenant_alias] = cfg


@dataclass
class AuthenticatedTenantUser:
    id: int
    username: str
    is_staff: bool
    is_superuser: bool
    is_client: bool
    is_active: bool
    tenant_alias: str
    @property
    def is_authenticated(self) -> bool: return True
    @property
    def is_anonymous(self) -> bool: return False
    def get_username(self) -> str: return self.username
    @property
    def pk(self) -> int: return self.id
    def __str__(self) -> str: return self.username


class JWTTenantAuthentication(BaseAuthentication):
    keyword = "Bearer"

    def authenticate(self, request):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith(f"{self.keyword} "):
            return None

        token = auth[len(self.keyword) + 1:].strip()
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed("Token expired")
        except jwt.PyJWTError:
            raise exceptions.AuthenticationFailed("Invalid token")

        tenant_alias = payload.get("tenant_alias")
        user_id = payload.get("user_id")
        username = payload.get("username")
        if not tenant_alias or not user_id or not username:
            raise exceptions.AuthenticationFailed("Invalid token payload")

        _ensure_tenant_alias_registered(tenant_alias)

        set_current_tenant(tenant_alias)

        try:
            tu = TenantUser.objects.using(tenant_alias).get(id=user_id, username=username)
            if not tu.is_active:
                raise exceptions.AuthenticationFailed("User inactive")
        except TenantUser.DoesNotExist:
            raise exceptions.AuthenticationFailed("User not found")

        principal = AuthenticatedTenantUser(
            id=tu.id,
            username=tu.username,
            is_staff=tu.is_staff,
            is_superuser=tu.is_superuser,
            is_client=getattr(tu, "is_client", False),
            is_active=tu.is_active,
            tenant_alias=tenant_alias,
        )
        return (principal, token)
