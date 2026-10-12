from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection


@dataclass
class UserRecord:
    user_id: str
    username: str
    display_name: str
    password_hash: str | None
    auth_source: str
    is_active: bool
    failed_login_count: int
    locked_until: datetime | None


async def get_by_username(conn: AsyncConnection, username: str) -> UserRecord | None:
    row = (await conn.execute(
        text("SELECT user_id::text, username::text, display_name, password_hash, auth_source, is_active, "
             "failed_login_count, locked_until FROM iam.users WHERE username = :u"),
        {"u": username},
    )).mappings().first()
    return UserRecord(**row) if row else None


async def get_by_id(conn: AsyncConnection, user_id: str) -> UserRecord | None:
    row = (await conn.execute(
        text("SELECT user_id::text, username::text, display_name, password_hash, auth_source, is_active, "
             "failed_login_count, locked_until FROM iam.users WHERE user_id = CAST(:id AS uuid)"),
        {"id": user_id},
    )).mappings().first()
    return UserRecord(**row) if row else None


async def roles_permissions_scope(conn: AsyncConnection, user_id: str) -> tuple[list[str], list[str], dict]:
    rows = (await conn.execute(
        text("SELECT ur.role_id, ur.scope, array_remove(array_agg(rp.permission_id), NULL) AS perms "
             "FROM iam.user_roles ur LEFT JOIN iam.role_permissions rp ON rp.role_id = ur.role_id "
             "WHERE ur.user_id = CAST(:id AS uuid) GROUP BY ur.role_id, ur.scope"),
        {"id": user_id},
    )).mappings().all()
    roles = [r["role_id"] for r in rows]
    permissions = sorted({p for r in rows for p in r["perms"]})
    scope: dict = {}
    for r in rows:
        for key, values in (r["scope"] or {}).items():
            scope.setdefault(key, []).extend(values)
    return roles, permissions, scope


async def record_failed_login(conn: AsyncConnection, user_id: str, threshold: int, lockout_minutes: int) -> bool:
    """Increments the failure counter; returns True if the account is now locked."""
    locked = (await conn.execute(
        text("UPDATE iam.users SET "
             "failed_login_count = CASE WHEN failed_login_count + 1 >= :t THEN 0 ELSE failed_login_count + 1 END, "
             "locked_until = CASE WHEN failed_login_count + 1 >= :t "
             "  THEN now() + make_interval(mins => :m) ELSE locked_until END "
             "WHERE user_id = CAST(:id AS uuid) RETURNING locked_until > now()"),
        {"id": user_id, "t": threshold, "m": lockout_minutes},
    )).scalar()
    return bool(locked)


async def record_successful_login(conn: AsyncConnection, user_id: str) -> None:
    await conn.execute(
        text("UPDATE iam.users SET failed_login_count = 0, locked_until = NULL, last_login_at = now() "
             "WHERE user_id = CAST(:id AS uuid)"),
        {"id": user_id},
    )
