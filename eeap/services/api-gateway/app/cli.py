"""Administrative CLI.

    docker compose --profile app run --rm -e EEAP_NEW_USER_PASSWORD api-gateway \
        python -m app.cli create-user --username admin --display-name "Platform Admin" --role admin
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys

from sqlalchemy import text

from eeap_shared.logging import configure_logging
from eeap_shared.utils.db import create_engine

from .audit import AuditEntry, write_audit
from .config import settings
from .security import MIN_PASSWORD_LENGTH, hash_password


def _read_password() -> str:
    password = os.environ.get("EEAP_NEW_USER_PASSWORD")
    if password:
        return password
    if not sys.stdin.isatty():
        raise SystemExit("set EEAP_NEW_USER_PASSWORD or run with an interactive terminal (-it)")
    first = getpass.getpass(f"Password (min {MIN_PASSWORD_LENGTH} chars): ")
    if first != getpass.getpass("Repeat password: "):
        raise SystemExit("passwords do not match")
    return first


async def create_user(username: str, display_name: str, email: str | None, roles: list[str]) -> None:
    password_hash = hash_password(_read_password())
    engine = create_engine(settings, pool_size=1)
    try:
        async with engine.begin() as conn:
            known = set((await conn.execute(text("SELECT role_id FROM iam.roles"))).scalars())
            unknown = set(roles) - known
            if unknown:
                raise SystemExit(f"unknown role(s): {', '.join(sorted(unknown))}; valid: {', '.join(sorted(known))}")
            user_id = (await conn.execute(
                text("INSERT INTO iam.users (username, email, display_name, password_hash) "
                     "VALUES (:u, :e, :d, :p) ON CONFLICT (username) DO NOTHING RETURNING user_id::text"),
                {"u": username.lower(), "e": email, "d": display_name, "p": password_hash},
            )).scalar()
            if user_id is None:
                raise SystemExit(f"user {username!r} already exists")
            for role in roles:
                await conn.execute(
                    text("INSERT INTO iam.user_roles (user_id, role_id) VALUES (CAST(:u AS uuid), :r)"),
                    {"u": user_id, "r": role},
                )
        await write_audit(engine, AuditEntry("system", "user.create", "success", actor_name="cli",
                                             resource_type="user", resource_id=user_id,
                                             details={"username": username.lower(), "roles": roles}))
        print(f"created user {username.lower()} ({user_id}) with roles {', '.join(roles)}")
    finally:
        await engine.dispose()


def main() -> None:
    configure_logging(settings.service_name, "WARNING")
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-user", help="create a local user")
    create.add_argument("--username", required=True)
    create.add_argument("--display-name", required=True)
    create.add_argument("--email")
    create.add_argument("--role", action="append", required=True, dest="roles")
    args = parser.parse_args()
    if args.command == "create-user":
        asyncio.run(create_user(args.username, args.display_name, args.email, args.roles))


if __name__ == "__main__":
    main()
