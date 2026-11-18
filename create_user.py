"""Create a dashboard login account in the MySQL users table."""

import argparse
import getpass
import re
import sys

import pymysql
from werkzeug.security import generate_password_hash

import db


USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MIN_PASSWORD_LENGTH = 12


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username", help="username for the new dashboard account")
    parser.add_argument("--role", choices=("admin", "viewer"), default="admin")
    args = parser.parse_args(argv)

    username = args.username.strip().lower()
    if not USERNAME_RE.fullmatch(username):
        parser.error("username must be 1-64 letters, numbers, dots, underscores, or hyphens")

    password = getpass.getpass("Password (minimum 12 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < MIN_PASSWORD_LENGTH:
        parser.error("password must be at least 12 characters")
    if password != confirmation:
        parser.error("passwords do not match")

    db.init_schema()
    conn = db.connect()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                (username, generate_password_hash(password), args.role),
            )
    except pymysql.IntegrityError as err:
        if err.args and err.args[0] == 1062:
            parser.error(f"username {username!r} already exists")
        raise
    finally:
        conn.close()

    print(f"Created {args.role} account {username!r}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
