#!/usr/bin/env python3
"""A small, dependency-free backend for a community-run Rec Room revival."""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


MAX_BODY_SIZE = 64 * 1024
TOKEN_LIFETIME = 30 * 24 * 60 * 60
PASSWORD_ITERATIONS = 260_000
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,24}$")


def connect(database_path):
    connection = sqlite3.connect(database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(database_path):
    with connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                banned_until INTEGER
            );
            CREATE TABLE IF NOT EXISTS tokens (
                token_hash BLOB PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rooms (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                owner_id TEXT NOT NULL REFERENCES accounts(id),
                max_players INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS room_members (
                room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                joined_at INTEGER NOT NULL,
                PRIMARY KEY (room_id, account_id)
            );
            """
        )
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(accounts)")
        }
        if "is_admin" not in columns:
            connection.execute(
                "ALTER TABLE accounts ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0"
            )
        if "banned_until" not in columns:
            connection.execute("ALTER TABLE accounts ADD COLUMN banned_until INTEGER")


def promote_account(database_path, username):
    with connect(database_path) as connection:
        result = connection.execute(
            "UPDATE accounts SET is_admin = 1 WHERE username = ?", (username,)
        )
        if result.rowcount == 0:
            raise ValueError(f"No account exists with username {username!r}")


class APIError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).digest()


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "RecRevival/0.1"

    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_empty(self, status):
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def read_json(self):
        content_type = self.headers.get("Content-Type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise APIError(415, "Content-Type must be application/json")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise APIError(400, "A valid Content-Length is required") from None
        if length < 0:
            raise APIError(400, "Invalid Content-Length")
        if length > MAX_BODY_SIZE:
            raise APIError(413, "Request body is too large")
        try:
            payload = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise APIError(400, "Request body must be valid JSON") from None
        if not isinstance(payload, dict):
            raise APIError(400, "Request body must be a JSON object")
        return payload

    def handle_api(self, callback):
        try:
            callback()
        except APIError as error:
            self.send_json(error.status, {"error": error.message})
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "The requested resource conflicts with existing data"})
        except sqlite3.Error:
            self.log_error("Database operation failed")
            self.send_json(500, {"error": "Internal server error"})

    def database(self):
        return connect(self.server.database_path)

    def authenticated_account(self, connection):
        authorization = self.headers.get("Authorization", "")
        scheme, separator, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not separator or not token:
            raise APIError(401, "A bearer token is required")
        row = connection.execute(
            """
            SELECT accounts.id, accounts.username, accounts.is_admin, accounts.banned_until
            FROM tokens JOIN accounts ON accounts.id = tokens.account_id
            WHERE tokens.token_hash = ? AND tokens.expires_at > ?
            """,
            (token_digest(token), int(time.time())),
        ).fetchone()
        if row is None:
            raise APIError(401, "Invalid or expired bearer token")
        now = int(time.time())
        if row["banned_until"] is None:
            return row
        if row["banned_until"] == 0 or row["banned_until"] > now:
            raise APIError(403, "This account is banned")
        return row

    def require_admin(self, connection):
        account = self.authenticated_account(connection)
        if not account["is_admin"]:
            raise APIError(403, "Administrator access is required")
        return account

    def do_GET(self):
        path = urlsplit(self.path).path.rstrip("/") or "/"

        def request():
            if path == "/health":
                self.send_json(200, {"status": "ok"})
                return
            if path == "/api/admin/players":
                with self.database() as connection:
                    self.require_admin(connection)
                    now = int(time.time())
                    players = connection.execute(
                        """
                        SELECT id, username, is_admin,
                               CASE WHEN banned_until = 0 THEN NULL
                                    WHEN banned_until > ? THEN banned_until
                                    ELSE NULL END AS banned_until,
                               CASE WHEN banned_until = 0 OR banned_until > ?
                                    THEN 1 ELSE 0 END AS is_banned
                        FROM accounts ORDER BY username COLLATE NOCASE
                        """,
                        (now, now),
                    ).fetchall()
                self.send_json(200, {"players": [dict(player) for player in players]})
                return
            if path == "/api/rooms":
                with self.database() as connection:
                    rooms = connection.execute(
                        """
                        SELECT rooms.id, rooms.name, rooms.max_players, rooms.created_at,
                               accounts.username AS owner,
                               COUNT(room_members.account_id) AS player_count
                        FROM rooms
                        JOIN accounts ON accounts.id = rooms.owner_id
                        LEFT JOIN room_members ON room_members.room_id = rooms.id
                        GROUP BY rooms.id
                        ORDER BY rooms.created_at DESC
                        """
                    ).fetchall()
                self.send_json(200, {"rooms": [dict(room) for room in rooms]})
                return
            match = re.fullmatch(r"/api/rooms/([^/]+)", path)
            if match:
                with self.database() as connection:
                    room = connection.execute(
                        """
                        SELECT rooms.id, rooms.name, rooms.max_players, rooms.created_at,
                               accounts.username AS owner,
                               COUNT(room_members.account_id) AS player_count
                        FROM rooms
                        JOIN accounts ON accounts.id = rooms.owner_id
                        LEFT JOIN room_members ON room_members.room_id = rooms.id
                        WHERE rooms.id = ?
                        GROUP BY rooms.id
                        """,
                        (match.group(1),),
                    ).fetchone()
                    if room is None:
                        raise APIError(404, "Room not found")
                    players = connection.execute(
                        """
                        SELECT accounts.username
                        FROM room_members JOIN accounts ON accounts.id = room_members.account_id
                        WHERE room_members.room_id = ?
                        ORDER BY room_members.joined_at
                        """,
                        (match.group(1),),
                    ).fetchall()
                self.send_json(
                    200,
                    {**dict(room), "players": [player["username"] for player in players]},
                )
                return
            raise APIError(404, "Not found")

        self.handle_api(request)

    def do_POST(self):
        path = urlsplit(self.path).path.rstrip("/") or "/"

        def request():
            payload = self.read_json()
            if path == "/api/accounts/register":
                username = payload.get("username")
                password = payload.get("password")
                if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
                    raise APIError(
                        400, "Username must be 3-24 letters, numbers, underscores, or hyphens"
                    )
                if not isinstance(password, str) or not 8 <= len(password) <= 128:
                    raise APIError(400, "Password must be between 8 and 128 characters")
                salt = secrets.token_bytes(16)
                password_hash = hashlib.pbkdf2_hmac(
                    "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
                )
                account_id = str(uuid.uuid4())
                with self.database() as connection:
                    connection.execute(
                        """
                        INSERT INTO accounts (id, username, password_salt, password_hash, created_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (account_id, username, salt, password_hash, int(time.time())),
                    )
                self.send_json(201, {"id": account_id, "username": username})
                return
            if path == "/api/accounts/login":
                username = payload.get("username")
                password = payload.get("password")
                if not isinstance(username, str) or not isinstance(password, str):
                    raise APIError(400, "Username and password are required")
                with self.database() as connection:
                    account = connection.execute(
                        """
                        SELECT id, username, password_salt, password_hash, banned_until
                        FROM accounts WHERE username = ?
                        """,
                        (username,),
                    ).fetchone()
                    if account is None:
                        raise APIError(401, "Invalid username or password")
                    candidate = hashlib.pbkdf2_hmac(
                        "sha256",
                        password.encode("utf-8"),
                        account["password_salt"],
                        PASSWORD_ITERATIONS,
                    )
                    if not hmac.compare_digest(candidate, account["password_hash"]):
                        raise APIError(401, "Invalid username or password")
                    if account["banned_until"] == 0 or (
                        account["banned_until"] is not None
                        and account["banned_until"] > int(time.time())
                    ):
                        raise APIError(403, "This account is banned")
                    token = secrets.token_urlsafe(32)
                    expires_at = int(time.time()) + TOKEN_LIFETIME
                    connection.execute(
                        "INSERT INTO tokens (token_hash, account_id, expires_at) VALUES (?, ?, ?)",
                        (token_digest(token), account["id"], expires_at),
                    )
                self.send_json(
                    200,
                    {
                        "token": token,
                        "expires_at": expires_at,
                        "account": {"id": account["id"], "username": account["username"]},
                    },
                )
                return

            admin_match = re.fullmatch(
                r"/api/admin/players/([^/]+)/(ban|unban|password)", path
            )
            if admin_match:
                username, action = admin_match.groups()
                with self.database() as connection:
                    self.require_admin(connection)
                    player = connection.execute(
                        "SELECT id, is_admin FROM accounts WHERE username = ?",
                        (username,),
                    ).fetchone()
                    if player is None:
                        raise APIError(404, "Player not found")
                    if player["is_admin"]:
                        raise APIError(403, "This action cannot be used on an administrator")

                    if action == "password":
                        password = payload.get("password")
                        if not isinstance(password, str) or not 8 <= len(password) <= 128:
                            raise APIError(
                                400, "Password must be between 8 and 128 characters"
                            )
                        salt = secrets.token_bytes(16)
                        password_hash = hashlib.pbkdf2_hmac(
                            "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
                        )
                        connection.execute(
                            """
                            UPDATE accounts SET password_salt = ?, password_hash = ?
                            WHERE id = ?
                            """,
                            (salt, password_hash, player["id"]),
                        )
                        connection.execute(
                            "DELETE FROM tokens WHERE account_id = ?", (player["id"],)
                        )
                        self.send_json(200, {"username": username, "password_changed": True})
                        return

                    if action == "unban":
                        connection.execute(
                            "UPDATE accounts SET banned_until = NULL WHERE id = ?",
                            (player["id"],),
                        )
                        self.send_json(
                            200,
                            {"username": username, "banned_until": None, "is_banned": False},
                        )
                        return

                    duration = payload.get("duration_seconds")
                    if duration is not None and (
                        isinstance(duration, bool)
                        or not isinstance(duration, int)
                        or duration <= 0
                        or duration > (2**63 - 1) - int(time.time())
                    ):
                        raise APIError(
                            400, "duration_seconds must be a positive integer or null"
                        )
                    banned_until = (
                        None if duration is None else int(time.time()) + duration
                    )
                    connection.execute(
                        "UPDATE accounts SET banned_until = ? WHERE id = ?",
                        (0 if banned_until is None else banned_until, player["id"]),
                    )
                    connection.execute(
                        "DELETE FROM tokens WHERE account_id = ?", (player["id"],)
                    )
                    connection.execute(
                        "DELETE FROM room_members WHERE account_id = ?", (player["id"],)
                    )
                self.send_json(
                    200,
                    {
                        "username": username,
                        "banned_until": banned_until,
                        "is_banned": True,
                    },
                )
                return

            match = re.fullmatch(r"/api/rooms/([^/]+)/(join|leave)", path)
            if path == "/api/rooms" or match:
                with self.database() as connection:
                    account = self.authenticated_account(connection)
                    if path == "/api/rooms":
                        name = payload.get("name")
                        max_players = payload.get("max_players", 8)
                        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 64:
                            raise APIError(400, "Room name must be between 1 and 64 characters")
                        if (
                            isinstance(max_players, bool)
                            or not isinstance(max_players, int)
                            or not 1 <= max_players <= 40
                        ):
                            raise APIError(400, "max_players must be an integer from 1 to 40")
                        room_id = str(uuid.uuid4())
                        now = int(time.time())
                        connection.execute(
                            "INSERT INTO rooms (id, name, owner_id, max_players, created_at) VALUES (?, ?, ?, ?, ?)",
                            (room_id, name.strip(), account["id"], max_players, now),
                        )
                        connection.execute(
                            "INSERT INTO room_members (room_id, account_id, joined_at) VALUES (?, ?, ?)",
                            (room_id, account["id"], now),
                        )
                        self.send_json(
                            201,
                            {
                                "id": room_id,
                                "name": name.strip(),
                                "owner": account["username"],
                                "max_players": max_players,
                                "player_count": 1,
                            },
                        )
                        return

                    room_id, action = match.groups()
                    room = connection.execute(
                        "SELECT id, max_players FROM rooms WHERE id = ?", (room_id,)
                    ).fetchone()
                    if room is None:
                        raise APIError(404, "Room not found")
                    if action == "join":
                        connection.execute("BEGIN IMMEDIATE")
                        existing = connection.execute(
                            "SELECT 1 FROM room_members WHERE room_id = ? AND account_id = ?",
                            (room_id, account["id"]),
                        ).fetchone()
                        if existing is None:
                            count = connection.execute(
                                "SELECT COUNT(*) FROM room_members WHERE room_id = ?", (room_id,)
                            ).fetchone()[0]
                            if count >= room["max_players"]:
                                raise APIError(409, "Room is full")
                            connection.execute(
                                "INSERT INTO room_members (room_id, account_id, joined_at) VALUES (?, ?, ?)",
                                (room_id, account["id"], int(time.time())),
                            )
                    else:
                        connection.execute(
                            "DELETE FROM room_members WHERE room_id = ? AND account_id = ?",
                            (room_id, account["id"]),
                        )
                self.send_json(200, {"room_id": room_id, "joined": action == "join"})
                return
            raise APIError(404, "Not found")

        self.handle_api(request)

    def do_DELETE(self):
        path = urlsplit(self.path).path.rstrip("/")
        match = re.fullmatch(r"/api/rooms/([^/]+)", path)

        def request():
            if not match:
                raise APIError(404, "Not found")
            with self.database() as connection:
                account = self.authenticated_account(connection)
                room = connection.execute(
                    "SELECT owner_id FROM rooms WHERE id = ?", (match.group(1),)
                ).fetchone()
                if room is None:
                    raise APIError(404, "Room not found")
                if room["owner_id"] != account["id"]:
                    raise APIError(403, "Only the room owner can delete this room")
                connection.execute("DELETE FROM rooms WHERE id = ?", (match.group(1),))
            self.send_empty(204)

        self.handle_api(request)


def main():
    database_path = os.environ.get("REC_SERVER_DATABASE", "rec_room.db")
    if len(sys.argv) == 3 and sys.argv[1] == "make-admin":
        initialize_database(database_path)
        try:
            promote_account(database_path, sys.argv[2])
        except ValueError as error:
            raise SystemExit(str(error)) from error
        print(f"Granted administrator access to {sys.argv[2]!r}")
        return
    if len(sys.argv) != 1:
        raise SystemExit("Usage: python3 server.py [make-admin USERNAME]")
    host = os.environ.get("REC_SERVER_HOST", "127.0.0.1")
    port = int(os.environ.get("REC_SERVER_PORT", "8000"))
    initialize_database(database_path)
    server = ThreadingHTTPServer((host, port), RequestHandler)
    server.database_path = database_path
    print(f"Rec Room revival server listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
