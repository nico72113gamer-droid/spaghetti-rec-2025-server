import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from pathlib import Path

import server


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.database_path = str(Path(cls.temp_dir.name) / "test.db")
        server.initialize_database(cls.database_path)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.RequestHandler)
        cls.httpd.database_path = cls.database_path
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()
        cls.temp_dir.cleanup()

    def request(self, method, path, payload=None, token=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        try:
            response = urllib.request.urlopen(request)
        except urllib.error.HTTPError as error:
            response = error
        body = response.read()
        return response.code, json.loads(body) if body else None

    def create_account(self, username):
        status, account = self.request(
            "POST",
            "/api/accounts/register",
            {"username": username, "password": "correct horse battery"},
        )
        self.assertEqual(status, 201)
        status, login = self.request(
            "POST",
            "/api/accounts/login",
            {"username": username, "password": "correct horse battery"},
        )
        self.assertEqual(status, 200)
        return account, login["token"]

    def create_admin(self, username):
        account, token = self.create_account(username)
        server.promote_account(self.database_path, username)
        return account, token

    def test_health_and_account_validation(self):
        self.assertEqual(self.request("GET", "/health"), (200, {"status": "ok"}))
        status, body = self.request(
            "POST", "/api/accounts/register", {"username": "x", "password": "short"}
        )
        self.assertEqual(status, 400)
        self.assertIn("error", body)

    def test_room_lifecycle_and_capacity(self):
        _, owner_token = self.create_account("owner")
        _, guest_token = self.create_account("guest")
        status, room = self.request(
            "POST",
            "/api/rooms",
            {"name": "Community Hangout", "max_players": 1},
            token=owner_token,
        )
        self.assertEqual(status, 201)
        self.assertEqual(room["player_count"], 1)

        status, rooms = self.request("GET", "/api/rooms")
        self.assertEqual(status, 200)
        self.assertTrue(any(item["id"] == room["id"] for item in rooms["rooms"]))

        status, body = self.request(
            "POST", f"/api/rooms/{room['id']}/join", {}, token=guest_token
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "Room is full")

        status, detail = self.request("GET", f"/api/rooms/{room['id']}")
        self.assertEqual(status, 200)
        self.assertEqual(detail["players"], ["owner"])

        status, body = self.request(
            "DELETE", f"/api/rooms/{room['id']}", token=owner_token
        )
        self.assertEqual(status, 204)
        self.assertIsNone(body)
        self.assertEqual(self.request("GET", f"/api/rooms/{room['id']}")[0], 404)

    def test_concurrent_joins_do_not_exceed_room_capacity(self):
        _, owner_token = self.create_account("capacity_owner")
        _, first_token = self.create_account("capacity_first")
        _, second_token = self.create_account("capacity_second")
        status, room = self.request(
            "POST",
            "/api/rooms",
            {"name": "Limited", "max_players": 2},
            token=owner_token,
        )
        self.assertEqual(status, 201)

        def join(token):
            return self.request(
                "POST", f"/api/rooms/{room['id']}/join", {}, token=token
            )[0]

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(join, (first_token, second_token)))
        self.assertCountEqual(results, [200, 409])
        status, details = self.request("GET", f"/api/rooms/{room['id']}")
        self.assertEqual(status, 200)
        self.assertEqual(details["player_count"], 2)

    def test_room_membership_requires_authentication_and_supports_leave(self):
        _, owner_token = self.create_account("owner2")
        _, guest_token = self.create_account("guest2")
        status, body = self.request("POST", "/api/rooms", {"name": "Open"})
        self.assertEqual(status, 401)
        self.assertIn("error", body)

        status, room = self.request(
            "POST", "/api/rooms", {"name": "Open"}, token=owner_token
        )
        self.assertEqual(status, 201)
        self.assertEqual(
            self.request("POST", f"/api/rooms/{room['id']}/join", {}, token=guest_token)[0],
            200,
        )
        status, detail = self.request("GET", f"/api/rooms/{room['id']}")
        self.assertEqual(status, 200)
        self.assertEqual(detail["player_count"], 2)
        self.assertEqual(
            self.request("POST", f"/api/rooms/{room['id']}/leave", {}, token=guest_token)[0],
            200,
        )

    def test_duplicate_registration_and_invalid_login(self):
        self.create_account("duplicate")
        status, body = self.request(
            "POST",
            "/api/accounts/register",
            {"username": "duplicate", "password": "correct horse battery"},
        )
        self.assertEqual(status, 409)
        self.assertIn("error", body)
        status, body = self.request(
            "POST",
            "/api/accounts/login",
            {"username": "duplicate", "password": "incorrect password"},
        )
        self.assertEqual(status, 401)
        self.assertIn("error", body)

    def test_admin_permissions_temporary_ban_and_unban(self):
        _, admin_token = self.create_admin("moderator")
        _, player_token = self.create_account("player_to_ban")

        self.assertEqual(
            self.request("GET", "/api/admin/players", token=player_token)[0], 403
        )
        status, players = self.request(
            "GET", "/api/admin/players", token=admin_token
        )
        self.assertEqual(status, 200)
        self.assertTrue(any(player["username"] == "player_to_ban" for player in players["players"]))

        status, result = self.request(
            "POST",
            "/api/admin/players/player_to_ban/ban",
            {"duration_seconds": 3600},
            token=admin_token,
        )
        self.assertEqual(status, 200)
        self.assertIsInstance(result["banned_until"], int)
        self.assertEqual(
            self.request("POST", "/api/accounts/login", {
                "username": "player_to_ban", "password": "correct horse battery"
            })[0],
            403,
        )
        self.assertEqual(
            self.request("POST", "/api/rooms", {"name": "Blocked"}, token=player_token)[0],
            401,
        )

        status, result = self.request(
            "POST",
            "/api/admin/players/player_to_ban/unban",
            {},
            token=admin_token,
        )
        self.assertEqual(status, 200)
        self.assertIsNone(result["banned_until"])
        self.assertEqual(
            self.request("POST", "/api/accounts/login", {
                "username": "player_to_ban", "password": "correct horse battery"
            })[0],
            200,
        )
        with server.connect(self.database_path) as connection:
            connection.execute(
                "UPDATE accounts SET banned_until = ? WHERE username = ?",
                (int(time.time()) - 1, "player_to_ban"),
            )
        self.assertEqual(
            self.request("POST", "/api/accounts/login", {
                "username": "player_to_ban", "password": "correct horse battery"
            })[0],
            200,
        )

    def test_admin_password_reset_revokes_sessions_and_permanent_ban(self):
        _, admin_token = self.create_admin("password_moderator")
        _, player_token = self.create_account("reset_player")

        status, result = self.request(
            "POST",
            "/api/admin/players/reset_player/password",
            {"password": "a different safe password"},
            token=admin_token,
        )
        self.assertEqual(status, 200)
        self.assertTrue(result["password_changed"])
        self.assertEqual(
            self.request("POST", "/api/rooms", {"name": "Old session"}, token=player_token)[0],
            401,
        )
        self.assertEqual(
            self.request("POST", "/api/accounts/login", {
                "username": "reset_player", "password": "correct horse battery"
            })[0],
            401,
        )
        status, login = self.request(
            "POST",
            "/api/accounts/login",
            {"username": "reset_player", "password": "a different safe password"},
        )
        self.assertEqual(status, 200)

        status, result = self.request(
            "POST",
            "/api/admin/players/reset_player/ban",
            {"duration_seconds": None},
            token=admin_token,
        )
        self.assertEqual(status, 200)
        self.assertIsNone(result["banned_until"])
        status, players = self.request("GET", "/api/admin/players", token=admin_token)
        player = next(item for item in players["players"] if item["username"] == "reset_player")
        self.assertTrue(player["is_banned"])
        self.assertIsNone(player["banned_until"])
        self.assertEqual(
            self.request("POST", "/api/accounts/login", {
                "username": "reset_player", "password": "a different safe password"
            })[0],
            403,
        )

    def test_database_initialization_adds_admin_columns_to_existing_accounts(self):
        legacy_path = str(Path(self.temp_dir.name) / "legacy.db")
        with server.connect(legacy_path) as connection:
            connection.execute(
                """
                CREATE TABLE accounts (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    password_salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
        server.initialize_database(legacy_path)
        with server.connect(legacy_path) as connection:
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(accounts)")
            }
        self.assertIn("is_admin", columns)
        self.assertIn("banned_until", columns)


if __name__ == "__main__":
    unittest.main()
