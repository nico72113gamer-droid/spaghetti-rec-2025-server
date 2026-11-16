# Rec Room Revival Server

A small, dependency-free Python backend for a community-run Rec Room revival.
It provides account registration and login, bearer-token authentication, and
room discovery, membership, and admin moderation over JSON HTTP. It is a
starter backend, not a drop-in implementation of the original Rec Room
service or client protocol.

## Run

Requires Python 3.9 or newer. No third-party packages are needed.

```sh
python3 server.py
```

To grant administrator access to an existing account, stop the server and run:

```sh
python3 server.py make-admin player1
```

The command uses the same `REC_SERVER_DATABASE` setting as the server. Admin
accounts cannot be banned or have their passwords reset through the player
moderation endpoints.

By default, the server listens on `127.0.0.1:8000` and stores data in
`rec_room.db`. Configure it with:

- `REC_SERVER_HOST` — bind address
- `REC_SERVER_PORT` — HTTP port
- `REC_SERVER_DATABASE` — SQLite database path

## API

All request and response bodies use JSON. For protected endpoints, send
`Authorization: Bearer <token>`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Liveness check |
| `POST` | `/api/accounts/register` | Register with `{"username":"player1","password":"..."}` |
| `POST` | `/api/accounts/login` | Log in; returns a bearer token |
| `GET` | `/api/rooms` | Discover rooms |
| `POST` | `/api/rooms` | Create a room with `{"name":"Hangout","max_players":8}` |
| `GET` | `/api/rooms/{room_id}` | Get room and player details |
| `POST` | `/api/rooms/{room_id}/join` | Join a room |
| `POST` | `/api/rooms/{room_id}/leave` | Leave a room |
| `DELETE` | `/api/rooms/{room_id}` | Delete a room (owner only) |
| `GET` | `/api/admin/players` | List players and their moderation status (admin only) |
| `POST` | `/api/admin/players/{username}/ban` | Ban with `{"duration_seconds":3600}`; use `null` for a permanent ban (admin only) |
| `POST` | `/api/admin/players/{username}/unban` | Unban a player (admin only) |
| `POST` | `/api/admin/players/{username}/password` | Set a player's password with `{"password":"new-password"}` (admin only) |

Banning immediately revokes the player's active tokens and removes them from
rooms. After a temporary ban expires, they can log in again. Password resets
also revoke all active tokens for that player.

Usernames are 3-24 letters, digits, underscores, or hyphens; passwords are
8-128 characters; room capacity is 1-40 players. This starter is intended for
local development and should be deployed behind HTTPS with operational
hardening before being exposed to the public internet.

## Test

```sh
python3 -m unittest discover -s tests -v
```

## Deploy to Cloudflare Workers

The Cloudflare Worker implementation uses D1 and is maintained separately
from the Python server. Its database starts empty; the existing `rec_room.db`
is not migrated automatically.

1. Install the Worker tooling and authenticate:

   ```sh
   npm install
   npx wrangler login
   ```

2. Create the D1 database:

   ```sh
   npx wrangler d1 create spaghettirec --update-config
   ```

3. Apply the schema and deploy:

   ```sh
   npx wrangler d1 migrations apply spaghettirec --remote
   npm run deploy
   ```

Cloudflare prints the deployed `workers.dev` URL. Enable the `workers.dev`
subdomain for the account if prompted. To grant admin access to an existing
account, run:

```sh
npx wrangler d1 execute spaghettirec --remote \
  --command "UPDATE accounts SET is_admin = 1 WHERE username = 'player1';"
```

For local Worker development, apply migrations locally with
`npx wrangler d1 migrations apply spaghettirec --local`, then run `npm run dev`.
Run the Worker tests with `npm test` and its type check with `npm run typecheck`.