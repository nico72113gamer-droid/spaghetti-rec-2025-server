const MAX_BODY_SIZE = 64 * 1024;
const TOKEN_LIFETIME = 30 * 24 * 60 * 60;
const PASSWORD_ITERATIONS = 260_000;
const USERNAME_PATTERN = /^[A-Za-z0-9_-]{3,24}$/;
const encoder = new TextEncoder();

export interface Env {
  DB: D1Database;
}

interface Account {
  id: string;
  username: string;
  is_admin: number;
  banned_until: number | null;
}

interface LoginAccount extends Account {
  password_salt: string;
  password_hash: string;
}

interface Room {
  id: string;
  name: string;
  max_players: number;
  created_at: number;
  owner: string;
  player_count: number;
}

type JsonObject = Record<string, unknown>;

class APIError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function jsonResponse(status: number, payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function emptyResponse(status: number): Response {
  return new Response(null, { status });
}

async function readJson(request: Request): Promise<JsonObject> {
  const contentType = request.headers.get("Content-Type") ?? "";
  if (contentType.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    throw new APIError(415, "Content-Type must be application/json");
  }

  const contentLength = request.headers.get("Content-Length");
  if (contentLength !== null && !/^\d+$/.test(contentLength)) {
    throw new APIError(400, "A valid Content-Length is required");
  }
  if (contentLength !== null) {
    const length = Number(contentLength);
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new APIError(400, "Invalid Content-Length");
    }
    if (length > MAX_BODY_SIZE) {
      throw new APIError(413, "Request body is too large");
    }
  }

  const reader = request.body?.getReader();
  if (!reader) {
    throw new APIError(400, "Request body must be valid JSON");
  }

  const chunks: Uint8Array[] = [];
  let totalLength = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    totalLength += value.byteLength;
    if (totalLength > MAX_BODY_SIZE) {
      await reader.cancel();
      throw new APIError(413, "Request body is too large");
    }
    chunks.push(value);
  }

  let text: string;
  try {
    const bytes = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    throw new APIError(400, "Request body must be valid JSON");
  }

  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    throw new APIError(400, "Request body must be valid JSON");
  }
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new APIError(400, "Request body must be a JSON object");
  }
  return payload as JsonObject;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/i.test(value)) {
    throw new Error("Stored password hash is invalid");
  }
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

async function digest(value: string): Promise<string> {
  const result = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return bytesToHex(new Uint8Array(result));
}

async function passwordHash(password: string, salt: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const result = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PASSWORD_ITERATIONS },
    key,
    256,
  );
  return bytesToHex(new Uint8Array(result));
}

function equalHash(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

function randomToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function isBanned(bannedUntil: number | null, now: number): boolean {
  return bannedUntil === 0 || (bannedUntil !== null && bannedUntil > now);
}

async function authenticatedAccount(
  request: Request,
  db: D1Database,
): Promise<Account> {
  const authorization = request.headers.get("Authorization") ?? "";
  const separator = authorization.indexOf(" ");
  const scheme = separator < 0 ? authorization : authorization.slice(0, separator);
  const token = separator < 0 ? "" : authorization.slice(separator + 1);
  if (scheme.toLowerCase() !== "bearer" || !token) {
    throw new APIError(401, "A bearer token is required");
  }

  const account = await db
    .prepare(
      `SELECT accounts.id, accounts.username, accounts.is_admin, accounts.banned_until
       FROM tokens JOIN accounts ON accounts.id = tokens.account_id
       WHERE tokens.token_hash = ? AND tokens.expires_at > ?`,
    )
    .bind(await digest(token), nowSeconds())
    .first<Account>();
  if (!account) throw new APIError(401, "Invalid or expired bearer token");
  if (isBanned(account.banned_until, nowSeconds())) {
    throw new APIError(403, "This account is banned");
  }
  return account;
}

async function requireAdmin(request: Request, db: D1Database): Promise<Account> {
  const account = await authenticatedAccount(request, db);
  if (!account.is_admin) {
    throw new APIError(403, "Administrator access is required");
  }
  return account;
}

function normalizedPath(request: Request): string {
  return new URL(request.url).pathname.replace(/\/+$/, "") || "/";
}

function isDatabaseConflict(error: unknown): boolean {
  return (
    error instanceof Error &&
    /(?:UNIQUE|PRIMARY KEY|FOREIGN KEY|CHECK) constraint failed/i.test(error.message)
  );
}

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const { DB: db } = env;
  const path = normalizedPath(request);

  if (request.method === "GET") {
    if (path === "/health") return jsonResponse(200, { status: "ok" });

    if (path === "/api/admin/players") {
      await requireAdmin(request, db);
      const now = nowSeconds();
      const players = await db
        .prepare(
          `SELECT id, username, is_admin,
                  CASE WHEN banned_until = 0 THEN NULL
                       WHEN banned_until > ? THEN banned_until
                       ELSE NULL END AS banned_until,
                  CASE WHEN banned_until = 0 OR banned_until > ?
                       THEN 1 ELSE 0 END AS is_banned
           FROM accounts ORDER BY username COLLATE NOCASE`,
        )
        .bind(now, now)
        .all();
      return jsonResponse(200, { players: players.results });
    }

    if (path === "/api/rooms") {
      const rooms = await db
        .prepare(
          `SELECT rooms.id, rooms.name, rooms.max_players, rooms.created_at,
                  accounts.username AS owner,
                  COUNT(room_members.account_id) AS player_count
           FROM rooms
           JOIN accounts ON accounts.id = rooms.owner_id
           LEFT JOIN room_members ON room_members.room_id = rooms.id
           GROUP BY rooms.id
           ORDER BY rooms.created_at DESC`,
        )
        .all<Room>();
      return jsonResponse(200, { rooms: rooms.results });
    }

    const roomMatch = path.match(/^\/api\/rooms\/([^/]+)$/);
    if (roomMatch) {
      const roomId = roomMatch[1];
      const room = await db
        .prepare(
          `SELECT rooms.id, rooms.name, rooms.max_players, rooms.created_at,
                  accounts.username AS owner,
                  COUNT(room_members.account_id) AS player_count
           FROM rooms
           JOIN accounts ON accounts.id = rooms.owner_id
           LEFT JOIN room_members ON room_members.room_id = rooms.id
           WHERE rooms.id = ?
           GROUP BY rooms.id`,
        )
        .bind(roomId)
        .first<Room>();
      if (!room) throw new APIError(404, "Room not found");
      const players = await db
        .prepare(
          `SELECT accounts.username
           FROM room_members JOIN accounts ON accounts.id = room_members.account_id
           WHERE room_members.room_id = ?
           ORDER BY room_members.joined_at`,
        )
        .bind(roomId)
        .all<{ username: string }>();
      return jsonResponse(200, {
        ...room,
        players: players.results.map((player) => player.username),
      });
    }

    throw new APIError(404, "Not found");
  }

  if (request.method === "POST") {
    const payload = await readJson(request);

    if (path === "/api/accounts/register") {
      const { username, password } = payload;
      if (typeof username !== "string" || !USERNAME_PATTERN.test(username)) {
        throw new APIError(
          400,
          "Username must be 3-24 letters, numbers, underscores, or hyphens",
        );
      }
      if (
        typeof password !== "string" ||
        [...password].length < 8 ||
        [...password].length > 128
      ) {
        throw new APIError(400, "Password must be between 8 and 128 characters");
      }
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const accountId = crypto.randomUUID();
      await db
        .prepare(
          `INSERT INTO accounts (id, username, password_salt, password_hash, created_at)
           VALUES (?, ?, ?, ?, ?)`,
        )
        .bind(
          accountId,
          username,
          bytesToHex(salt),
          await passwordHash(password, salt),
          nowSeconds(),
        )
        .run();
      return jsonResponse(201, { id: accountId, username });
    }

    if (path === "/api/accounts/login") {
      const { username, password } = payload;
      if (typeof username !== "string" || typeof password !== "string") {
        throw new APIError(400, "Username and password are required");
      }
      const account = await db
        .prepare(
          `SELECT id, username, is_admin, banned_until, password_salt, password_hash
           FROM accounts WHERE username = ?`,
        )
        .bind(username)
        .first<LoginAccount>();
      if (!account) throw new APIError(401, "Invalid username or password");

      const candidate = await passwordHash(password, hexToBytes(account.password_salt));
      if (!equalHash(candidate, account.password_hash)) {
        throw new APIError(401, "Invalid username or password");
      }
      if (isBanned(account.banned_until, nowSeconds())) {
        throw new APIError(403, "This account is banned");
      }

      const token = randomToken();
      const expiresAt = nowSeconds() + TOKEN_LIFETIME;
      await db
        .prepare("INSERT INTO tokens (token_hash, account_id, expires_at) VALUES (?, ?, ?)")
        .bind(await digest(token), account.id, expiresAt)
        .run();
      return jsonResponse(200, {
        token,
        expires_at: expiresAt,
        account: { id: account.id, username: account.username },
      });
    }

    const adminMatch = path.match(/^\/api\/admin\/players\/([^/]+)\/(ban|unban|password)$/);
    if (adminMatch) {
      const [, username, action] = adminMatch;
      await requireAdmin(request, db);
      const player = await db
        .prepare("SELECT id, is_admin FROM accounts WHERE username = ?")
        .bind(username)
        .first<{ id: string; is_admin: number }>();
      if (!player) throw new APIError(404, "Player not found");
      if (player.is_admin) {
        throw new APIError(403, "This action cannot be used on an administrator");
      }

      if (action === "password") {
        const password = payload.password;
        if (
          typeof password !== "string" ||
          [...password].length < 8 ||
          [...password].length > 128
        ) {
          throw new APIError(400, "Password must be between 8 and 128 characters");
        }
        const salt = crypto.getRandomValues(new Uint8Array(16));
        await db.batch([
          db
            .prepare(
              "UPDATE accounts SET password_salt = ?, password_hash = ? WHERE id = ?",
            )
            .bind(
              bytesToHex(salt),
              await passwordHash(password, salt),
              player.id,
            ),
          db.prepare("DELETE FROM tokens WHERE account_id = ?").bind(player.id),
        ]);
        return jsonResponse(200, { username, password_changed: true });
      }

      if (action === "unban") {
        await db
          .prepare("UPDATE accounts SET banned_until = NULL WHERE id = ?")
          .bind(player.id)
          .run();
        return jsonResponse(200, {
          username,
          banned_until: null,
          is_banned: false,
        });
      }

      const duration = payload.duration_seconds ?? null;
      if (
        duration !== null &&
        (typeof duration !== "number" ||
          !Number.isSafeInteger(duration) ||
          duration <= 0 ||
          duration > Number.MAX_SAFE_INTEGER - nowSeconds())
      ) {
        throw new APIError(400, "duration_seconds must be a positive integer or null");
      }
      const bannedUntil = duration === null ? null : nowSeconds() + duration;
      await db.batch([
        db
          .prepare("UPDATE accounts SET banned_until = ? WHERE id = ?")
          .bind(bannedUntil === null ? 0 : bannedUntil, player.id),
        db.prepare("DELETE FROM tokens WHERE account_id = ?").bind(player.id),
        db.prepare("DELETE FROM room_members WHERE account_id = ?").bind(player.id),
      ]);
      return jsonResponse(200, {
        username,
        banned_until: bannedUntil,
        is_banned: true,
      });
    }

    const membershipMatch = path.match(/^\/api\/rooms\/([^/]+)\/(join|leave)$/);
    if (path === "/api/rooms" || membershipMatch) {
      const account = await authenticatedAccount(request, db);
      if (path === "/api/rooms") {
        const name = payload.name;
        const maxPlayers = payload.max_players === undefined ? 8 : payload.max_players;
        if (typeof name !== "string" || !name.trim() || name.trim().length > 64) {
          throw new APIError(400, "Room name must be between 1 and 64 characters");
        }
        if (
          typeof maxPlayers !== "number" ||
          !Number.isInteger(maxPlayers) ||
          maxPlayers < 1 ||
          maxPlayers > 40
        ) {
          throw new APIError(400, "max_players must be an integer from 1 to 40");
        }
        const roomId = crypto.randomUUID();
        const now = nowSeconds();
        const roomName = name.trim();
        await db.batch([
          db
            .prepare(
              "INSERT INTO rooms (id, name, owner_id, max_players, created_at) VALUES (?, ?, ?, ?, ?)",
            )
            .bind(roomId, roomName, account.id, maxPlayers, now),
          db
            .prepare(
              "INSERT INTO room_members (room_id, account_id, joined_at) VALUES (?, ?, ?)",
            )
            .bind(roomId, account.id, now),
        ]);
        return jsonResponse(201, {
          id: roomId,
          name: roomName,
          owner: account.username,
          max_players: maxPlayers,
          player_count: 1,
        });
      }

      const [, roomId, action] = membershipMatch!;
      const room = await db
        .prepare("SELECT id, max_players FROM rooms WHERE id = ?")
        .bind(roomId)
        .first<{ id: string; max_players: number }>();
      if (!room) throw new APIError(404, "Room not found");

      if (action === "join") {
        const existing = await db
          .prepare("SELECT 1 FROM room_members WHERE room_id = ? AND account_id = ?")
          .bind(roomId, account.id)
          .first();
        if (!existing) {
          const result = await db
            .prepare(
              `INSERT INTO room_members (room_id, account_id, joined_at)
               SELECT ?, ?, ?
               WHERE (SELECT COUNT(*) FROM room_members WHERE room_id = ?)
                     < (SELECT max_players FROM rooms WHERE id = ?)
                 AND EXISTS (SELECT 1 FROM rooms WHERE id = ?)`,
            )
            .bind(roomId, account.id, nowSeconds(), roomId, roomId, roomId)
            .run();
          if (result.meta.changes === 0) {
            const stillExists = await db
              .prepare("SELECT 1 FROM rooms WHERE id = ?")
              .bind(roomId)
              .first();
            if (!stillExists) throw new APIError(404, "Room not found");
            throw new APIError(409, "Room is full");
          }
        }
      } else {
        await db
          .prepare("DELETE FROM room_members WHERE room_id = ? AND account_id = ?")
          .bind(roomId, account.id)
          .run();
      }
      return jsonResponse(200, { room_id: roomId, joined: action === "join" });
    }

    throw new APIError(404, "Not found");
  }

  if (request.method === "DELETE") {
    const roomMatch = path.match(/^\/api\/rooms\/([^/]+)$/);
    if (!roomMatch) throw new APIError(404, "Not found");
    const account = await authenticatedAccount(request, db);
    const roomId = roomMatch[1];
    const room = await db
      .prepare("SELECT owner_id FROM rooms WHERE id = ?")
      .bind(roomId)
      .first<{ owner_id: string }>();
    if (!room) throw new APIError(404, "Room not found");
    if (room.owner_id !== account.id) {
      throw new APIError(403, "Only the room owner can delete this room");
    }
    await db.prepare("DELETE FROM rooms WHERE id = ?").bind(roomId).run();
    return emptyResponse(204);
  }

  throw new APIError(404, "Not found");
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      if (error instanceof APIError) {
        return jsonResponse(error.status, { error: error.message });
      }
      if (isDatabaseConflict(error)) {
        return jsonResponse(409, {
          error: "The requested resource conflicts with existing data",
        });
      }
      console.error("Request failed", error);
      return jsonResponse(500, { error: "Internal server error" });
    }
  },
};
