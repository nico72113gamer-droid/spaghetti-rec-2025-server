import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../src";

async function request(
  method: string,
  path: string,
  payload?: unknown,
  token?: string,
): Promise<Response> {
  const headers = new Headers();
  let body: string | undefined;
  if (payload !== undefined) {
    body = JSON.stringify(payload);
    headers.set("Content-Type", "application/json");
  }
  if (token) headers.set("Authorization", `Bearer ${token}`);
  return worker.fetch(new Request(`https://spaghettirec.test${path}`, {
    method,
    headers,
    body,
  }), env);
}

async function createAccount(username: string): Promise<string> {
  const registration = await request("POST", "/api/accounts/register", {
    username,
    password: "correct horse battery",
  });
  expect(registration.status).toBe(201);
  const login = await request("POST", "/api/accounts/login", {
    username,
    password: "correct horse battery",
  });
  expect(login.status).toBe(200);
  return ((await login.json()) as { token: string }).token;
}

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM room_members"),
    env.DB.prepare("DELETE FROM tokens"),
    env.DB.prepare("DELETE FROM rooms"),
    env.DB.prepare("DELETE FROM accounts"),
  ]);
});

describe("Cloudflare Worker API", () => {
  it("serves health checks and registers/logs in accounts", async () => {
    const health = await request("GET", "/health");
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ status: "ok" });

    const registration = await request("POST", "/api/accounts/register", {
      username: "test_player",
      password: "correct horse battery",
    });
    expect(registration.status).toBe(201);

    const login = await request("POST", "/api/accounts/login", {
      username: "TEST_PLAYER",
      password: "correct horse battery",
    });
    expect(login.status).toBe(200);
    const loginBody = (await login.json()) as { token: string };
    expect(loginBody.token).toBeTruthy();

    const duplicate = await request("POST", "/api/accounts/register", {
      username: "TEST_PLAYER",
      password: "correct horse battery",
    });
    expect(duplicate.status).toBe(409);
    const invalidLogin = await request("POST", "/api/accounts/login", {
      username: "test_player",
      password: "incorrect password",
    });
    expect(invalidLogin.status).toBe(401);
  });

  it("preserves room authentication, capacity, and deletion behavior", async () => {
    const ownerToken = await createAccount("room_owner");
    const guestToken = await createAccount("room_guest");
    const unauthorized = await request("POST", "/api/rooms", { name: "Open" });
    expect(unauthorized.status).toBe(401);

    const create = await request(
      "POST",
      "/api/rooms",
      { name: "Limited", max_players: 1 },
      ownerToken,
    );
    expect(create.status).toBe(201);
    const room = (await create.json()) as { id: string };

    const join = await request(
      "POST",
      `/api/rooms/${room.id}/join`,
      {},
      guestToken,
    );
    expect(join.status).toBe(409);

    const deletion = await request(
      "DELETE",
      `/api/rooms/${room.id}`,
      undefined,
      ownerToken,
    );
    expect(deletion.status).toBe(204);
  });

  it("supports admin password resets, bans, and unbans", async () => {
    const adminToken = await createAccount("test_moderator");
    const playerToken = await createAccount("test_target");
    await env.DB.prepare("UPDATE accounts SET is_admin = 1 WHERE username = ?")
      .bind("test_moderator")
      .run();

    const reset = await request(
      "POST",
      "/api/admin/players/test_target/password",
      { password: "a different safe password" },
      adminToken,
    );
    expect(reset.status).toBe(200);
    expect(
      (
        await request("POST", "/api/rooms", { name: "Old session" }, playerToken)
      ).status,
    ).toBe(401);
    expect(
      (
        await request("POST", "/api/accounts/login", {
          username: "test_target",
          password: "correct horse battery",
        })
      ).status,
    ).toBe(401);

    const ban = await request(
      "POST",
      "/api/admin/players/test_target/ban",
      { duration_seconds: null },
      adminToken,
    );
    expect(ban.status).toBe(200);
    expect(await ban.json()).toMatchObject({
      username: "test_target",
      banned_until: null,
      is_banned: true,
    });

    const unban = await request(
      "POST",
      "/api/admin/players/test_target/unban",
      {},
      adminToken,
    );
    expect(unban.status).toBe(200);
    expect(
      (
        await request("POST", "/api/accounts/login", {
          username: "test_target",
          password: "a different safe password",
        })
      ).status,
    ).toBe(200);
  });
});
