import { applyD1Migrations } from "cloudflare:test";
import { env } from "cloudflare:workers";

type TestEnv = typeof env & {
  TEST_MIGRATIONS: Array<{ name: string; queries: string[] }>;
};

await applyD1Migrations(
  env.DB,
  (env as TestEnv).TEST_MIGRATIONS,
);
