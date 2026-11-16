import type { Env as WorkerBindings } from "../src";

declare global {
  namespace Cloudflare {
    interface Env extends WorkerBindings {}
  }
}
