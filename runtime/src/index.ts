import { claimSession } from "./db.js";
import { runSession, closeBrowser } from "./operator.js";

const HOST = process.env.RUNTIME_HOST_ID ?? `host-${Math.random().toString(36).slice(2, 8)}`;
const POLL = Number(process.env.POLL_INTERVAL_MS ?? 3000);

let shuttingDown = false;
process.on("SIGTERM", async () => { shuttingDown = true; await closeBrowser(); process.exit(0); });
process.on("SIGINT",  async () => { shuttingDown = true; await closeBrowser(); process.exit(0); });

console.log(`[runtime] starting host=${HOST} poll=${POLL}ms`);

async function loop() {
  while (!shuttingDown) {
    try {
      const s = await claimSession(HOST);
      if (!s) {
        await sleep(POLL);
        continue;
      }
      console.log(`[runtime] claimed session ${s.id} for target ${s.target_id}`);
      await runSession(s);
      console.log(`[runtime] finished session ${s.id}`);
    } catch (e) {
      console.error("[runtime] loop error:", e);
      await sleep(POLL);
    }
  }
}

function sleep(ms: number) { return new Promise((r) => setTimeout(r, ms)); }

loop().catch((e) => { console.error("fatal", e); process.exit(1); });
