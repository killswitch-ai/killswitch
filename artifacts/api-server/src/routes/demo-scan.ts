import { Router, type IRouter, type Request, type Response } from "express";
import { spawn } from "node:child_process";
import path from "node:path";

const router: IRouter = Router();

const HELPER_SCRIPT = path.resolve(process.cwd(), "scan_demo_helper.py");

const MAX_INPUT_BYTES = 8_000;
const MAX_OUTPUT_BYTES = 256 * 1024; // 256 KB
const RATE_WINDOW_MS = 60_000;
const RATE_MAX_REQUESTS = 20;

interface RateEntry {
  count: number;
  windowStart: number;
}

const rateMap = new Map<string, RateEntry>();

const SCAN_TIMEOUT_MS = 5_000;
const RATE_PRUNE_INTERVAL_MS = 5 * 60_000;

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateMap) {
    if (now - entry.windowStart > RATE_WINDOW_MS) {
      rateMap.delete(ip);
    }
  }
}, RATE_PRUNE_INTERVAL_MS).unref();

function getClientIp(req: Request): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0].trim();
  return req.socket.remoteAddress ?? "unknown";
}

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = rateMap.get(ip);

  if (!entry || now - entry.windowStart > RATE_WINDOW_MS) {
    rateMap.set(ip, { count: 1, windowStart: now });
    return false;
  }

  if (entry.count >= RATE_MAX_REQUESTS) return true;

  entry.count += 1;
  return false;
}

type Finding = {
  finding_id: string;
  severity: string;
  category: string;
  finding_type: string;
  description: string;
  recommendation: string;
  match_start: number;
  match_end: number;
};

function modeOutcomes(findings: Finding[]): Record<string, string> {
  if (findings.length === 0) {
    return {
      kill: "Request allowed — no threats detected",
      redact: "Request allowed — nothing to redact",
      pause: "Request allowed — no issues found",
      report_only: "Request allowed and logged as clean",
    };
  }
  return {
    kill: "Request BLOCKED — killswitch raised KillswitchBlocked exception",
    redact: `Request allowed after redacting ${findings.length} finding${findings.length > 1 ? "s" : ""} with [REDACTED_…] placeholders`,
    pause: "Execution PAUSED — user prompted in terminal to block, redact, or allow",
    report_only: "Request allowed — findings recorded in audit log only",
  };
}

router.post("/demo/scan", async (req: Request, res: Response): Promise<void> => {
  const ip = getClientIp(req);

  if (isRateLimited(ip)) {
    res.status(429).json({ error: "Rate limit exceeded. Max 20 requests per minute." });
    return;
  }

  const body = req.body as { text?: unknown };
  if (typeof body.text !== "string" || body.text.trim().length === 0) {
    res.status(400).json({ error: "text must be a non-empty string" });
    return;
  }
  if (body.text.length > MAX_INPUT_BYTES) {
    res.status(400).json({ error: `text must be ${MAX_INPUT_BYTES} characters or fewer` });
    return;
  }

  const text = body.text;

  let findings: Finding[];
  try {
    findings = await new Promise<Finding[]>((resolve, reject) => {
      const proc = spawn("python3", [HELPER_SCRIPT], {
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env },
      });

      let stdout = "";
      let stderr = "";
      let settled = false;

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        proc.kill("SIGKILL");
        reject(Object.assign(new Error("Scan timed out"), { code: "SCAN_TIMEOUT" }));
      }, SCAN_TIMEOUT_MS);

      proc.stdout.on("data", (chunk: Buffer) => {
        stdout += chunk.toString();
        if (Buffer.byteLength(stdout, "utf8") > MAX_OUTPUT_BYTES) {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          proc.kill("SIGKILL");
          reject(Object.assign(new Error("Scanner output exceeded limit"), { code: "OUTPUT_TOO_LARGE" }));
        }
      });
      proc.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });

      proc.on("close", (code) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (code !== 0) {
          reject(new Error(`Scanner exited with code ${code}: ${stderr.slice(0, 200)}`));
          return;
        }
        try {
          resolve(JSON.parse(stdout) as Finding[]);
        } catch {
          reject(new Error("Failed to parse scanner output"));
        }
      });

      proc.on("error", (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(err);
      });

      proc.stdin.write(text, "utf8");
      proc.stdin.end();
    });
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException & { code?: string }).code;
    if (err instanceof Error && code === "SCAN_TIMEOUT") {
      res.status(504).json({ error: "Scan timed out after 5 seconds. Please try a shorter input." });
      return;
    }
    if (err instanceof Error && code === "OUTPUT_TOO_LARGE") {
      res.status(500).json({ error: "Scanner output exceeded the allowed limit." });
      return;
    }
    throw err;
  }

  res.json({
    findings,
    summary: {
      total: findings.length,
      max_severity: findings.length === 0
        ? null
        : (["critical", "high", "medium", "low"].find(s => findings.some(f => f.severity === s)) ?? null),
      categories: [...new Set(findings.map(f => f.category))],
    },
    mode_outcomes: modeOutcomes(findings),
  });
});

export default router;
