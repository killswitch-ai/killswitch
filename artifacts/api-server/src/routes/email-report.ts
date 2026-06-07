import { Router, type IRouter, type Request, type Response } from "express";

const router: IRouter = Router();

// 3 sends per hour per IP — this is a machine-called endpoint
const RATE_WINDOW_MS = 60 * 60_000;
const RATE_MAX = 3;
const rateMap = new Map<string, { count: number; windowStart: number }>();

setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of rateMap) {
    if (now - e.windowStart > RATE_WINDOW_MS) rateMap.delete(ip);
  }
}, 15 * 60_000).unref();

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const e = rateMap.get(ip);
  if (!e || now - e.windowStart > RATE_WINDOW_MS) {
    rateMap.set(ip, { count: 1, windowStart: now });
    return false;
  }
  if (e.count >= RATE_MAX) return true;
  e.count += 1;
  return false;
}

function getIp(req: Request): string {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string") return fwd.split(",")[0].trim();
  return req.socket.remoteAddress ?? "unknown";
}

function num(v: unknown): number {
  return typeof v === "number" && isFinite(v) ? Math.max(0, Math.floor(v)) : 0;
}

function buildHtml(r: Record<string, unknown>): string {
  const period = num(r.period_days) || 7;
  const total = num(r.total_events);
  const cats = r.finding_categories && typeof r.finding_categories === "object"
    ? Object.entries(r.finding_categories as Record<string, number>)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
    : [];
  const types = r.finding_types && typeof r.finding_types === "object"
    ? Object.entries(r.finding_types as Record<string, number>)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
    : [];

  const catRows = cats.map(([k, v]) =>
    `<div class="stat"><span class="label">${k.replace(/_/g, " ")}</span><span class="value">${v}</span></div>`
  ).join("");

  const typeRows = types.map(([k, v]) =>
    `<div class="stat"><span class="label">${k.replace(/_/g, " ")}</span><span class="value">${v}</span></div>`
  ).join("");

  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#1a1a1a;max-width:560px;margin:40px auto;padding:0 20px}
h1{font-size:20px;color:#d32f2f;margin-bottom:4px}
.subtitle{color:#666;font-size:14px;margin-bottom:32px}
.section{margin-bottom:24px}
.section h2{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:#666;border-bottom:1px solid #eee;padding-bottom:6px;margin-bottom:12px}
.stat{display:flex;justify-content:space-between;padding:6px 0;font-size:15px}
.stat .label{color:#444}
.stat .value{font-weight:600;color:#111}
.crit{color:#d32f2f}.high{color:#e64a19}
.notice{background:#f5f5f5;border-left:3px solid #ccc;padding:12px 16px;font-size:13px;color:#555;border-radius:2px}
.footer{font-size:12px;color:#aaa;margin-top:32px}
</style></head>
<body>
<h1>killswitch-ai</h1>
<p class="subtitle">Weekly Summary — Last ${period} days</p>
<div class="section">
  <h2>Activity</h2>
  <div class="stat"><span class="label">LLM calls scanned</span><span class="value">${total}</span></div>
  <div class="stat"><span class="label">Requests blocked</span><span class="value">${num(r.blocked)}</span></div>
  <div class="stat"><span class="label">Requests redacted</span><span class="value">${num(r.redacted)}</span></div>
  <div class="stat"><span class="label">Requests flagged</span><span class="value">${num(r.flagged)}</span></div>
  <div class="stat"><span class="label">Requests allowed</span><span class="value">${num(r.allowed)}</span></div>
</div>
<div class="section">
  <h2>Findings by severity</h2>
  <div class="stat"><span class="label">Critical</span><span class="value crit">${num(r.critical_findings)}</span></div>
  <div class="stat"><span class="label">High</span><span class="value high">${num(r.high_findings)}</span></div>
  <div class="stat"><span class="label">Medium</span><span class="value">${num(r.medium_findings)}</span></div>
  <div class="stat"><span class="label">Low</span><span class="value">${num(r.low_findings)}</span></div>
</div>
${catRows ? `<div class="section"><h2>Findings by category</h2>${catRows}</div>` : ""}
${typeRows ? `<div class="section"><h2>Top finding types</h2>${typeRows}</div>` : ""}
<div class="notice">
  <strong>Privacy:</strong> This report contains only anonymized counts.
  No prompt text, file contents, secret values, or payload data was included.
</div>
<p class="footer">
  Install ID (hashed): ${String(r.install_id_hash ?? "").slice(0, 32)}<br>
  Project ID (hashed): ${String(r.project_id_hash ?? "").slice(0, 32)}<br><br>
  To turn off: <code>killswitch email --off</code> &nbsp;|&nbsp;
  Detailed local reports: <code>killswitch menu</code>
</p>
</body></html>`;
}

function buildText(r: Record<string, unknown>): string {
  const period = num(r.period_days) || 7;
  const lines = [
    "killswitch-ai Weekly Summary",
    "=".repeat(40),
    "",
    `Period: Last ${period} days`,
    `Generated: ${r.generated_at ?? new Date().toISOString()}`,
    "",
    "Activity",
    "-".repeat(20),
    `  Total LLM calls scanned : ${num(r.total_events)}`,
    `  Requests blocked        : ${num(r.blocked)}`,
    `  Requests redacted       : ${num(r.redacted)}`,
    `  Requests flagged        : ${num(r.flagged)}`,
    `  Requests allowed        : ${num(r.allowed)}`,
    "",
    "Findings by severity",
    "-".repeat(20),
    `  Critical : ${num(r.critical_findings)}`,
    `  High     : ${num(r.high_findings)}`,
    `  Medium   : ${num(r.medium_findings)}`,
    `  Low      : ${num(r.low_findings)}`,
    "",
    "Privacy notice",
    "-".repeat(20),
    "This report contains only anonymized counts.",
    "No prompt text, file contents, secret values, or payload data was included.",
    "",
    `Install ID (hashed): ${String(r.install_id_hash ?? "").slice(0, 32)}`,
    `Project ID (hashed): ${String(r.project_id_hash ?? "").slice(0, 32)}`,
    "",
    "To turn off email reports: killswitch email --off",
    "To view detailed local reports: killswitch menu",
  ];
  return lines.join("\n");
}

router.post("/email-report", async (req: Request, res: Response): Promise<void> => {
  if (isRateLimited(getIp(req))) {
    res.status(429).json({ error: "Rate limit exceeded. Please wait before sending another report." });
    return;
  }

  const body = req.body as Record<string, unknown>;
  const to = typeof body.to === "string" ? body.to.trim() : "";

  if (!to || !to.includes("@") || to.length > 254) {
    res.status(400).json({ error: "Invalid or missing 'to' email address." });
    return;
  }

  const RESEND_API_KEY = process.env["RESEND_API_KEY"];
  if (!RESEND_API_KEY) {
    res.status(503).json({ error: "Email service is not configured." });
    return;
  }

  try {
    const { Resend } = await import("resend");
    const resend = new Resend(RESEND_API_KEY);

    const totalEvents = num(body.total_events);
    const subject = `killswitch-ai Weekly Summary — ${totalEvents} scan${totalEvents !== 1 ? "s" : ""}`;

    const { error } = await resend.emails.send({
      from: "killswitch-ai <reports@killswitch-ai.com>",
      to,
      subject,
      text: buildText(body),
      html: buildHtml(body),
    });

    if (error) {
      console.error("Resend error (email-report):", error);
      res.status(500).json({ error: "Failed to send report email." });
      return;
    }

    res.status(200).json({ ok: true });
  } catch (err) {
    console.error("Email report error:", err);
    res.status(500).json({ error: "Failed to send report email." });
  }
});

export default router;
