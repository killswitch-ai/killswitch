import { Router, type IRouter } from "express";

const router: IRouter = Router();

const CACHE_TTL_MS = 5 * 60 * 1000;

interface PyPIRecentData {
  last_day: number;
  last_week: number;
  last_month: number;
}

let cached: { data: PyPIRecentData; fetchedAt: number } | null = null;

router.get("/pypi-stats", async (_req, res): Promise<void> => {
  const now = Date.now();

  if (cached && now - cached.fetchedAt < CACHE_TTL_MS) {
    res.json(cached.data);
    return;
  }

  try {
    const response = await fetch(
      "https://pypistats.org/api/packages/killswitch-ai/recent",
      { headers: { Accept: "application/json" } },
    );

    if (!response.ok) {
      if (cached) {
        res.json(cached.data);
        return;
      }
      res.status(502).json({ error: "Failed to fetch PyPI stats" });
      return;
    }

    const json = await response.json() as { data: PyPIRecentData };
    cached = { data: json.data, fetchedAt: now };
    res.json(json.data);
  } catch {
    if (cached) {
      res.json(cached.data);
      return;
    }
    res.status(502).json({ error: "Failed to fetch PyPI stats" });
  }
});

export default router;
