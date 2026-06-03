import { Router, type IRouter } from "express";
import { db, telemetryEventsTable } from "@workspace/db";
import { sql } from "drizzle-orm";
import {
  SubmitTelemetryBody,
  GetTelemetryStatsResponse,
} from "@workspace/api-zod";

const router: IRouter = Router();

router.post("/telemetry", async (req, res): Promise<void> => {
  const parsed = SubmitTelemetryBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const body = parsed.data;
  const [row] = await db
    .insert(telemetryEventsTable)
    .values({
      installId: body.install_id,
      libVersion: body.lib_version ?? null,
      pythonVersion: body.python_version ?? null,
      osType: body.os_type ?? null,
      commandsAnalyzed: body.commands_analyzed,
      prohibitedStopped: body.prohibited_stopped,
      sensitiveStopped: body.sensitive_stopped,
      agents: body.agents ?? null,
      providers: body.providers ?? null,
      modes: body.modes ?? null,
      findingTypes: body.finding_types ?? null,
    })
    .returning();

  res.status(201).json({
    id: row.id,
    install_id: row.installId,
    reported_at: row.reportedAt,
    lib_version: row.libVersion,
    python_version: row.pythonVersion,
    os_type: row.osType,
    commands_analyzed: row.commandsAnalyzed,
    prohibited_stopped: row.prohibitedStopped,
    sensitive_stopped: row.sensitiveStopped,
    agents: row.agents,
    providers: row.providers,
    modes: row.modes,
    finding_types: row.findingTypes,
  });
});

router.get("/telemetry", async (_req, res): Promise<void> => {
  const [agg] = await db
    .select({
      total_reports: sql<number>`count(*)::int`,
      total_commands_analyzed: sql<number>`coalesce(sum(commands_analyzed), 0)::int`,
      total_prohibited_stopped: sql<number>`coalesce(sum(prohibited_stopped), 0)::int`,
      total_sensitive_stopped: sql<number>`coalesce(sum(sensitive_stopped), 0)::int`,
    })
    .from(telemetryEventsTable);

  res.json(
    GetTelemetryStatsResponse.parse({
      total_reports: agg.total_reports,
      total_commands_analyzed: agg.total_commands_analyzed,
      total_prohibited_stopped: agg.total_prohibited_stopped,
      total_sensitive_stopped: agg.total_sensitive_stopped,
      top_agents: null,
      top_providers: null,
      top_finding_types: null,
    })
  );
});

export default router;
