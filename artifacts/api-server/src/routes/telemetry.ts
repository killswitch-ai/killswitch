import { Router, type IRouter } from "express";
import { db, telemetryEventsTable, telemetrySummaryTable } from "@workspace/db";
import { sql } from "drizzle-orm";
import {
  SubmitTelemetryBody,
  GetTelemetryStatsResponse,
} from "@workspace/api-zod";

const router: IRouter = Router();

async function ensureSummaryRow(): Promise<void> {
  await db
    .insert(telemetrySummaryTable)
    .values({
      id: 1,
      totalReports: 0,
      totalCommandsAnalyzed: 0,
      totalProhibitedStopped: 0,
      totalSensitiveStopped: 0,
    })
    .onConflictDoNothing();
}

async function recomputeSummaryFromEvents(): Promise<void> {
  const [agg] = await db
    .select({
      total_reports: sql<number>`count(*)::int`,
      total_commands_analyzed: sql<number>`coalesce(sum(commands_analyzed), 0)::int`,
      total_prohibited_stopped: sql<number>`coalesce(sum(prohibited_stopped), 0)::int`,
      total_sensitive_stopped: sql<number>`coalesce(sum(sensitive_stopped), 0)::int`,
    })
    .from(telemetryEventsTable);

  await db
    .insert(telemetrySummaryTable)
    .values({
      id: 1,
      totalReports: agg.total_reports,
      totalCommandsAnalyzed: agg.total_commands_analyzed,
      totalProhibitedStopped: agg.total_prohibited_stopped,
      totalSensitiveStopped: agg.total_sensitive_stopped,
    })
    .onConflictDoUpdate({
      target: telemetrySummaryTable.id,
      set: {
        totalReports: agg.total_reports,
        totalCommandsAnalyzed: agg.total_commands_analyzed,
        totalProhibitedStopped: agg.total_prohibited_stopped,
        totalSensitiveStopped: agg.total_sensitive_stopped,
        updatedAt: sql`now()`,
      },
    });
}

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

  await db
    .insert(telemetrySummaryTable)
    .values({
      id: 1,
      totalReports: 1,
      totalCommandsAnalyzed: body.commands_analyzed,
      totalProhibitedStopped: body.prohibited_stopped,
      totalSensitiveStopped: body.sensitive_stopped,
    })
    .onConflictDoUpdate({
      target: telemetrySummaryTable.id,
      set: {
        totalReports: sql`${telemetrySummaryTable.totalReports} + 1`,
        totalCommandsAnalyzed: sql`${telemetrySummaryTable.totalCommandsAnalyzed} + ${body.commands_analyzed}`,
        totalProhibitedStopped: sql`${telemetrySummaryTable.totalProhibitedStopped} + ${body.prohibited_stopped}`,
        totalSensitiveStopped: sql`${telemetrySummaryTable.totalSensitiveStopped} + ${body.sensitive_stopped}`,
        updatedAt: sql`now()`,
      },
    });

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
  let summary = await db.query.telemetrySummaryTable.findFirst({
    where: (t, { eq }) => eq(t.id, 1),
  });

  if (!summary) {
    await recomputeSummaryFromEvents();
    summary = await db.query.telemetrySummaryTable.findFirst({
      where: (t, { eq }) => eq(t.id, 1),
    });
  }

  if (!summary) {
    await ensureSummaryRow();
    summary = {
      id: 1,
      totalReports: 0,
      totalCommandsAnalyzed: 0,
      totalProhibitedStopped: 0,
      totalSensitiveStopped: 0,
      updatedAt: new Date(),
    };
  }

  res.json(
    GetTelemetryStatsResponse.parse({
      total_reports: summary.totalReports,
      total_commands_analyzed: summary.totalCommandsAnalyzed,
      total_prohibited_stopped: summary.totalProhibitedStopped,
      total_sensitive_stopped: summary.totalSensitiveStopped,
      top_agents: null,
      top_providers: null,
      top_finding_types: null,
    })
  );
});

export default router;
