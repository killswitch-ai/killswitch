import app from "./app";
import { logger } from "./lib/logger";
import { db, telemetryEventsTable, telemetrySummaryTable } from "@workspace/db";
import { sql } from "drizzle-orm";

const rawPort = process.env["PORT"];

if (!rawPort) {
  throw new Error(
    "PORT environment variable is required but was not provided.",
  );
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

async function seedTelemetrySummary(): Promise<void> {
  try {
    const existing = await db.query.telemetrySummaryTable.findFirst({
      where: (t, { eq }) => eq(t.id, 1),
    });

    if (!existing) {
      logger.info("Seeding telemetry_summary from existing events...");
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
        .onConflictDoNothing();

      logger.info(
        { total_reports: agg.total_reports },
        "Telemetry summary seeded",
      );
    }
  } catch (err) {
    logger.warn({ err }, "Failed to seed telemetry summary — will recompute on first GET");
  }
}

app.listen(port, async (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");
  await seedTelemetrySummary();
});
