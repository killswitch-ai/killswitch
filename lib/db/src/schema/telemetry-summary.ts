import { pgTable, integer, timestamp } from "drizzle-orm/pg-core";

export const telemetrySummaryTable = pgTable("telemetry_summary", {
  id: integer("id").primaryKey().default(1),
  totalReports: integer("total_reports").default(0).notNull(),
  totalCommandsAnalyzed: integer("total_commands_analyzed").default(0).notNull(),
  totalProhibitedStopped: integer("total_prohibited_stopped").default(0).notNull(),
  totalSensitiveStopped: integer("total_sensitive_stopped").default(0).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

export type TelemetrySummary = typeof telemetrySummaryTable.$inferSelect;
