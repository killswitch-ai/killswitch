import { pgTable, serial, text, integer, jsonb, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const telemetryEventsTable = pgTable("telemetry_events", {
  id: serial("id").primaryKey(),
  installId: text("install_id").notNull(),
  reportedAt: timestamp("reported_at", { withTimezone: true }).defaultNow().notNull(),
  libVersion: text("lib_version"),
  pythonVersion: text("python_version"),
  osType: text("os_type"),
  commandsAnalyzed: integer("commands_analyzed").default(0).notNull(),
  prohibitedStopped: integer("prohibited_stopped").default(0).notNull(),
  sensitiveStopped: integer("sensitive_stopped").default(0).notNull(),
  agents: jsonb("agents"),
  providers: jsonb("providers"),
  modes: jsonb("modes"),
  findingTypes: jsonb("finding_types"),
});

export const insertTelemetryEventSchema = createInsertSchema(telemetryEventsTable).omit({
  id: true,
  reportedAt: true,
});

export type InsertTelemetryEvent = z.infer<typeof insertTelemetryEventSchema>;
export type TelemetryEvent = typeof telemetryEventsTable.$inferSelect;
