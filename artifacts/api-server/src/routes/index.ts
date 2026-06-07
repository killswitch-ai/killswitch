import { Router, type IRouter } from "express";
import healthRouter from "./health";
import telemetryRouter from "./telemetry";
import pypiStatsRouter from "./pypi-stats";
import demoScanRouter from "./demo-scan";
import contactRouter from "./contact";
import emailReportRouter from "./email-report";

const router: IRouter = Router();

router.use(healthRouter);
router.use(telemetryRouter);
router.use(pypiStatsRouter);
router.use(demoScanRouter);
router.use(contactRouter);
router.use(emailReportRouter);

export default router;
