import { Router, type IRouter } from "express";
import healthRouter from "./health";
import telemetryRouter from "./telemetry";
import pypiStatsRouter from "./pypi-stats";
import demoScanRouter from "./demo-scan";

const router: IRouter = Router();

router.use(healthRouter);
router.use(telemetryRouter);
router.use(pypiStatsRouter);
router.use(demoScanRouter);

export default router;
