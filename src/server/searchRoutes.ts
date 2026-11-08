import { Router, type Request, type Response } from "express";
import type { AppDependencies } from "./app.js";
import { requireSession } from "./authMiddleware.js";
import { executeAuditedSearch } from "./search.js";
import { sendJsonError, sourceIpFromRequest } from "./http.js";

export function createSearchRouter(deps: AppDependencies): Router {
  const router = Router();

  function handleSearch(mode: "protected" | "vulnerable") {
    return (req: Request, res: Response) => {
      // Only authenticated users can reach this handler.
      const user = req.auth;

      if (!user) {
        sendJsonError(
          res,
          401,
          "AUTH_REQUIRED",
          "Authentication is required."
        );
        return;
      }

      // Vulnerable searches are only available in lab mode.
      if (mode === "vulnerable" && !deps.config.labMode) {
        sendJsonError(res, 404, "NOT_FOUND", "Not found.");
        return;
      }

      const q = req.query.q;

      if (typeof q !== "string" || q.length < 1 || q.length > 100) {
        sendJsonError(res, 400, "INVALID_REQUEST", "Invalid search input.");
        return;
      }

      try {
        const rows = executeAuditedSearch(deps.db, mode, q, {
          userId: user.userId,
          sourceIp: sourceIpFromRequest(req),
          requestId: req.requestId,
          clock: deps.clock,
        });

        res.json({
          mode,
          rows,
          resultCount: rows.length,
        });
      } catch {
        sendJsonError(res, 500, "INTERNAL_ERROR", "Search failed.");
      }
    };
  }

  // Require a valid session before executing either search.
  router.get(
    "/api/search/protected",
    requireSession(deps.db),
    handleSearch("protected")
  );

  router.get(
    "/api/search/vulnerable",
    requireSession(deps.db),
    handleSearch("vulnerable")
  );

  return router;
}