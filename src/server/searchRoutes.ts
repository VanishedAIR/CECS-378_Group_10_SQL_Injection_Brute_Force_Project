import { Router, type Request } from "express";
import type { AppDependencies } from "./app.js";
import { executeAuditedSearch } from "./search.js";
import { sendJsonError, sourceIpFromRequest } from "./http.js";

type AuthenticatedUser = {
  id: number;
};

// Van_ish's authentication middleware will provide this later.
// Until then, no request is treated as authenticated.
function getAuthenticatedUser(_req: Request): AuthenticatedUser | null {
  return null;
}

export function createSearchRouter(deps: AppDependencies): Router {
  const router = Router();

  function handleSearch(mode: "protected" | "vulnerable") {
    return (req: Request, res: import("express").Response) => {
      const user = getAuthenticatedUser(req);

      if (!user) {
        sendJsonError(res, 401, "AUTH_REQUIRED", "Login required.");
        return;
      }

      if (mode === "vulnerable" && !deps.config.labMode) {
        sendJsonError(res, 404, "NOT_FOUND", "Not found.");
        return;
      }

      const q = req.query.q;

      if (typeof q !== "string" || q.length > 200) {
        sendJsonError(res, 400, "INVALID_REQUEST", "Invalid search input.");
        return;
      }

      try {
        const rows = executeAuditedSearch(deps.db, mode, q, {
          userId: user.id,
          sourceIp: sourceIpFromRequest(req),
          requestId: req.requestId,
          clock: deps.clock,
        });

        res.json({ rows, resultCount: rows.length });
      } catch {
        sendJsonError(res, 500, "INTERNAL_ERROR", "Search failed.");
      }
    };
  }

  router.get("/api/search/protected", handleSearch("protected"));
  router.get("/api/search/vulnerable", handleSearch("vulnerable"));

  return router;
}
