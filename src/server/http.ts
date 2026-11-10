import crypto from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { normalizeSourceIp } from "./normalize.js";
export const API_ERROR_CODES = [
    "INVALID_REQUEST",
    "INVALID_CREDENTIALS",
    "AUTH_REQUIRED",
    "FORBIDDEN",
    "NOT_FOUND",
    "LOGIN_COOLDOWN",
    "INTERNAL_ERROR",
] as const;
export type ApiErrorCode = (typeof API_ERROR_CODES)[number];
export type ErrorEnvelope = {
    error: {
        code: ApiErrorCode;
        message: string;
    };
};
declare module "express-serve-static-core" {
    interface Request {
        requestId: string;
    }
}
/** Create an independent ID for correlating a request with its audit evidence. */
export function createRequestId(): string {
    return crypto.randomUUID();
}
/** Build the shared nested error shape without internal details. */
export function errorEnvelope(code: ApiErrorCode, message: string): ErrorEnvelope {
    return { error: { code, message } };
}
/** Send the agreed status and JSON error body. */
export function sendJsonError(res: Response, status: number, code: ApiErrorCode, message: string): void {
    res.status(status).json(errorEnvelope(code, message));
}
/** Read the socket address, ignoring forwarded headers, and normalize it for audit grouping. */
export function sourceIpFromRequest(req: Request): string {
    const remote = req.socket?.remoteAddress ?? "";
    return normalizeSourceIp(remote);
}
/** Assign a request ID and return it in X-Request-Id before route handlers run. */
export function attachRequestContext(req: Request, res: Response, next: NextFunction): void {
    const requestId = createRequestId();
    req.requestId = requestId;
    res.setHeader("X-Request-Id", requestId);
    next();
}
/** Handle malformed bodies and unexpected errors without sending SQL or stack traces to clients. */
export function handleUnexpectedError(err: unknown, _req: Request, res: Response, next: NextFunction): void {
    if (res.headersSent) {
        next(err);
        return;
    }
    const status = typeof err === "object" &&
        err !== null &&
        "status" in err &&
        typeof (err as {
            status: unknown;
        }).status === "number"
        ? (err as {
            status: number;
        }).status
        : 500;
    if (status === 400 || status === 413) {
        sendJsonError(res, status, "INVALID_REQUEST", "The request could not be read.");
        return;
    }
    console.error(err);
    sendJsonError(res, 500, "INTERNAL_ERROR", "An unexpected error occurred.");
}
