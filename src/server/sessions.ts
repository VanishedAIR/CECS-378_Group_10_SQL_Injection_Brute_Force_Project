
import "express-session";

export type AuthUser = {
  userId: number;
  usernameKey: string;
  role: "user" | "admin";
};

export type PublicUser = {
  id: number;
  usernameKey: string;
  displayUsername: string;
  role: "user" | "admin";
};

export const SESSION_COOKIE_NAME = "lab_session";
export const SESSION_DURATION_MS = 30 * 60 * 1000;

declare module "express-session" {
  interface SessionData {
    userId?: number;
  }
}
