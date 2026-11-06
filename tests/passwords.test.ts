
import { describe, expect, it } from "vitest";
import { hashPassword, verifyPassword } from "../src/server/passwords.js";

describe("Password hashing and verification", () => {
  it("hashes and verifies a correct password", () => {
    const hash = hashPassword("MySecurePassword123!");

    expect(hash).not.toContain("MySecurePassword123!");
    expect(verifyPassword("MySecurePassword123!", hash)).toBe(true);
  });

  it("rejects an incorrect password", () => {
    const hash = hashPassword("CorrectPassword123!");

    expect(verifyPassword("WrongPassword123!", hash)).toBe(false);
  });

  it("generates different hashes for the same password", () => {
    const first = hashPassword("SamePassword123!");
    const second = hashPassword("SamePassword123!");

    expect(first).not.toBe(second);
    expect(verifyPassword("SamePassword123!", first)).toBe(true);
    expect(verifyPassword("SamePassword123!", second)).toBe(true);
  });

  it("preserves password capitalization and spaces", () => {
    const hash = hashPassword(" MyPassword ");

    expect(verifyPassword(" MyPassword ", hash)).toBe(true);
    expect(verifyPassword("mypassword", hash)).toBe(false);
    expect(verifyPassword("MyPassword", hash)).toBe(false);
  });

  it("rejects malformed stored hashes", () => {
    expect(verifyPassword("password", "not-a-valid-hash")).toBe(false);
    expect(verifyPassword("password", "")).toBe(false);
  });

  it("rejects passwords outside the allowed length", () => {
    expect(() => hashPassword("")).toThrow();
    expect(() => hashPassword("a".repeat(129))).toThrow();
  });
});
