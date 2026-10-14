import { describe, expect, it } from "vitest";
import { detectSqlInjection } from "../src/server/sqlDetector.js";

describe("SQL injection detector", () => {
  it("does not flag normal product searches", () => {
    expect(detectSqlInjection("Mouse")).toEqual([]);
    expect(detectSqlInjection("Keyboard")).toEqual([]);
  });

  it("detects SQL comment markers", () => {
    expect(detectSqlInjection("Mouse --")).toContain("sql_comment");
    expect(detectSqlInjection("/* comment */")).toContain("sql_comment");
  });

  it("detects UNION SELECT", () => {
    expect(detectSqlInjection("UNION SELECT")).toContain("union_select");
    expect(detectSqlInjection("union   select")).toContain("union_select");
  });

  it("detects boolean tautologies", () => {
    expect(detectSqlInjection("' OR 1=1")).toContain("boolean_tautology");
    expect(detectSqlInjection("' or 1 = 1")).toContain("boolean_tautology");
  });

  it("detects multiple indicators in one input", () => {
    expect(detectSqlInjection("' OR 1=1 --")).toEqual([
      "sql_comment",
      "boolean_tautology",
    ]);
  });
});
