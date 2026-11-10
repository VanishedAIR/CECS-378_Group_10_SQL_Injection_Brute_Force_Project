import type { SqlIndicator } from "./audit.js";
/** Return every supported signature found in the input. This is demo detection, not a complete SQL firewall. */
export function detectSqlInjection(input: string): SqlIndicator[] {
    const matches: SqlIndicator[] = [];
    // Detect SQL comment markers
    if (/--|\/\*|\*\//.test(input)) {
        matches.push("sql_comment");
    }
    // Detect UNION SELECT, including extra whitespace
    if (/\bUNION\s+SELECT\b/i.test(input)) {
        matches.push("union_select");
    }
    // Detect common boolean injection patterns
    if (/\bOR\s+1\s*=\s*1\b/i.test(input)) {
        matches.push("boolean_tautology");
    }
    return matches;
}
