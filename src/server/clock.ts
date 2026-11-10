/** Milliseconds since the Unix epoch. Tests inject a fake clock. */
export type Clock = {
    now: () => number;
};
/** Return the real UTC millisecond clock used by policy and reporting. */
export function systemClock(): Clock {
    return {
        now: () => Date.now(),
    };
}
export type FakeClock = Clock & {
    advance: (milliseconds: number) => void;
};
/** Return an independently advanceable millisecond clock for deterministic tests and demos. */
export function createFakeClock(startUtcMs: number): FakeClock {
    let current = startUtcMs;
    return {
        now: () => current,
        advance: (milliseconds: number) => {
            current += milliseconds;
        },
    };
}
