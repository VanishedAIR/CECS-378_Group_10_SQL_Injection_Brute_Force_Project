/** Milliseconds since the Unix epoch. Tests inject a fake clock. */
export type Clock = {
  now: () => number;
};

export function systemClock(): Clock {
  return {
    now: () => Date.now(),
  };
}

export type FakeClock = Clock & {
  advance: (milliseconds: number) => void;
};

export function createFakeClock(startUtcMs: number): FakeClock {
  let current = startUtcMs;
  return {
    now: () => current,
    advance: (milliseconds: number) => {
      current += milliseconds;
    },
  };
}
