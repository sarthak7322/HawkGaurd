export interface TimerHost {
  setTimeout(callback: () => void, delay: number): number;
  clearTimeout(handle: number): void;
}

export function createBoundedDebouncedScan(
  onScan: () => void,
  timers: TimerHost,
  debounceMs = 900,
  maxWaitMs = 5000,
): { schedule: () => void; cancel: () => void } {
  let debounceTimer: number | undefined;
  let maxWaitTimer: number | undefined;

  const cancel = () => {
    if (debounceTimer !== undefined) timers.clearTimeout(debounceTimer);
    if (maxWaitTimer !== undefined) timers.clearTimeout(maxWaitTimer);
    debounceTimer = undefined;
    maxWaitTimer = undefined;
  };
  const fire = () => {
    cancel();
    onScan();
  };

  return {
    schedule() {
      if (debounceTimer !== undefined) timers.clearTimeout(debounceTimer);
      debounceTimer = timers.setTimeout(fire, debounceMs);
      if (maxWaitTimer === undefined) maxWaitTimer = timers.setTimeout(fire, maxWaitMs);
    },
    cancel,
  };
}

export function createSerialScanRunner(
  scan: () => Promise<void>,
): { run: () => void; cancelPending: () => void } {
  let running = false;
  let pending = false;

  const run = () => {
    if (running) {
      pending = true;
      return;
    }
    running = true;
    void scan().finally(() => {
      running = false;
      if (pending) {
        pending = false;
        run();
      }
    });
  };

  return {
    run,
    cancelPending() {
      pending = false;
    },
  };
}

export function createTrackedTimer(
  callback: () => void,
  timers: TimerHost,
  delay: number,
): { schedule: () => void; cancel: () => void } {
  let timer: number | undefined;
  return {
    schedule() {
      if (timer !== undefined) return;
      timer = timers.setTimeout(() => {
        timer = undefined;
        callback();
      }, delay);
    },
    cancel() {
      if (timer !== undefined) timers.clearTimeout(timer);
      timer = undefined;
    },
  };
}
