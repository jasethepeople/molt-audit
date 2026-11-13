// Minimal stub for the verify harness: retry helper with the interface the
// pack's router.ts uses. `attempts` is the total number of tries. On success
// returns { value, attempts: triesUsed }. On final failure rethrows the error
// with an `attempts` property attached (Router.execute reads it).

export interface RetryOptions {
  attempts?: number;
  backoffMs?: number;
}

export async function withRetry<T>(
  fn: () => Promise<T>,
  opts: RetryOptions = {},
): Promise<{ value: T; attempts: number }> {
  const maxAttempts = opts.attempts ?? 3;
  const backoffMs = opts.backoffMs ?? 250;
  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const value = await fn();
      return { value, attempts: attempt };
    } catch (error) {
      lastError = error;
      if (attempt < maxAttempts && backoffMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, backoffMs));
      }
    }
  }
  const err = lastError instanceof Error ? lastError : new Error(String(lastError));
  (err as Error & { attempts?: number }).attempts = maxAttempts;
  throw err;
}
