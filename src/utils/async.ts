export function sleep(ms: number) {
  return new Promise<void>((resolve) => window.setTimeout(resolve, ms));
}
