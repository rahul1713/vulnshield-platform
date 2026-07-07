'use client';

/** Poll until a demo report PDF input exists (async scan/review completion). */
export async function waitForDemoReportInput(
  key: string,
  maxMs = 10000,
  intervalMs = 250
): Promise<boolean> {
  const { demoStore } = await import('@/lib/demo-store');
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    if (demoStore.getReportInput(key)) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return !!demoStore.getReportInput(key);
}

/** Poll until a demo scan reaches completed status with a report ready. */
export async function waitForDemoScanComplete(scanId: string, maxMs = 10000): Promise<boolean> {
  const { demoStore } = await import('@/lib/demo-store');
  const key = `scan:${scanId}`;
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    const scan = demoStore.getScans().find((s) => s.id === scanId);
    if (scan?.status === 'completed' && demoStore.getReportInput(key)) return true;
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

/** Poll until a demo entity status is completed with report input. */
export async function waitForDemoEntityComplete(
  entityKey: string,
  getStatus: () => string | undefined,
  maxMs = 10000
): Promise<boolean> {
  const { demoStore } = await import('@/lib/demo-store');
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    if (getStatus() === 'completed' && demoStore.getReportInput(entityKey)) return true;
    await new Promise((r) => setTimeout(r, 250));
  }
  return getStatus() === 'completed' && !!demoStore.getReportInput(entityKey);
}
