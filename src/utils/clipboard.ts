export async function copyInformation(payload: string, clipboard?: Pick<Clipboard, 'writeText'>): Promise<boolean> {
  try {
    if (!clipboard || typeof clipboard.writeText !== 'function') return false;
    await clipboard.writeText(payload);
    return true;
  } catch { return false; }
}
