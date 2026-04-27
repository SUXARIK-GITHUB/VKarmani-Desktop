export function formatTrafficBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) {
    return '0 Б';
  }

  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let current = value;
  let unit = 0;
  while (current >= 1024 && unit < units.length - 1) {
    current /= 1024;
    unit += 1;
  }

  return `${current >= 10 || unit === 0 ? current.toFixed(0) : current.toFixed(2)} ${units[unit]}`;
}

export function buildTrafficBars(receivedBytes: number, sentBytes: number, sessionDuration: number) {
  const seed = Math.max(1, receivedBytes + sentBytes + sessionDuration * 8192);
  return Array.from({ length: 10 }, (_, index) => {
    const wave = Math.sin((sessionDuration + index * 5) / 9) * 22;
    const drift = ((seed / Math.max(1, index + 3)) % 31);
    return Math.max(12, Math.min(86, Math.round(24 + wave + drift)));
  });
}
