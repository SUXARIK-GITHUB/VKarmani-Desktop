export function maybeDecodeBase64(value: string) {
  const compact = value.replace(/\s+/g, '');
  if (!compact || compact.includes('://')) {
    return value;
  }

  let normalized = compact.replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)) {
    return value;
  }

  while (normalized.length % 4 !== 0) {
    normalized += '=';
  }

  try {
    const decoded = atob(normalized);
    return decoded.includes('://') || decoded.includes('\n') ? decoded : value;
  } catch {
    return value;
  }
}

export function parsePort(value: string | number | null | undefined, fallback: number) {
  const parsed = Number(value ?? '');
  return Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535 ? parsed : fallback;
}

export function splitHostPort(value: string): { address: string; portRaw: string | null } {
  const hostPart = value.trim();

  if (hostPart.startsWith('[')) {
    const closeIndex = hostPart.indexOf(']');
    if (closeIndex > 0) {
      const address = hostPart.slice(1, closeIndex);
      const rest = hostPart.slice(closeIndex + 1);
      return { address, portRaw: rest.startsWith(':') ? rest.slice(1) : null };
    }
  }

  const firstColon = hostPart.indexOf(':');
  const lastColon = hostPart.lastIndexOf(':');
  if (firstColon !== -1 && firstColon === lastColon) {
    return {
      address: hostPart.slice(0, lastColon),
      portRaw: hostPart.slice(lastColon + 1)
    };
  }

  return { address: hostPart, portRaw: null };
}
