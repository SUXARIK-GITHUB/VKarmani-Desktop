const VPN_LINK_RE = /(?:vless|vmess|trojan|ss|hy2|hysteria2):\/\/[^\s"'<>`]+/gi;
const SUBSCRIPTION_URL_RE = /https:\/\/sub\.vkarmani\.com\/[^\s"'<>`)]+/gi;
const SECRET_QUERY_RE = /([?&](?:access[_-]?key|api[_-]?key|authorization|bearer|key|password|secret|sub|subscription|token)=)[^&\s"'<>`)]+/gi;
const UUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi;
const LONG_TOKEN_RE = /\b[A-Za-z0-9_-]{32,}\b/g;

export function redactSensitiveText(value: string) {
  return value
    .replace(VPN_LINK_RE, '[redacted-vpn-link]')
    .replace(SUBSCRIPTION_URL_RE, 'https://sub.vkarmani.com/[redacted-key]')
    .replace(SECRET_QUERY_RE, '$1[redacted-secret]')
    .replace(UUID_RE, '[redacted-uuid]')
    .replace(LONG_TOKEN_RE, (token) => `${token.slice(0, 6)}…${token.slice(-4)}`);
}

export function redactUnknown(value: unknown) {
  if (typeof value === 'string') {
    return redactSensitiveText(value);
  }

  if (value instanceof Error) {
    return redactSensitiveText(value.message);
  }

  try {
    return redactSensitiveText(JSON.stringify(value));
  } catch {
    return '';
  }
}
