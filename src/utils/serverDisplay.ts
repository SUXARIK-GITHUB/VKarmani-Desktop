const FLAG_RE = /[\u{1F1E6}-\u{1F1FF}]{2}/u;

const COUNTRY_NAME_TO_CODE: Record<string, string> = {
  nl: 'NL',
  netherland: 'NL',
  netherlands: 'NL',
  nederland: 'NL',
  holland: 'NL',
  de: 'DE',
  germany: 'DE',
  deutschland: 'DE',
  germania: 'DE',
  ru: 'RU',
  russia: 'RU',
  'russian federation': 'RU',
  россия: 'RU',
  us: 'US',
  usa: 'US',
  'united states': 'US',
  'united states of america': 'US',
  america: 'US',
  uk: 'GB',
  gb: 'GB',
  'great britain': 'GB',
  britain: 'GB',
  england: 'GB',
  'united kingdom': 'GB',
  fr: 'FR',
  france: 'FR',
  es: 'ES',
  spain: 'ES',
  it: 'IT',
  italy: 'IT',
  pl: 'PL',
  poland: 'PL',
  ch: 'CH',
  switzerland: 'CH',
  at: 'AT',
  austria: 'AT',
  se: 'SE',
  sweden: 'SE',
  no: 'NO',
  norway: 'NO',
  fi: 'FI',
  finland: 'FI',
  dk: 'DK',
  denmark: 'DK',
  cz: 'CZ',
  'czech republic': 'CZ',
  czechia: 'CZ',
  sk: 'SK',
  slovakia: 'SK',
  ro: 'RO',
  romania: 'RO',
  bg: 'BG',
  bulgaria: 'BG',
  hu: 'HU',
  hungary: 'HU',
  tr: 'TR',
  turkey: 'TR',
  ua: 'UA',
  ukraine: 'UA',
  lt: 'LT',
  lithuania: 'LT',
  lv: 'LV',
  latvia: 'LV',
  ee: 'EE',
  estonia: 'EE',
  ca: 'CA',
  canada: 'CA',
  br: 'BR',
  brazil: 'BR',
  ar: 'AR',
  argentina: 'AR',
  jp: 'JP',
  japan: 'JP',
  kr: 'KR',
  korea: 'KR',
  'south korea': 'KR',
  singapore: 'SG',
  sg: 'SG',
  hk: 'HK',
  'hong kong': 'HK',
  in: 'IN',
  india: 'IN',
  ae: 'AE',
  uae: 'AE',
  'united arab emirates': 'AE',
  il: 'IL',
  israel: 'IL',
  au: 'AU',
  australia: 'AU',
  nz: 'NZ',
  'new zealand': 'NZ',
  cn: 'CN',
  china: 'CN',
  kz: 'KZ',
  kazakhstan: 'KZ',
  ge: 'GE',
  georgia: 'GE',
  md: 'MD',
  moldova: 'MD',
  pt: 'PT',
  portugal: 'PT',
  be: 'BE',
  belgium: 'BE'
};

function normalizeCountryKey(value: string) {
  return value
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(FLAG_RE, ' ')
    .toLowerCase()
    .replace(/^[^a-zа-яё0-9]+/giu, '')
    .replace(/[^a-zа-яё0-9]+/giu, ' ')
    .trim();
}

function flagEmojiToCountryCode(flag: string) {
  const symbols = Array.from(flag);
  if (symbols.length !== 2) {
    return undefined;
  }

  const letters = symbols.map((symbol) => {
    const codePoint = symbol.codePointAt(0);
    if (!codePoint || codePoint < 0x1F1E6 || codePoint > 0x1F1FF) {
      return '';
    }
    return String.fromCharCode(codePoint - 0x1F1E6 + 65);
  }).join('');

  return /^[A-Z]{2}$/.test(letters) ? letters : undefined;
}

export function flagEmojiFromCountryCode(code?: string | null) {
  if (!code || !/^[A-Z]{2}$/.test(code)) {
    return '🌐';
  }

  return String.fromCodePoint(...code.split('').map((char) => 127397 + char.charCodeAt(0)));
}

export function looksLikeHost(value?: string | null) {
  if (!value) {
    return false;
  }

  const normalized = value.trim();
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(normalized)
    || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(normalized)
    || normalized.includes(':');
}

export function inferCountryCode({
  country,
  rawLabel,
  host,
  explicitCode
}: {
  country?: string | null;
  rawLabel?: string | null;
  host?: string | null;
  explicitCode?: string | null;
}) {
  const normalizedExplicit = explicitCode?.trim().toUpperCase();
  if (normalizedExplicit && /^[A-Z]{2}$/.test(normalizedExplicit)) {
    return normalizedExplicit;
  }

  const labelFlag = rawLabel?.match(FLAG_RE)?.[0];
  const flagCode = labelFlag ? flagEmojiToCountryCode(labelFlag) : undefined;
  if (flagCode) {
    return flagCode;
  }

  const labelCode = rawLabel?.trim().match(/^[^A-Z]*([A-Z]{2})\b/);
  if (labelCode?.[1]) {
    return labelCode[1];
  }

  const candidates = [country, rawLabel];
  for (const candidate of candidates) {
    const normalized = normalizeCountryKey(candidate ?? '');
    if (!normalized) {
      continue;
    }

    const direct = COUNTRY_NAME_TO_CODE[normalized];
    if (direct) {
      return direct;
    }

    const firstWord = normalized.split(' ')[0];
    const byFirstWord = COUNTRY_NAME_TO_CODE[firstWord];
    if (byFirstWord) {
      return byFirstWord;
    }
  }

  const tld = host?.trim().split('.').pop()?.toUpperCase();
  if (tld && /^[A-Z]{2}$/.test(tld)) {
    return tld;
  }

  return undefined;
}

export function resolveServerFlag({
  flag,
  country,
  rawLabel,
  host,
  explicitCode
}: {
  flag?: string | null;
  country?: string | null;
  rawLabel?: string | null;
  host?: string | null;
  explicitCode?: string | null;
}) {
  const normalizedFlag = flag?.trim();
  if (normalizedFlag && normalizedFlag !== '🌐') {
    return normalizedFlag;
  }

  const countryCode = inferCountryCode({ country, rawLabel, host, explicitCode });
  return flagEmojiFromCountryCode(countryCode);
}

export function getServerPrimaryLabel(server: {
  flag?: string | null;
  country?: string | null;
  rawLabel?: string | null;
  host?: string | null;
}) {
  const resolvedFlag = resolveServerFlag(server);
  const country = server.country?.trim() || 'VKarmani';
  return `${resolvedFlag} ${country}`.trim();
}

export function getServerSecondaryLabel(
  server: {
    country?: string | null;
    city?: string | null;
    host?: string | null;
  },
  showDiagnostics = false
) {
  const city = server.city?.trim();
  const host = server.host?.trim();
  const country = server.country?.trim().toLowerCase();

  if (showDiagnostics) {
    return host || (city && !looksLikeHost(city) ? city : undefined);
  }

  if (!city || looksLikeHost(city) || city.toLowerCase() === country) {
    return undefined;
  }

  return city;
}

export function getServerDisplayLabel(
  server: {
    flag?: string | null;
    country?: string | null;
    city?: string | null;
    rawLabel?: string | null;
    host?: string | null;
  },
  showDiagnostics = false
) {
  const primary = getServerPrimaryLabel(server);
  const secondary = getServerSecondaryLabel(server, showDiagnostics);
  return secondary ? `${primary}, ${secondary}` : primary;
}
