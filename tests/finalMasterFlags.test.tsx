import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { getServerCountryCode, getServerPrimaryLabel, inferCountryCode, resolveServerFlag } from '../src/utils/serverDisplay';
import { ServerFlag } from '../src/components/ServerFlag';

describe('final master R01/R02 explicit country identity', () => {
  it.each(['BY', 'by', 'Belarus', 'Беларусь', 'Белоруссия'])('recognizes Belarus metadata %s', country => {
    expect(inferCountryCode({ country })).toBe('BY');
    expect(resolveServerFlag({ country })).toBe('🇧🇾');
  });
  it('prioritizes explicit country metadata over conflicting stale flag/label/host', () => {
    const server = { country: 'BY', countryCode: 'by', rawLabel: '🇳🇱 Netherlands', flag: '🇷🇺', host: 'node.de' };
    expect(getServerCountryCode(server)).toBe('BY');
    expect(resolveServerFlag(server)).toBe('🇧🇾');
    expect(inferCountryCode({ country: 'Belarus', rawLabel: '🇳🇱 Netherlands', host: 'node.de' })).toBe('BY');
    expect(getServerPrimaryLabel(server)).toBe('Belarus');
    const markup = renderToStaticMarkup(<ServerFlag server={server}/>);
    expect(markup).toContain('<svg'); expect(markup).toContain('#C8313E'); expect(markup).toContain('#4AA657'); expect(markup).toContain('#FFFFFF');
  });
  it('does not claim location from any two-letter host suffix', () => {
    for (let a = 65; a <= 90; a++) for (let b = 65; b <= 90; b++) {
      expect(inferCountryCode({ host: `node.${String.fromCharCode(a,b).toLowerCase()}` })).toBeUndefined();
    }
    expect(inferCountryCode({ host: '2001:db8::1' })).toBeUndefined();
  });
  it.each(['EU','NL','DE','RU','US','GB','FR','ES','IT','PL','CH','AT','SE','NO','FI','DK','CZ','SK','RO','BG','HU','TR','UA','LT','LV','EE','CA','BR','AR','JP','KR','SG','HK','IN','AE','IL','AU','NZ','CN','KZ','GE','MD','PT','BE'])('preserves existing explicit country and SVG %s', countryCode => {
    const server = { countryCode };
    expect(getServerCountryCode(server)).toBe(countryCode);
    const markup = renderToStaticMarkup(<ServerFlag server={server}/>);
    expect(markup).toContain('<svg'); expect(markup).toContain(`aria-label="Флаг ${countryCode}"`); expect(markup).toContain(`<title>${countryCode}</title>`);
    if (countryCode === 'EU') expect(markup.match(/#FFCC00/g)).toHaveLength(12);
  });
  it('escapes unknown labels and keeps unknown regions neutral', () => {
    expect(renderToStaticMarkup(<ServerFlag server={{ country: '<img onerror=alert(1)>', host: 'node.by' }}/>)).not.toContain('<img');
    expect(getServerCountryCode({ host: 'node.by', country: 'Unspecified' })).toBeUndefined();
  });
});
