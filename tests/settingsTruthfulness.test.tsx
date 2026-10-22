import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {describe,expect,it} from 'vitest';
import {SettingsTab} from '../src/components/SettingsTab';
import {defaultSettings} from '../src/services/storage';
describe('R47 truthful settings and selected connection mode',()=>{
  it.each(['ru','en'] as const)('keeps UI state distinct from native health in %s',language=>{
    const noop=()=>{};
    const html=renderToStaticMarkup(<SettingsTab settings={{...defaultSettings,tunnelMode:'proxy'}} language={language} onToggleSetting={noop} onTunnelModeChange={noop} onIpStackChange={noop} onTunRoutingModeChange={noop} onLanguageChange={noop} onRoutingExclusionsChange={noop}/>);
    expect(html).not.toContain(language==='ru'?'Все системы работают':'All systems operational');
    expect(html).toContain('aria-pressed="true">Proxy</button>');
    expect(html).toContain('aria-pressed="false">TUN</button>');
    expect(html).toContain(language==='ru'?'Настройки клиента':'Client settings');
  });
});
