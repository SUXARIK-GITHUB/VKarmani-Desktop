import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ log: vi.fn(), handoff: vi.fn() }));
vi.mock('../src/services/runtime', () => ({ writeNativeInterfaceLog: mocks.log }));
vi.mock('../src/services/stateHandoff', () => ({ listenForStateHandoff: mocks.handoff }));
import { createFrontendCrashReceipt, listenForFrontendCrashes, recordFrontendCrash } from '../src/services/crashReceipts';
import { RootErrorBoundary } from '../src/components/RootErrorBoundary';
import packageJson from '../package.json';

beforeEach(() => { mocks.log.mockReset().mockResolvedValue(undefined); mocks.handoff.mockReset().mockResolvedValue(vi.fn()); });
afterEach(() => vi.unstubAllGlobals());

describe('R17/R46 bounded allowlisted frontend crash evidence', () => {
  it('retains version/code/phase/time and numeric stack locations without exception text or secrets', () => {
    const failure = new Error('password=short-secret https://sensitive.test/private?key=abc');
    failure.stack = 'Error: plaintext\n at privateUser (https://private.test/sensitive.js:20:31)\nComponent@http://localhost:1234/App.tsx?t=123:5:9';
    const receipt = createFrontendCrashReceipt('UI_RENDER_FAILED', failure);
    expect(receipt).toMatchObject({ appVersion: packageJson.version, code: 'UI_RENDER_FAILED', phase: 'render', stack: [{ line: 20, column: 31 }, { line: 5, column: 9 }] });
    expect(Number.isFinite(Date.parse(receipt.timestamp))).toBe(true);
    const text = JSON.stringify(receipt); for (const secret of ['short-secret', 'sensitive', 'private', 'plaintext', 'App.tsx', 'localhost']) expect(text).not.toContain(secret);
  });
  it('bounds adversarial stacks and ignores hostile/non-Error rejections', () => {
    const error = new Error('omitted'); error.stack = 'Error\n' + ' at f (http://secret.test/asset.js:12:34)\n'.repeat(10000);
    const receipt = createFrontendCrashReceipt('UI_UNHANDLED_REJECTION', error);
    expect(receipt.stack).toHaveLength(16); expect(JSON.stringify(receipt).length).toBeLessThan(1500); expect(receipt.phase).toBe('async');
    Object.defineProperty(error, 'stack', { get() { throw Error('bad getter'); } });
    expect(createFrontendCrashReceipt('UI_UNCAUGHT_ERROR', error).stack).toEqual([]);
    const arbitrary = { password: 'abc', toString: () => { throw Error(); } };
    expect(createFrontendCrashReceipt('UI_UNHANDLED_REJECTION', arbitrary).stack).toEqual([]);
  });
  it('removes global listeners and bounds repeated diagnostic writes even if native logging rejects', async () => {
    const target = new EventTarget(); const stop = listenForFrontendCrashes(target as Window);
    mocks.log.mockRejectedValue(Error('disk full'));
    for (let i=0;i<200;i++) { const event = new Event('error'); Object.assign(event, { error: new Error('secret') }); target.dispatchEvent(event); }
    await vi.waitFor(() => expect(mocks.log).toHaveBeenCalledTimes(16));
    stop(); target.dispatchEvent(new Event('unhandledrejection')); expect(mocks.log).toHaveBeenCalledTimes(16);
    recordFrontendCrash(createFrontendCrashReceipt('UI_RENDER_FAILED', null)); expect(mocks.log).toHaveBeenCalledTimes(16);
    await Promise.resolve();
  });
  it.each(['ru', 'en'])('renders an accessible persistent fallback and escaped diagnostics in %s', language => {
    vi.stubGlobal('document', { documentElement: { lang: language } });
    const boundary = new RootErrorBoundary({ children: <p>original</p> });
    expect(renderToStaticMarkup(boundary.render())).toContain('original');
    boundary.state = { ...boundary.state, ...RootErrorBoundary.getDerivedStateFromError(new Error('<img onerror=alert(1)>')) };
    const html = renderToStaticMarkup(boundary.render());
    expect(html).toContain('role="alert"'); expect(html).toContain('UI_RENDER_FAILED'); expect(html).toContain('<time'); expect(html).not.toContain('<img');
    expect(html).toContain(language === 'en' ? 'Copy error details' : 'Скопировать сведения об ошибке');
    expect(html).not.toContain('original');
  });
  it('retains the existing save/ACK shutdown listener after App unmount without initiating exit', async () => {
    const stop = vi.fn(); mocks.handoff.mockResolvedValue(stop);
    const boundary = new RootErrorBoundary({ children: null });
    boundary.componentDidCatch(); await vi.waitFor(() => expect(mocks.handoff).toHaveBeenCalledOnce()); await Promise.resolve();
    expect(mocks.handoff).toHaveBeenCalledOnce(); expect(stop).not.toHaveBeenCalled();
    const callbacks = mocks.handoff.mock.calls[0][0]; expect(callbacks.quiesce()).toBeUndefined(); expect(callbacks.resume()).toBeUndefined();
    boundary.componentWillUnmount(); expect(stop).toHaveBeenCalledOnce();
  });
  it('disposes a listener which resolves after the fallback has unmounted', async () => {
    let resolve!: (stop: () => void) => void; const stop = vi.fn(); mocks.handoff.mockReturnValue(new Promise(r => { resolve = r; }));
    const boundary = new RootErrorBoundary({ children: null }); boundary.componentDidCatch(); await vi.waitFor(() => expect(mocks.handoff).toHaveBeenCalledOnce()); boundary.componentWillUnmount();
    resolve(stop); await vi.waitFor(() => expect(stop).toHaveBeenCalledOnce());
  });
});
