import { quiescePersistentWrites, resumePersistentWrites } from './storage';

let activeTicket: string | null = null;
let previousInert: boolean | null = null;
let controlsFrozen = false;
type Callbacks = { quiesce: () => void; resume: () => void; error: (failure: unknown) => void };
let currentCallbacks: Callbacks | null = null;
function freezeControls() {
  controlsFrozen = true;
  if (typeof document !== 'undefined' && previousInert === null) {
    previousInert = document.documentElement.inert;
    document.documentElement.inert = true;
  }
}
function thawControls() {
  if (typeof document !== 'undefined' && previousInert !== null) document.documentElement.inert = previousInert;
  previousInert = null;
  controlsFrozen = false;
}
export async function listenForStateHandoff(callbacks: Callbacks) {
  currentCallbacks = callbacks;
  const { listen } = await import('@tauri-apps/api/event');
  const stop = await listen<{ id: string; action: string }>('vkarmani://state-handoff', event => {
    const ticket = event.payload;
    if (!/^[0-9a-f]{48}$/.test(ticket?.id) || !['quit', 'restart', 'elevate'].includes(ticket.action) || activeTicket !== null) return;
    activeTicket = ticket.id;
    void (async () => {
      const { invoke } = await import('@tauri-apps/api/core');
      freezeControls();
      currentCallbacks?.quiesce();
      try {
        const stamp = await quiescePersistentWrites();
        // No JS deadline here: timeout cannot cancel native cleanup or release
        // its write seal. Native operations have their own bounded ownership.
        const exiting = await invoke<boolean>('acknowledge_state_handoff', { ticket: ticket.id, ...stamp });
        if (!exiting) { resumePersistentWrites(); thawControls(); currentCallbacks?.resume(); }
      } catch (failure) {
        try {
          await invoke('cancel_state_handoff', { ticket: ticket.id });
          resumePersistentWrites(); thawControls(); currentCallbacks?.resume();
        } catch { /* Native cleanup may still own the seal: never reopen it by a JS deadline. */ }
        currentCallbacks?.error(failure);
      } finally { activeTicket = null; }
    })();
  });
  return () => { stop(); if (currentCallbacks === callbacks) currentCallbacks = null; };
}

export async function sealUpdateState() {
  const { invoke } = await import('@tauri-apps/api/core');
  freezeControls();
  const ticket = [...crypto.getRandomValues(new Uint8Array(24))].map(byte => byte.toString(16).padStart(2, '0')).join('');
  try {
    const stamp = await quiescePersistentWrites();
    const confirmed = await invoke<string>('seal_state_for_update', { ticket, ...stamp });
    if (confirmed !== ticket) throw new Error('STATE_HANDOFF_INVALID');
    return ticket;
  } catch (failure) {
    try { await invoke('cancel_state_handoff', { ticket }); resumePersistentWrites(); thawControls(); }
    catch { /* An unknown native seal remains closed until cancellation is confirmed. */ }
    throw failure;
  }
}
export async function approveUpdateExit(ticket: string) {
  const { invoke } = await import('@tauri-apps/api/core');
  await invoke('approve_state_update_exit', { ticket });
}
export async function releaseUpdateState(ticket: string | null) {
  const { invoke } = await import('@tauri-apps/api/core');
  if (ticket) await invoke('cancel_state_handoff', { ticket });
  else if (controlsFrozen) throw new Error('STATE_HANDOFF_UNCONFIRMED');
  resumePersistentWrites(); thawControls();
}
