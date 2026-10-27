// Compiled only by the ignored local launcher. Native admission independently
// requires a debug binary and the isolated identifier; this is not an entitlement.
export function isLocalTestBuild(): boolean {
  return import.meta.env.VITE_VKARMANI_LOCAL_TEST === '1';
}
