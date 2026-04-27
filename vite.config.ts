import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const nodeProcess = (globalThis as unknown as { process?: { env?: Record<string, string | undefined> } }).process;
const allowLanDevServer = nodeProcess?.env?.VKARMANI_DEV_SERVER_LAN === 'true';

export default defineConfig({
  plugins: [react()],
  server: {
    host: allowLanDevServer ? '0.0.0.0' : '127.0.0.1',
    port: 5173,
    strictPort: true
  },
  preview: {
    host: '127.0.0.1',
    strictPort: true
  },
  build: {
    // Keeps local Windows/dev builds deterministic and avoids rare esbuild minifier stalls.
    minify: false
  }
});
