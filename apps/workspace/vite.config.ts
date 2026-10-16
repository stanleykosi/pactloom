import { defineConfig } from 'vite';
import { fileURLToPath, URL } from 'node:url';
export default defineConfig({
  resolve: { alias: { '@wholepact/sdk': fileURLToPath(new URL('../../packages/sdk/src/index.ts', import.meta.url)) } },
  server: { host: '127.0.0.1', port: 4319, strictPort: true, allowedHosts: ['localhost', '127.0.0.1'] },
  preview: { host: '127.0.0.1', port: 4319, strictPort: true },
});
