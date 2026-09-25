import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { crx } from '@crxjs/vite-plugin';
import manifest from './manifest.json' assert { type: 'json' };

export default defineConfig({
  plugins: [react(), crx({ manifest })],
  server: {
    port: 5173,
    strictPort: true,
    hmr: {
      port: 5173,
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        report: 'src/report/index.html',
        demo: 'src/demo/index.html',
        map: 'src/map/index.html',
        offscreen: 'src/offscreen/index.html',
      },
    },
  },
});
