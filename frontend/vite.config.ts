import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    cssCodeSplit: false,
    // The native app only embeds report-app.css/js, so small bundled fonts must be inlined into CSS.
    assetsInlineLimit: 1_000_000,
    rollupOptions: {
      output: {
        entryFileNames: 'assets/report-app.js',
        chunkFileNames: 'assets/report-app.js',
        assetFileNames: (assetInfo) => {
          if (assetInfo.name?.endsWith('.css')) {
            return 'assets/report-app.css';
          }

          return 'assets/[name][extname]';
        }
      }
    }
  }
});
