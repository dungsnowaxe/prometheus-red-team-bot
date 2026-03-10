import { defineConfig } from 'vite';

// https://vitejs.dev/config
export default defineConfig({
  server: {
    watch: {
      // Ignore .claude directory to prevent reloads during agent scans
      ignored: ['**/.claude/**', '**/node_modules/**'],
    },
  },
});
