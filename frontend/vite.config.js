import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // When the FastAPI backend is running, requests to /analyze are proxied to it.
    // Flip USE_MOCK_API to false in src/api.js to start using this.
    proxy: {
      '/analyze': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})
