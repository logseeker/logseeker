import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    watch: { usePolling: true }, // bind mount / VM 共有フォルダでの変更検知を確実にする
    // ブラウザは 5173 だけ見れればよい。/api などは Vite が backend(127.0.0.1:8000)へ中継。
    // → 8000 を外部公開する必要がなくなり、CORSも回避できる（開発時のみ。本番は npm run build + nginx）。
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: true },
      "/ingest": { target: "http://127.0.0.1:8000", changeOrigin: true },
      "/health": { target: "http://127.0.0.1:8000", changeOrigin: true },
    },
  },
});
