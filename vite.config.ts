import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const apiTarget = process.env.VITE_API_PROXY_TARGET ?? "http://127.0.0.1:8790";
const wsTarget = process.env.VITE_WS_PROXY_TARGET ?? apiTarget.replace(/^http/i, "ws");

const silenceEpipe = (proxy: import("http-proxy").Server) => {
  proxy.on("error", (err: NodeJS.ErrnoException, _req, res) => {
    if (err.code === "EPIPE" || err.code === "ECONNRESET") return;
    if (res && "writeHead" in res && !(res as any).headersSent) {
      (res as any).writeHead(502);
      (res as any).end();
    }
  });
  proxy.on("proxyReqWs", (_proxyReq, _req, socket) => {
    socket.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EPIPE" || err.code === "ECONNRESET") return;
    });
  });
};

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    allowedHosts: [".ts.net"],
    watch: {
      ignored: ["**/.climpire-worktrees/**"],
    },
    proxy: {
      "/api": {
        target: apiTarget,
        configure: silenceEpipe,
      },
      "/ws": {
        target: wsTarget,
        ws: true,
        configure: silenceEpipe,
      },
    },
  },
  build: {
    outDir: "dist",
  },
});
