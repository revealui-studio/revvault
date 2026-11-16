import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    // Desktop DOM tests run in one worker to bound process and memory use.
    maxWorkers: 1,
    minWorkers: 1,
  },
});
