import { defineConfig } from "vitest/config";

// The command's tests run dist/cli.js, so it is built once before any test file starts: two files building
// it at the same time could each run the other's half-written output.
export default defineConfig({ test: { globalSetup: ["./test/build.ts"] } });
