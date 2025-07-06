import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/**/*.[jt]s", "!./src/**/*.d.ts"],
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  splitting: false,
  sourcemap: true,
  minify: false,
  shims: true,
  treeshake: true,
});
