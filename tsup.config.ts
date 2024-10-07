import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  splitting: true,
	dts: true,
  sourcemap: true,
  clean: true,
  format: ['esm', 'cjs'],
  target: 'es2022',
  outDir: 'lib',
  shims: true,
  cjsInterop: true,
  platform: 'node'
});