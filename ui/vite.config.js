import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

// Library build for the "password" feature-level plugin.
//
// Loaded by the Ligoj Vue host via a dynamic import of
//   /main/password/vue/index.js
// — so the output lives under the Java module's webjars classpath, where
// Spring Boot's webjars servlet serves it at runtime.
//
// Shared deps (vue, pinia, vue-router, vuetify, @ligoj/host) are kept
// EXTERNAL: the plugin must use the host's module instances or reactivity
// and plugin registries break across SFC boundaries.

// Path to the Ligoj host repo, sitting beside `ligoj-plugins/` in the
// developer workspace. Used to resolve `@ligoj/host` for tests and the
// standalone dev server (the runtime import map handles the production
// case via the webjars-served bundle).
const HOST_SRC = resolve(__dirname, '../../../ligoj/app-ui/src/main/webapp/src')

export default defineConfig({
  plugins: [vue()],

  resolve: {
    alias: {
      '@ligoj/host': resolve(HOST_SRC, 'host.js'),
      '@': HOST_SRC,
    },
    // Force a single instance of every shared dep so `setActivePinia`
    // from the test reaches `useI18nStore` resolved through `@ligoj/host`.
    // Without this each side picks its own node_modules copy.
    dedupe: ['vue', 'pinia', 'vue-router', 'vuetify'],
  },

  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.js'),
      formats: ['es'],
      fileName: () => 'index.js',
    },
    outDir: resolve(
      __dirname,
      '../src/main/resources/META-INF/resources/webjars/password/vue',
    ),
    emptyOutDir: true,
    rollupOptions: {
      external: ['vue', 'vue-router', 'pinia', 'vuetify', '@ligoj/host'],
      output: {
        assetFileNames: 'index.[ext]',
      },
    },
  },

  // Standalone dev server — tests the plugin in isolation against a running
  // Ligoj backend on :8080. `npm run dev` then open http://localhost:5176/.
  server: {
    port: 5176,
    proxy: {
      '/rest': { target: 'http://localhost:8080', changeOrigin: true },
      '/webjars': { target: 'http://localhost:8080', changeOrigin: true },
    },
  },

  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['src/__tests__/setup.js'],
    exclude: ['node_modules/**', 'dist/**'],
    css: false,
    server: {
      deps: {
        inline: ['vuetify'],
      },
    },
  },
})
