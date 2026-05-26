# plugin-password UI

Vue sources for the Ligoj "password" feature-level plugin. Provides the
logged-in password-change flow against `PUT /rest/service/password`.
Pre-session recovery / reset (the "Forgot password" + token-reset flows)
live in the host's `LoginApp.vue` — they run before the plugin loader
boots, so they call the REST endpoints directly.

Built with Vite in library mode; the output bundle lands under the
Java module's webjars classpath so the host serves it at
`/main/password/vue/index.js`.

## Layout

```
ui/
├── package.json
├── vite.config.js            # library build → ../src/main/resources/.../webjars/password/vue/
├── index.html                # standalone dev entry
└── src/
    ├── index.js              # plugin contract entry (default export)
    ├── service.js            # changePassword wrapper around /rest/service/password
    ├── i18n/{en,fr}.js       # password-change form labels
    └── views/
        └── PasswordChangeView.vue
```

## Commands

```sh
npm install
npm run dev        # standalone dev server on :5176; proxies REST to :8080
npm run build      # writes ../src/main/resources/META-INF/resources/webjars/password/vue/index.js
```

## Routes

- `/password/change` — current-user password change form. The host's
  Profile view links here when the plugin is registered.
