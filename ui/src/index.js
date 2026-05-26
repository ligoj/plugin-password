/*
 * Plugin "password" — credential management (feature:password).
 *
 * Feature-level plugin: no subscription model, no tool nodes. Lives in
 * the host's plugin registry purely to expose the logged-in
 * password-change flow and prevent the runtime 404 the loader was
 * hitting before this scaffold landed.
 *
 * Pre-session flows (`recovery`, `reset`) live entirely in the host's
 * `LoginApp.vue` — they run before the plugin loader boots, so they
 * call `POST /rest/service/password/(recovery|reset)/*` directly.
 *
 * Authored as source — compiled to `/main/password/vue/index.js` by
 * Vite. Shared host surface (stores, components) is imported from
 * `@ligoj/host` and kept external at build so plugin and host share
 * the same instances.
 */
import { useI18nStore } from '@ligoj/host'
import enMessages from './i18n/en.js'
import frMessages from './i18n/fr.js'
import service from './service.js'
import PasswordChangeView from './views/PasswordChangeView.vue'

const features = {
  changePassword: service.changePassword,
}

const routes = [
  // Linked from the host's Profile view (when the plugin is registered).
  // The path lives under `/password/*` so a future "force change on
  // first login" flow can sit alongside without colliding with the
  // unauthenticated reset paths the host's LoginApp handles directly.
  { path: '/password/change', name: 'password-change', component: PasswordChangeView },
]

export default {
  id: 'password',
  label: 'Password',
  routes,
  install({ router }) {
    const i18n = useI18nStore()
    i18n.merge(enMessages, 'en')
    i18n.merge(frMessages, 'fr')
    for (const route of routes) router.addRoute(route)
  },
  feature(action, ...args) {
    const fn = features[action]
    if (!fn) throw new Error(`Plugin "password" has no feature "${action}"`)
    return fn(...args)
  },
  service,
  meta: { icon: 'mdi-key-variant', color: 'amber-darken-3' },
}

export { service }
