import { useApi } from '@ligoj/host'

/**
 * Thin service wrapper around the password plugin's REST endpoints.
 * Recovery/reset (pre-session) is handled directly by the host's
 * `LoginApp.vue` because it runs before the plugin loader boots. Here
 * we only expose the change-password endpoint that requires an
 * authenticated session.
 */
const service = {
  /**
   * Updates the current user's password via `PUT /rest/service/password`.
   * The backend re-authenticates the supplied `password` to confirm the
   * caller actually knows the current credential before applying
   * `newPassword`, so an invalid `password` field surfaces as a 400.
   *
   * @param {{ password: string, newPassword: string }} payload
   * @returns The api response (typically empty body on success).
   */
  async changePassword(payload) {
    const api = useApi()
    return api.put('rest/service/password', payload)
  },
}

export default service
