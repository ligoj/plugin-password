<template>
  <div>
    <h1 class="text-h4 mb-6 d-flex align-center ga-2">
      <v-icon size="x-large">mdi-key-variant</v-icon>
      <span>{{ t('password.change.title') }}</span>
    </h1>

    <v-row>
      <v-col cols="12" md="6">
        <v-card>
          <v-card-text>
            <v-form ref="formRef" @submit.prevent="submit">
              <v-text-field v-model="form.password" type="password" autocomplete="current-password" :label="t('password.change.current')" :rules="REQUIRED_RULES" variant="outlined" class="mb-2" />
              <v-text-field v-model="form.newPassword" type="password" autocomplete="new-password" :label="t('password.change.new')" :rules="NEW_PASSWORD_RULES" :hint="t('password.change.helpPassword')"
                persistent-hint variant="outlined" class="mb-4" />
              <v-text-field v-model="form.confirm" type="password" autocomplete="new-password" :label="t('password.change.confirm')" :rules="CONFIRM_RULES" variant="outlined" class="mb-2" />
            </v-form>
          </v-card-text>
          <v-card-actions>
            <v-spacer />
            <v-btn variant="text" :to="'/profile'" :disabled="saving">{{ t('password.change.cancel') }}</v-btn>
            <v-btn color="primary" variant="elevated" prepend-icon="mdi-content-save" :loading="saving" @click="submit">
              {{ t('password.change.submit') }}
            </v-btn>
          </v-card-actions>
        </v-card>
      </v-col>
    </v-row>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAppStore, useErrorStore, useI18nStore } from '@ligoj/host'
import service from '../service.js'

const router = useRouter()
const app = useAppStore()
const errorStore = useErrorStore()
const { t } = useI18nStore()

const formRef = ref(null)
const saving = ref(false)
const form = reactive({ password: '', newPassword: '', confirm: '' })

// Hoist the rule arrays — Vuetify 4's v-form watches `rules` by
// reference, and a fresh `[required]` literal per render triggers
// "Maximum recursive updates" inside an expand transition. The host's
// REWRITE_VUEJS.md notes the same trap on every other form.
const REQUIRED_RULES = [(v) => !!v || t('common.required')]
const NEW_PASSWORD_RULES = [
  (v) => !!v || t('common.required'),
  // Same complexity policy as LoginApp.vue's reset flow.
  (v) => (/[A-Z]/.test(v) && /[a-z]/.test(v) && /[0-9]/.test(v) && v.length >= 8) || t('password.change.weak'),
]
const CONFIRM_RULES = [
  (v) => !!v || t('common.required'),
  (v) => v === form.newPassword || t('password.change.mismatch'),
]

async function submit() {
  const { valid } = await formRef.value.validate()
  if (!valid) return
  saving.value = true
  try {
    const result = await service.changePassword({
      password: form.password,
      newPassword: form.newPassword,
    })
    // `api.put` returns `false` on a validation rejection from the
    // backend (the wrapper surfaces the error toast for us).
    if (result === false) return
    errorStore.success(t('password.change.success'))
    router.push('/profile')
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  app.setBreadcrumbs([
    { title: t('nav.home'), to: '/' },
    { title: t('nav.profile'), to: '/profile' },
    { title: t('password.change.title') },
  ])
})
</script>
