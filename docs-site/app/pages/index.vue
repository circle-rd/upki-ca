<script setup lang="ts">

// Hardcode path to '/' so it is never affected by NUXT_APP_BASE_URL at runtime.
const { data: page } = await useAsyncData('landing', () =>
  queryCollection('landing').path('/').first(),
)

if (!page.value) {
  throw createError({ statusCode: 404, statusMessage: 'Page not found', fatal: true })
}

useSeoMeta({
  title: page.value.seo?.title ?? page.value.title,
  description: page.value.seo?.description ?? page.value.description,
  ogTitle: page.value.seo?.title ?? page.value.title,
  ogDescription: page.value.seo?.description ?? page.value.description,
})
</script>

<template>
  <ContentRenderer
    v-if="page"
    :value="page"
  />
</template>
