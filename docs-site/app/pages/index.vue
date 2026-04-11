<script setup lang="ts">

// The landing collection always contains exactly one document (content/index.md).
// Using .first() avoids any stored-path edge cases ('/index', '', etc.) that
// could cause .path('/').first() to return null and throw a 404.
const { data: page } = await useAsyncData('landing', () =>
  queryCollection('landing').first(),
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
