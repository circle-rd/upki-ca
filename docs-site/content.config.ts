import { defineContentConfig, defineCollection } from "@nuxt/content";

// Only define the landing collection here.
// Docus's own content.config.ts (layer) handles the docs collection with its
// full schema (including the `links` field used by the raw markdown endpoint).
// We define landing ourselves because Docus skips it when app/pages/index.vue
// exists (landingPageExists() returns true), but we still need the collection
// so that our index.vue can query it.
export default defineContentConfig({
  collections: {
    landing: defineCollection({
      type: "page",
      source: "index.md",
    }),
  },
});
