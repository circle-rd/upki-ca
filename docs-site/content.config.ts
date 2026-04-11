import { defineContentConfig, defineCollection } from '@nuxt/content'
import { resolve } from 'path'

/**
 * Local content configuration for uPKI-CA docs.
 *
 * We only declare the `landing` collection here (content/index.md).
 * The `docs` collection (content/docs/**) is handled by the Docus layer.
 *
 * After Docus PR #1274 (Feb 16 2026), the Docus layer no longer defines the
 * `landing` collection when app/pages/index.vue exists in the user project.
 * We must define it here with an explicit `cwd` so that @nuxt/content resolves
 * index.md from THIS project's content/ directory.
 *
 * We use `resolve(process.cwd(), 'content')` rather than useNuxt() because
 * this file is evaluated by c12/jiti in the same Node.js process as `nuxt build`,
 * making process.cwd() a guaranteed, zero-import way to get the project root.
 * Importing @nuxt/kit inside jiti can fail silently (c12 catches evaluation
 * errors and falls back to defaultConfig: { collections: {} }), which would
 * leave the landing collection empty and cause a 404 on the landing page.
 */
const contentDir = resolve(process.cwd(), 'content')

export default defineContentConfig({
  collections: {
    landing: defineCollection({
      type: 'page',
      source: {
        cwd: contentDir,
        include: 'index.md',
      },
    }),
  },
})
