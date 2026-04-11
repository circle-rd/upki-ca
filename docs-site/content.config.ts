import { defineContentConfig, defineCollection } from '@nuxt/content'
import { useNuxt } from '@nuxt/kit'
import { joinURL } from 'ufo'

/**
 * Local content configuration for uPKI-CA docs.
 *
 * We only declare the `landing` collection here (content/index.md).
 * The `docs` collection (content/docs/**) is handled by the Docus layer.
 *
 * We use an explicit `cwd` (mirroring the Docus layer pattern) to ensure
 * @nuxt/content resolves `index.md` from THIS project's content/ directory
 * rather than leaving it ambiguous in the layer stack. Without it, since
 * Docus PR #1274 no longer defines the landing collection when index.vue
 * exists, the collection ends up empty and the landing page returns 404.
 */
const { options } = useNuxt()
const cwd = joinURL(options.rootDir, 'content')

export default defineContentConfig({
  collections: {
    landing: defineCollection({
      type: 'page',
      source: {
        cwd,
        include: 'index.md',
      },
    }),
  },
})
