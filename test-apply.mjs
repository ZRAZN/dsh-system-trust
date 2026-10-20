import { apply } from './index.js'

apply({ logger: console })
await new Promise((resolve) => setTimeout(resolve, 8000))
