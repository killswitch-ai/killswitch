---
name: api-client-react dist rebuild
description: The lib package uses composite TS project references; dist/.d.ts must be rebuilt manually when generated source changes.
---

## Rule
`lib/api-client-react` has `"composite": true` — TypeScript resolves from `dist/` via project references.

When orval regenerates `src/generated/api.ts`, run:
```bash
cd lib/api-client-react && pnpm exec tsc --project tsconfig.json
```

**Why:** Without rebuilding, `dist/generated/api.d.ts` stays stale and TS reports missing exports even though the source has them.

**How to apply:** Any time codegen adds/changes hooks in `lib/api-client-react/src/generated/`, rebuild the declarations.
