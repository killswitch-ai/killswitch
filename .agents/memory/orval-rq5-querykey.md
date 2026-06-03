---
name: Orval + React Query v5 queryKey type mismatch
description: Orval-generated hooks use UseQueryOptions as the query option type, which requires queryKey in RQ v5. Cast as any at call sites.
---

## Rule
When calling orval-generated hooks, pass the query option with `as any`:
```ts
useGetTelemetryStats({ query: { staleTime: 5 * 60 * 1000 } as any })
```

**Why:** Orval generates `{ query?: UseQueryOptions<...> }` but `@tanstack/query-core@5.x` marks `queryKey` as required on `UseQueryOptions`. The key is managed internally by the generated hook — the cast is safe.

**How to apply:** Any new call site using orval-generated hooks with inline `query` options needs the `as any` cast to avoid TS2741.
