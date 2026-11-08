# Contributing

Thank you for helping. Tocsin deals with legal deadlines and confidential incident data, so changes are held to a high bar.

## Before you start

- **Sign the CLA.** Pull requests can only be merged after you agree to `CLA.md` (one line in your first pull request). You keep your copyright; the CLA lets MB AFKzona Group also offer the code under a commercial licence.
- **Security issues** go through GitHub Security Advisories, not issues. See `SECURITY.md`.
- **Legal changes** must cite the official text on EUR-Lex (article, paragraph, point) and quote it. Blogs and summaries are not sources. If a change depends on an interpretation, add it to "Interpretation choices" in `LEGAL.md`.

## Development

Requires Node.js 22.12 or later (the test tooling needs it).

```sh
npm ci
npm run check      # typecheck + lint + build + tests
npm run coverage   # coverage report (aim: 90 % lines on core logic)
```

Rules:

- TypeScript strict, no `any`, no `@ts-ignore`, no `eslint-disable` without a written reason on the same line.
- Pure functions for rules and calculations; disk, network and clock only at the edges.
- Every rule, threshold, boundary and deadline gets a test, including the value just below and just above the limit.
- Every security control gets a test that fails when the control is removed.
- No new runtime dependencies without a strong reason, written in the README "Dependencies" section.
- No `eval`, `new Function`, dynamic imports of user input, child processes, or `innerHTML`.
- No raw bidirectional-control characters in source files (a test checks this).
- Keep README examples and `test/examples.test.ts` identical.

## Pull requests

Small and focused. Describe what changed and why, and how you tested it. CI runs `npm run check` on pull requests.

## Code of conduct

See `CODE_OF_CONDUCT.md`.
