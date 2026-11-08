// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/**', 'dist-check/**', 'coverage/**', 'node_modules/**'] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: { allowDefaultProject: ['eslint.config.js', 'bin/tocsin.js'] },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      'no-eval': 'error',
      'no-implied-eval': 'off',
      '@typescript-eslint/no-implied-eval': 'error',
      'no-new-func': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/ban-ts-comment': ['error', { 'ts-ignore': true, 'ts-nocheck': true, 'ts-expect-error': 'allow-with-description' }],
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
      // Prefer explicit `as T` over `!`: the strict config also forbids non-null assertions.
      '@typescript-eslint/non-nullable-type-assertion-style': 'off',
      'no-restricted-properties': [
        'error',
        { property: 'innerHTML', message: 'Use textContent / createElement.' },
        { property: 'outerHTML', message: 'Use textContent / createElement.' },
        { property: 'insertAdjacentHTML', message: 'Use textContent / createElement.' },
      ],
      'no-restricted-imports': ['error', { paths: [{ name: 'node:child_process', message: 'No child processes.' }, { name: 'child_process', message: 'No child processes.' }] }],
    },
  },
  {
    // Tests use `expect(() => fn()).toThrow()` with functions that return void.
    files: ['test/**/*.ts'],
    rules: { '@typescript-eslint/no-confusing-void-expression': ['error', { ignoreArrowShorthand: true }] },
  },
  {
    files: ['**/*.js'],
    ...tseslint.configs.disableTypeChecked,
  },
);
