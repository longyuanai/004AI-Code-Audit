import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['src/**/*.ts', 'tests/**/*.ts', 'scripts/**/*.{ts,mjs}'],
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
  {
    // Plain-JS scripts keep core `no-undef` (it is disabled for TypeScript,
    // where the compiler already checks it), so the Node globals they use
    // have to be declared. Listed inline rather than pulling in `globals`,
    // which is only present here as a transitive dependency.
    files: ['scripts/**/*.mjs'],
    languageOptions: {
      globals: { console: 'readonly', process: 'readonly' },
    },
  },
  {
    // These directories are scan *inputs*, not project code: deliberately
    // vulnerable or sloppy sources that the rule engine and the precision
    // ratchet run against. Linting them would report the very patterns they
    // exist to contain.
    ignores: [
      'dist/',
      'node_modules/',
      'coverage/',
      'samples/',
      'tests/fixtures/',
      'tests/corpus/',
      'tests/corpus-triage/',
    ],
  },
);
