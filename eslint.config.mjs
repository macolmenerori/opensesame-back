import eslint from '@eslint/js';
import { defineConfig, globalIgnores } from 'eslint/config';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import simpleImportSort from 'eslint-plugin-simple-import-sort';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default defineConfig([
  // Global ignores (replaces .eslintignore)
  globalIgnores(['types/**', 'jest.config.js', '.github/**', 'build/**', 'dist/**']),

  // Base configs
  eslint.configs.recommended,
  tseslint.configs.recommended,

  // Prettier (must come after to override conflicting rules)
  eslintPluginPrettierRecommended,

  // Project-specific configuration
  {
    files: ['**/*.{js,mjs,cjs,ts}'],
    plugins: {
      'simple-import-sort': simpleImportSort
    },
    languageOptions: {
      globals: { ...globals.node }
    },
    rules: {
      'no-console': 'warn',
      'no-unused-vars': ['warn', { argsIgnorePattern: 'req|res|next|val' }],
      '@typescript-eslint/no-unused-vars': 'warn',
      'prefer-destructuring': ['warn', { object: true, array: false }],
      'valid-typeof': 'warn',
      'no-useless-escape': 'warn',
      'simple-import-sort/exports': 'error',
      'simple-import-sort/imports': [
        'error',
        {
          groups: [
            ['^@macolmenerori?\\w'],
            ['^@?\\w'],
            [
              '^(api|assets|common|components|locales|mocks|pages|src|services|state|styles|types|utils)(/.*|$)'
            ],
            ['^\\u0000'],
            ['^\\.\\.(?!/?$)', '^\\.\\./?$'],
            ['^\\./(?=.*/)(?!/?$)', '^\\.(?!/?$)', '^\\./?$']
          ]
        }
      ]
    }
  }
]);
