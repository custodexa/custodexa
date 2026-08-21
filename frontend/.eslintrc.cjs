/* eslint-env node */
module.exports = {
  root: true,
  extends: ['plugin:vue/vue3-recommended', 'eslint:recommended'],
  env: {
    browser: true,
    node: true,
    es2022: true,
  },
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  globals: {
    Guacamole: 'readonly',
  },
  rules: {
    'vue/multi-word-component-names': 'off',
    'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    'no-console': 'off',
  },
}
