import config, { node } from 'eslint-config-coinspace';

/** @type {import('eslint').Linter.Config[]} */
export default [
  ...config,
  ...node,
  {
    files: ['test/**/*.js'],
    rules: {
      'max-len': ['error', {
        code: 120,
        ignoreComments: true,
        ignoreStrings: true,
        ignoreTemplateLiterals: true,
      }],
    },
  },
];
