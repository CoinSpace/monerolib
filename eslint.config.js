import config, { node } from 'eslint-config-coinspace';

/** @type {import('eslint').Linter.Config[]} */
export default [
  ...config,
  ...node,
  {
    rules: {
      'object-curly-newline': ['error', { minProperties: 3, consistent: true }],
    },
  },
];
