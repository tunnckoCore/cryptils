const config = require('eslint-config-tunnckocore/prettier.cjs');

const cfg = {
  ...config,
  overrides: [
    ...config.overrides,
    {
      files: '**/*.sol',
      options: {
        parser: 'solidity-parse',
        printWidth: 100,
        tabWidth: 4,
        useTabs: false,
        singleQuote: false,
        bracketSpacing: false,
      },
    },
  ],
};

module.exports = cfg;
