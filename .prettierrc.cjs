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

/**
Explain me how PoS, liquid staking, and DeFi is not a Ponzi scheme.

I'll wait.

Next: stake the staked of the staked and wrap it the LP.

It's certifiably the biggest Ponzi scheme humanity ever created. Except it won't crash, which doesn't justify it's existence.

*/
