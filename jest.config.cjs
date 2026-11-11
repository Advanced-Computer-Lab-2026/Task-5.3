// One jest run with two environments:
//   - "server" tests run in node (they boot the Express app + in-memory Mongo)
//   - "client" tests run in jsdom (they exercise the browser-side api client)
// `npm test` runs both.
const { spawnSync } = require('node:child_process');

// Reuse a local MongoDB installation when available, avoiding a large download
// during the server suite's setup. Explicit memory-server settings take priority.
if (!process.env.MONGOMS_SYSTEM_BINARY) {
  const located = spawnSync(process.platform === 'win32' ? 'where.exe' : 'which', ['mongod'], {
    encoding: 'utf8',
    windowsHide: true
  });
  if (located.status === 0) {
    const binaryPath = located.stdout.split(/\r?\n/).find((line) => line.trim());
    if (binaryPath) process.env.MONGOMS_SYSTEM_BINARY = binaryPath.trim();
  }
}

module.exports = {
  projects: [
    {
      displayName: 'server',
      testEnvironment: 'node',
      testMatch: ['<rootDir>/tests/server/**/*.test.js'],
      transform: {
        '^.+\\.js$': 'babel-jest'
      }
    },
    {
      displayName: 'client',
      testEnvironment: 'jsdom',
      testMatch: ['<rootDir>/tests/client/**/*.test.js'],
      transform: {
        '^.+\\.js$': 'babel-jest'
      }
    }
  ]
};
