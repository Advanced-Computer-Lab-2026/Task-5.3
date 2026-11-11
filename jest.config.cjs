// One jest run with two environments:
//   - "server" tests run in node (Express app + in-memory Mongo)
//   - "client" tests run in jsdom (browser-side api client)
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
