import fs from 'fs';
import path from 'path';

const babelConfigPath = path.join(process.cwd(), 'babel.config.cjs');

const babelConfigContent = `// Lets jest load the project's ESM source (server + client) through babel-jest.
module.exports = {
  presets: [
    ['@babel/preset-env', { targets: { node: 'current' } }]
  ]
};
`;

if (!fs.existsSync(babelConfigPath)) {
  fs.writeFileSync(babelConfigPath, babelConfigContent, { encoding: 'utf8' });
}