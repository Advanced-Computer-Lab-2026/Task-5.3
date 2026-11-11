import fs from 'fs';
import path from 'path';

const workflowDir = path.join(process.cwd(), '.github', 'workflows');
const filePath = path.join(workflowDir, 'ci.yaml');

const ciContent = `name: CI

on:
  push:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - name: Check out the code
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm install

      - name: Run the test suite
        run: npm test
`;

if (!fs.existsSync(workflowDir)) {
  fs.mkdirSync(workflowDir, { recursive: true });
}
fs.writeFileSync(filePath, ciContent, { encoding: 'utf8' });
