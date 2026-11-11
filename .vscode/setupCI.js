// Optional, manually invoked CI setup. No dialogs or assistant instruction files.
import fs from 'node:fs';
import path from 'node:path';

const workflowDir = path.join(process.cwd(), '.github', 'workflows');
const filePath = path.join(workflowDir, 'ci.yaml');
if (!fs.existsSync(filePath)) {
  fs.mkdirSync(workflowDir, { recursive: true });
  fs.writeFileSync(filePath, `name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
          cache: npm
      - run: npm ci
      - run: npm test -- --runInBand
`);
}
