import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.PORT || 1337;

// The attacker only needs to serve a static page. The malicious work happens
// in the victim's browser, using the victim's own logged-in session.
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`Attacker site running on http://localhost:${PORT}`);
  console.log('Send a logged-in victim here to forge a recovery-email change.');
});
