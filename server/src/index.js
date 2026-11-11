import dotenv from 'dotenv';
dotenv.config();
import app from './app.js';
import { connectDB } from './config/db.js';

const PORT = process.env.PORT || 4000;

// Fail fast: CSRF protection needs a secret to sign its tokens.
if (!process.env.CSRF_SECRET) {
  console.error('CSRF_SECRET is missing — add it to server/.env');
  process.exit(1);
}

async function bootstrap() {
  await connectDB();
  app.listen(PORT, () => {
    console.log(`API listening on http://localhost:${PORT}`);
  });
}
bootstrap();
