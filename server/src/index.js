import 'dotenv/config';
import app from './app.js';
import { connectDB } from './config/db.js';
import { assertCsrfSecret } from './middleware/csrf.js';

const PORT = process.env.PORT || 4000;

async function bootstrap() {
  assertCsrfSecret();
  await connectDB();
  app.listen(PORT, () => {
    console.log(`API listening on http://localhost:${PORT}`);
  });
}
bootstrap();
