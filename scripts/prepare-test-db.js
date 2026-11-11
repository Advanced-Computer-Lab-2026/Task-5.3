import { MongoBinary } from 'mongodb-memory-server';

// Download outside Jest: a first-time download can exceed the test hook timeout.
// getPath reuses the same binary cache and environment options as the tests.
console.log('Preparing MongoDB for tests (the first download may take several minutes)...');
try {
  const binaryPath = await MongoBinary.getPath();
  console.log(`MongoDB ready: ${binaryPath}`);
} catch (error) {
  console.error('Could not prepare MongoDB. Check your connection and run npm test again.');
  console.error(error.message);
  process.exitCode = 1;
}
