import { generateKeyPair } from 'crypto';
import { writeFile } from 'fs/promises';

async function generateKeys() {
  generateKeyPair('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    }
  }, async (err, publicKey, privateKey) => {
    if (err) {
      console.error(err);
      return;
    }
    await writeFile('public.key', publicKey);
    await writeFile('private.key', privateKey);
    console.log('Keys generated and saved to public.key and private.key');
  });
}

generateKeys();
