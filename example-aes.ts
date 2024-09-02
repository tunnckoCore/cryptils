import { decryptWithSecret, encryptWithSecret } from './src/aes.ts';
import { spectreV4 } from './src/derive.ts';
import { randomBytes } from './src/utils.ts';

const account = spectreV4('usrname', 'foo pass bar', 'twt.com');

// or try with random one
const secret = randomBytes(32);

console.log({ account });

const encrypted = await encryptWithSecret(account.pass, account.secret);
const decrypted = await decryptWithSecret(encrypted, account.secret);

console.log({ encrypted, decrypted, same: decrypted === account.pass });
