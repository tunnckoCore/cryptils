import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { scrypt } from '@noble/hashes/scrypt';
import { randomBytes } from '@noble/hashes/utils';

import { decryptWithSecret, encryptWithSecret } from './src/aes.ts';
import { spectreV4 } from './src/derive.ts';

const account = spectreV4('usrname', 'foo pass bar', 'twt.com');

// or try with random one
const secret = randomBytes(32);

console.log({ account, secret });

const encrypted = await encryptWithSecret(account.securepass, account.secret);
const decrypted = await decryptWithSecret(encrypted, account.secret);

console.log({ encrypted, decrypted, same: decrypted === account.securepass });

console.log(scrypt.name);
console.log(pbkdf2.name);
// const iterations = 2 ** 18;
// const userKey2 = scrypt(toBytes('pass'), toBytes('user'), {
//   N: iterations,
//   r: 8,
//   p: 2,
//   dkLen: 64,
// });

// // use pbkdf2 instead of scrypt
// const userKey = pbkdf2(sha256, toBytes('pass'), toBytes('user'), {
//   c: iterations,
//   dkLen: 64,
// });
