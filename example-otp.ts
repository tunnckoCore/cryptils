import qrcode from 'qrcode';

import {
  generateBase32Secret,
  getHotpToken,
  getTokenUri,
  getTotpToken,
  validateHotpToken,
  validateTotpToken,
} from './src/otp.ts';

// import { bytesToHex, randomBytes } from './src/utils.ts';

async function printset(options) {
  const secret = generateBase32Secret();
  // const secret = 'XB2FZCEQFWUPEDQ6Y5CFT5KN';

  const totpToken = await getTotpToken(secret, options);
  const hotpToken = await getHotpToken(secret, options);
  const uri = getTokenUri(secret, options);

  console.log(await qrcode.toString(uri));

  console.log({
    secret,
    totpToken,
    hotpToken,
    uri,
  });
}

printset({ algorithm: 'SHA-1', label: 'testsha1', username: 'user_test_sha1' });
printset({ algorithm: 'SHA256', period: 15, label: 'twosha', username: 'user_test_sha2' });
printset({ algorithm: 'SHA-512', period: 45, label: 'sha512', username: 'user_test_sha3' });
printset({ digits: 8, period: 5, label: 'testsha2', username: 'user_test_sh4' });
printset({ digits: 9, period: 30, label: 'testsha3', username: 'user_test_sha5' });
printset({
  algorithm: 'sha512',
  digits: 7,
  period: 13,
  label: 'label3',
  username: 'barry',
  issuer: 'issuer3',
});

const secret = generateBase32Secret();
const token = await getTotpToken(secret);
const valid = await validateTotpToken(secret, token);

console.log({ secret, token, valid });

const hotpToken = await getHotpToken(secret);
console.log({ hotpToken, valid: await validateHotpToken(secret, hotpToken) });
