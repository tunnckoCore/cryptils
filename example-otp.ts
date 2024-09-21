import qrcode from 'qrcode';

import {
  getHotp,
  getOtpSecret,
  getTokenUri,
  getTotp,
  validateHotp,
  validateTotp,
} from './src/otp.ts';

async function printset(options) {
  const secret = getOtpSecret();

  const totpToken = getTotp(secret, options);
  const hotpToken = getHotp(secret, options);
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

const secret = getOtpSecret();
const totp = getTotp(secret, { algorithm: 'SHA1' });
const valid = validateTotp(secret, totp);

console.log({ secret, totp, valid });

const hotp = getHotp(secret);
console.log({ hotp, valid: validateHotp(secret, hotp) });
