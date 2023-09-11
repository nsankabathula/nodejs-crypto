const rsaOAEP = require('./rsa-crypto')
//const crypto = require('crypto');

const actualData = "TEST RSA-OAEP (encrypt & decrypt) Sensitive Data: " + new Date();

test(actualData, () => {
    const rsaCipher = new rsaOAEP("./crypto-keys/crypto-enc.pem", "./crypto-keys/crypto-enc.key");
    const decryptedData = rsaCipher.decrypt(rsaCipher.encrypt(actualData));
    expect(decryptedData).toBe(actualData);
});