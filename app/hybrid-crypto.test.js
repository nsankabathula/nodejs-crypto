const hybrid = require('./hybrid-crypto');

const actualData = "TEST HYBRID (encrypt & decrypt) Sensitive Data: " + new Date();

test(actualData, () => {
    const [cipherText, iv, authTag, contentEncKey] = hybrid.encrypt(actualData, "./crypto-keys/crypto-enc.pem");
    const decryptedData = hybrid.decrypt(cipherText, iv, authTag, contentEncKey, "./crypto-keys/crypto-enc.key")

    expect(decryptedData).toBe(actualData);
});