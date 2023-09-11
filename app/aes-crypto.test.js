
const aes256gcm = require('./aes-crypto')
const crypto = require('crypto');

const actualData = "TEST AES-GCM (encrypt & decrypt) Sensitive Data: " + new Date();


test(actualData, () => {

    const AES_256_KEY = new Buffer.from(crypto.randomBytes(32), 'utf8');

    const aesCipher = new aes256gcm(AES_256_KEY);
    const [encrypted, iv, authTag] = aesCipher.encrypt(actualData);
    const decryptedData = aesCipher.decrypt(encrypted, iv, authTag);
    //console.log("Decrypted Data : ", decryptedData);
    //console.log("Comparision Result (Actual vs Decrypted)", actualData === decryptedData);
    expect(decryptedData).toBe(actualData);
});


