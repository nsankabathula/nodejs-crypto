const buffer = require('buffer');
const crypto = require('crypto');

class aes256gcm {
    static ALGO = 'aes-256-gcm';
    static IV_SIZE = 12;
    constructor(key) {
        this.key = key !== null ? key : new Buffer.from(crypto.randomBytes(32), 'utf8');;
    }

    // encrypt returns base64-encoded ciphertext
    encrypt(str) {
        const iv = new Buffer.from(crypto.randomBytes(aes256gcm.IV_SIZE), 'utf8');
        const cipher = crypto.createCipheriv(aes256gcm.ALGO, this.key, iv);

        let enc = cipher.update(str, 'utf8', 'base64');
        enc += cipher.final('base64');
        return [enc, iv, cipher.getAuthTag()];
    };

    decrypt(enc, iv, authTag) {
        const decipher = crypto.createDecipheriv(aes256gcm.ALGO, this.key, iv);
        decipher.setAuthTag(authTag);
        let str = decipher.update(enc, 'base64', 'utf8');
        str += decipher.final('utf8');
        return str;
    };

}

const test = () => {

    const AES_256_KEY = new Buffer.from(crypto.randomBytes(32), 'utf8');

    const aesCipher = new aes256gcm(AES_256_KEY);

    const actualData = "Sensitive Data: " + new Date();
    const [encrypted, iv, authTag] = aesCipher.encrypt(actualData);
    const decryptedData = aesCipher.decrypt(encrypted, iv, authTag);


    console.log("Decrypted Data : ", decryptedData);

    console.log("Comparision Result (Actual vs Decrypted)", actualData === decryptedData);
};

//test();
module.exports = aes256gcm;

