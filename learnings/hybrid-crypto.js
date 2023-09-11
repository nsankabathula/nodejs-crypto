const rsaOAEP = require('./rsa-crypto')
const aes256gcm = require('./aes-crypto')
const crypto = require('crypto');

class hybrid {

    static encrypt(dataToEncrypt, publicKeyPath) {
        const rsaCipher = new rsaOAEP(publicKeyPath, null);
        const aesCipher = new aes256gcm(new Buffer.from(crypto.randomBytes(32), 'utf8'));
        var aesResult = aesCipher.encrypt(dataToEncrypt)
        //console.log(aesCipher.key);
        aesResult.push(rsaCipher.encryptBuffer(aesCipher.key));
        return aesResult;
    }

    static decrypt(cipherText, iv, authTag, contentEncKey, privateKeyPath) {
        const rsaCipher = new rsaOAEP(null, privateKeyPath);
        const aesCipher = new aes256gcm(rsaCipher.decryptBuffer(contentEncKey));
        //console.log(aesCipher.key);
        return aesCipher.decrypt(cipherText, iv, authTag);
    }

}

module.exports = hybrid;