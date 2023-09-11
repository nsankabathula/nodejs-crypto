const crypto = require("crypto");
const fs = require("fs");
const assert = require('assert');


class rsaOAEP {

    constructor(publicKeyPath, privateKeyPath) {
        this.rsaPrivateKey = privateKeyPath !== null ? fs.readFileSync(privateKeyPath, { encoding: "utf-8" }) : null;
        this.rsaPublicKey = publicKeyPath !== null ? fs.readFileSync(publicKeyPath, { encoding: "utf-8" }) : null;
    }

    static PADDING = crypto.constants.RSA_PKCS1_OAEP_PADDING;
    static OAEP_HASH = "sha256";

    encrypt(dataToEncrypt) {
        return this.encryptBuffer(Buffer.from(dataToEncrypt));
    }

    encryptBuffer(bufferDataToEncrypt) {
        // Encryting data using public key and padding.
        assert(this.rsaPublicKey !== null, "Public key required for encrypt operation.");

        const encryptedData = crypto.publicEncrypt(
            {
                key: this.rsaPublicKey,
                padding: rsaOAEP.PADDING,
                oaepHash: rsaOAEP.OAEP_HASH
            },
            bufferDataToEncrypt
        );
        return encryptedData.toString("base64")
    }

    decrypt(encryptedData) {
        return this.decryptBuffer(encryptedData).toString();
    }

    decryptBuffer(encryptedData) {
        assert(this.rsaPrivateKey !== null, "Private key required for decrypt operation.");
        const decryptedData = crypto.privateDecrypt(
            {
                key: this.rsaPrivateKey,
                padding: rsaOAEP.PADDING,
                oaepHash: rsaOAEP.OAEP_HASH
            },
            Buffer.from(encryptedData, "base64") // assuming that encrypted data is sent as base64
        );

        return decryptedData;
    };

};

const test = () => {
    const rsaCipher = new rsaOAEP("./crypto-keys/crypto-enc.pem", "./crypto-keys/crypto-enc.key");
    const actualData = "Sensitive Data: " + new Date();
    console.log("Actual Data : ", actualData);
    const decryptedData = rsaCipher.decrypt(rsaCipher.encrypt(actualData));
    console.log("Decrypted Data : ", decryptedData);
    console.log("Comparision Result (Actual vs Decrypted)", actualData === decryptedData);
}
//test();
module.exports = rsaOAEP;
