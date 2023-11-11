const fs = require("fs");
const crypto = require('asymmetric-crypto')
const naclUtil = require('tweetnacl-util')
const nacl = require('tweetnacl')

const random_pw = 'kmd'

const enc = '.enc'
const pub = '.pub'

class Safe {
    constructor(filePath, password='') {
        this.filePath = filePath
        this.setPassword(password)
    }

    setPassword(password) {
        this.password = password
    }

    getPair(pw) {
        let text_encoder = new TextEncoder();

        let encodedPassword = text_encoder.encode(pw)
        let hashedPassword = nacl.hash(encodedPassword)
        let userSecretKey = naclUtil.encodeBase64(hashedPassword)

        let keyPair = crypto.fromSecretKey(userSecretKey)
        console.log('password: ', pw)
        console.log('GETPAIR: ', keyPair)

        return keyPair
    }

    errWrongPassword(msg) {
        return msg.indexOf('invalid encoding') !== -1 
                || msg.indexOf('wrong password') !== -1 
                || msg.indexOf('failed opening nacl.box') !== -1
    }

    errFileNotFound(msg) {
        return msg.indexOf('no such file or directory') !== -1
    }

    _encrypt(data) {
        const userKey = this.getPair(this.password)
        const randomKey = this.getPair(random_pw)

        const pubkey = userKey.publicKey

        console.log('Encrypting: ', data.toString(), pubkey, randomKey.secretKey)
        let encrypted = crypto.encrypt(data.toString(), pubkey, randomKey.secretKey)
        encrypted.publicKey = pubkey

        return encrypted
    }

    _decrypt(data, nonce) {
        const userKey = this.getPair(this.password)
        const randomKey = this.getPair(random_pw)

        console.log('Decrypting: ', data.toString(), nonce, randomKey.publicKey, userKey.secretKey)
        return crypto.decrypt(data.toString(), nonce, randomKey.publicKey, userKey.secretKey)
    }

    decryptFile() {
        return new Promise((resolve, reject) => {
            // Read encryption information
            let enc_info
            try {  
                enc_info = JSON.parse(fs.readFileSync(this.filePath + pub))
            } 
            catch(exception) { 
                console.log('Could not read encryption information, probably first launch', this.filePath + pub)
                reject({ message: exception.message })
            }

            // Password check
            if(enc_info.publicKey !== this.getPair(this.password).publicKey) 
                reject({ message: 'wrong password' })

            // Read encrypted file
            let data
            try {  
                data = fs.readFileSync(this.filePath + enc) 
            } 
            catch(exception) { 
                console.log('Could not read encrypted file, probably first launch', this.filePath + enc)
                reject({ message: exception.message })
            }

            // Decrypted and write
            try { 
                fs.writeFileSync(this.filePath, Buffer.from(this._decrypt(data, enc_info.nonce)))
                console.log('Decrypted and saved: ', this.filePath)

                console.log('Removing : ', this.filePath + enc)
                fs.unlinkSync(this.filePath + enc)
                console.log('Removed : ', this.filePath + enc)

                resolve({ message: 'success' }); 
            } 
            catch(exception) { 
                console.log('Could not decrypt and save: ', this.filePath)
                reject({ message: exception.message }); 
            }
        });
    }

    encryptFile() {
        return new Promise((resolve, reject) => {
            // Read non-encrypted file
            let data
            try {  
                data = fs.readFileSync(this.filePath) 
            } 
            catch(exception) { 
                console.log('Could not read to encrypt', this.filePath)
                reject({ message: exception.message })
            }

            // Encrypt and write
            try {  
                let encrypted = this._encrypt(data)

                // Write data file
                fs.writeFileSync(this.filePath + enc, encrypted.data);
                console.log('Encrypted and saved: ', this.filePath + enc)
                
                console.log('Removing : ', this.filePath)
                fs.unlinkSync(this.filePath)
                console.log('Removed : ', this.filePath)


                // Save pubkey and nonce
                fs.writeFileSync(this.filePath + pub, JSON.stringify({ publicKey: encrypted.publicKey, nonce: encrypted.nonce }))


                resolve({ message: 'success'})
            } 
            catch(exception) { 
                console.log('Could not encrypt the file!', this.filePath)
                reject({ message: exception.message })
            }
        });
    }
}

exports.Safe = Safe;
