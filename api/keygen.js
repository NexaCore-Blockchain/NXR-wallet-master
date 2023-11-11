const bitcoin = require('bitcoinjs-lib');

let kmd_network = {
    messagePrefix: '\x19Komodo Signed Message:\n',
    bip32: {
        public: 0x0488b21e,
        private: 0x0488ade4,
    },
    pubKeyHash: 0x3c,
    scriptHash: 0x55,
    wif: 0xbc,
    dustThreshold: 1000,
    isZcash: true,
    kmdInterest: true,
}

function generateKeyPair() {
    let pair = bitcoin.ECPair.makeRandom({network: kmd_network})
    return {
        pubkey: pair.publicKey.toString('hex'),
        privkey: pair.toWIF()
    }
}

module.exports = { 
    generateKeyPair
}
