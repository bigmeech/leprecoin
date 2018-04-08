const crypto = require('crypto');
const random = require('secure-random');
const secp256k1 = require('secp256k1/elliptic');
const Ripemd = require('ripemd160');
const base58Check = require('base58check');
/**
 * creates a single hash
 * @param inputString
 * @returns {*}
 */
function hasherFn(inputString) {
    return crypto
        .createHash('sha256')
        .update(inputString)
        .digest('hex');
}

/**
 * creates double hash
 * @param inputString
 */
function createDoubleHash(inputString) {
    return hasherFn(hasherFn(inputString));
}

/**
 * signs a message with a private key
 * @param message
 * @param privateKey
 * @returns {*}
 */
function sign(message, privateKey) {
    let signatureObj;
    try {
        signatureObj = secp256k1.sign(message, privateKey);
    }
    catch(e) {
        console.error(e);
    }
    return signatureObj;
}

/**
 * verifies that the signature was signed by a private key that created supplied public key
 * @param message
 * @param signature
 * @param publicKey
 * @returns {*}
 */
function verify(message, signature, publicKey) {
    let isValid = false;
    try {
        isValid = secp256k1.verify(message, signature, publicKey);
    } catch(e) {
        console.log(e);
    }
    return isValid;
}

/**
 * generate new private and public key pairs when called
 * @returns {{privateKey: string, publicKey: string}}
 */
function generateAddressComponentsFn() {
    let privateKey = generateRandomPrivatekey();

    // Get public key from private key
    const publicKey = secp256k1
        .publicKeyCreate(privateKey)
        .toString('hex');

    // compute sha256
    const pkHash = crypto.createHash('sha256').update(publicKey).digest('hex');

    // compute ripemd hash from above sha256
    const ripeMdHash = new Ripemd().update(pkHash).digest('hex');

    // internally prefixes the ripemd hash with the correct prefix,
    // does a hash-of-hash (a double hash function)
    const address = base58Check.encode(ripeMdHash);
    const privateKeyWIF = base58Check.encode(privateKey, '0x80');

    // TODO: Get this working, find out how to do this with the secp256k1 library
    const publicKeyWIF = base58Check.encode(ripeMdHash, '0x80');

    return {
        publicKey,
        privateKey: privateKey.toString('hex'),
        wifs: {
            privKey: privateKeyWIF,
            pubKey: ''
        },
        address,
    }
}

/**
 * gets private key
 * @returns {*}
 */
function generateRandomPrivatekey() {
    let privateKey;
    do {
        privateKey = random.randomBuffer(32);
    }
    while(!secp256k1.privateKeyVerify(privateKey));
    return privateKey;
}

exports.generateAddressComponents = generateAddressComponentsFn;
exports.hasher = hasherFn;