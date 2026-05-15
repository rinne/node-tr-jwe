'use strict';

const crypto = require('node:crypto');
const zlib = require("node:zlib");
            
const { cipherKeyGen } = require('tr-jwk');

const kwAlgOpts = {
    A128GCMKW: { keyLength: 128, nodeJsCipherId: 'aes-128-gcm', enc: 'A128GCM' },
    A192GCMKW: { keyLength: 192, nodeJsCipherId: 'aes-192-gcm', enc: 'A192GCM' },
    A256GCMKW: { keyLength: 256, nodeJsCipherId: 'aes-256-gcm', enc: 'A256GCM' }
};

const simpleKwAlgOpts = {
    A128KW: { keyLength: 128, nodeJsCipherId: 'id-aes128-wrap', enc: 'A128GCM' },
    A192KW: { keyLength: 192, nodeJsCipherId: 'id-aes192-wrap', enc: 'A192GCM' },
    A256KW: { keyLength: 256, nodeJsCipherId: 'id-aes256-wrap', enc: 'A256GCM' }
};

const rsaAlgOpts = {
    'RSA1_5':       { padding: crypto.constants.RSA_PKCS1_PADDING },
    'RSA-OAEP':     { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    'RSA-OAEP-256': { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }
};

const AES_KW_IV = Buffer.from('a6a6a6a6a6a6a6a6', 'hex');

const encAlgOpts = {
    A128GCM: { keyLength: 128, nodeJsCipherId: 'aes-128-gcm' },
    A192GCM: { keyLength: 192, nodeJsCipherId: 'aes-192-gcm' },
    A256GCM: { keyLength: 256, nodeJsCipherId: 'aes-256-gcm' }
};

const ecdhCurveOpts = {
    'P-256': { enc: 'A128GCM' },
    'P-384': { enc: 'A192GCM' },
    'P-521': { enc: 'A256GCM' }
};

function encrypt(alg, jwk, data, options) {
    if (options === undefined || options === null) {
        options = {};
    }
    if (! ((typeof options === 'object') && ! Array.isArray(options))) {
        throw new Error('Invalid options');
    }
    {
        const known = new Set([ 'compressPayload', 'extendedReturn' ]);
        for (const k of Object.keys(options)) {
            if (! known.has(k)) {
                throw new Error('Unknown option: ' + k);
            }
        }
    }
    const compressOpt = options.compressPayload ?? false;
    if (! (compressOpt === false || compressOpt === true || compressOpt === 'auto')) {
        throw new Error('Invalid compressPayload option');
    }
    const extendedReturn = options.extendedReturn ?? false;
    if (! (extendedReturn === false || extendedReturn === true)) {
        throw new Error('Invalid extendedReturn option');
    }
    var mode, enc, keyBytes = 0, keyBits = 0;
    if (kwAlgOpts[alg]) {
        if (! (jwk && (jwk?.kty === 'oct') && (/^[0-9a-zA-Z_-]{22,43}$/.test(jwk.k)))) {
            throw new Error('Invalid JWK key for key wrap');
        }
        mode = 'kw';
        enc = kwAlgOpts[alg]?.enc;
        keyBits = kwAlgOpts[alg]?.keyLength ?? 0; 
        keyBytes = Math.ceil(keyBits / 8);
    } else if (simpleKwAlgOpts[alg]) {
        if (! (jwk && (jwk?.kty === 'oct') && (/^[0-9a-zA-Z_-]{22,43}$/.test(jwk.k)))) {
            throw new Error('Invalid JWK key for key wrap');
        }
        mode = 'skw';
        enc = simpleKwAlgOpts[alg]?.enc;
        keyBits = simpleKwAlgOpts[alg]?.keyLength ?? 0;
        keyBytes = Math.ceil(keyBits / 8);
    } else if (rsaAlgOpts[alg]) {
        if (! (jwk && (jwk?.kty === 'RSA'))) {
            throw new Error('Invalid JWK key for RSA encryption');
        }
        mode = 'rsa';
        const modulusLength = crypto.createPublicKey({ key: jwk, format: 'jwk' }).asymmetricKeyDetails.modulusLength;
        if (modulusLength < 1024) {
            throw new Error('RSA key too short');
        }
        enc = (modulusLength >= 2048) ? 'A256GCM' : 'A128GCM';
        keyBits = encAlgOpts[enc]?.keyLength ?? 0;
        keyBytes = Math.ceil(keyBits / 8);
    } else if (alg === 'dir') {
        if (! (jwk && (jwk?.kty === 'oct') && (/^[0-9a-zA-Z_-]{22,43}$/.test(jwk.k)))) {
            throw new Error('Invalid JWK key for direct encryption');
        }
        const dirKey = Buffer.from(jwk.k, 'base64url');
        enc = { 16: 'A128GCM', 24: 'A192GCM', 32: 'A256GCM' }[dirKey.length];
        if (! enc) {
            throw new Error('Invalid key length for direct encryption');
        }
        mode = 'dir';
        keyBits = encAlgOpts[enc]?.keyLength ?? 0;
        keyBytes = Math.ceil(keyBits / 8);
    } else if (alg === 'ECDH-ES') {
        if (! (jwk && (jwk?.kty === 'EC') && ecdhCurveOpts[jwk.crv])) {
            throw new Error('Invalid JWK key for ECDH');
        }
        mode = 'ecdh';
        enc = ecdhCurveOpts[jwk?.crv].enc;
        keyBits = encAlgOpts[enc]?.keyLength ?? 0;
        keyBytes = Math.ceil(keyBits / 8);
    }
    if (! (keyBits && keyBytes)) {
        throw new Error('Invalid encryption algorithm');
    }
    var headerData = { alg, enc }, contentKey, encryptedContentKey;
    switch (mode) {
    case 'kw':
        {
            if (! [ null, undefined, alg ].includes(jwk.alg)) {
                throw new Error('Invalid JWK key algorithm');
            }
            const kwKey = Buffer.from(jwk.k, 'base64url');
            if (kwKey.length != keyBytes) {
                throw new Error('Invalid JWK key length');
            }
            contentKey = Buffer.from(cipherKeyGen(kwAlgOpts[alg].enc).k, 'base64url');
            const kwIv = crypto.randomBytes(12);
            const kwCipher = crypto.createCipheriv(kwAlgOpts[alg].nodeJsCipherId, kwKey, kwIv);
            encryptedContentKey = Buffer.concat([kwCipher.update(contentKey), kwCipher.final()]);
            const kwTag = kwCipher.getAuthTag();
            Object.assign(headerData, { alg,
                                        iv: kwIv.toString('base64url'),
                                        tag: kwTag.toString('base64url') });
        }
        break;
    case 'skw':
        {
            if (! [ null, undefined, alg ].includes(jwk.alg)) {
                throw new Error('Invalid JWK key algorithm');
            }
            const skwKey = Buffer.from(jwk.k, 'base64url');
            if (skwKey.length != keyBytes) {
                throw new Error('Invalid JWK key length');
            }
            contentKey = Buffer.from(cipherKeyGen(simpleKwAlgOpts[alg].enc).k, 'base64url');
            const skwCipher = crypto.createCipheriv(simpleKwAlgOpts[alg].nodeJsCipherId, skwKey, AES_KW_IV);
            encryptedContentKey = Buffer.concat([skwCipher.update(contentKey), skwCipher.final()]);
        }
        break;
    case 'rsa':
        {
            contentKey = Buffer.from(cipherKeyGen(enc).k, 'base64url');
            const rsaOpts = rsaAlgOpts[alg];
            const rsaPubKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
            encryptedContentKey = crypto.publicEncrypt({ key: rsaPubKey, ...rsaOpts }, contentKey);
        }
        break;
    case 'dir':
        {
            contentKey = Buffer.from(jwk.k, 'base64url');
            encryptedContentKey = Buffer.alloc(0);
        }
        break;
    case 'ecdh':
        {
            const recipientKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
            const ephemeralKeys = crypto.generateKeyPairSync('ec', { namedCurve: jwk.crv });
            const sharedSecret = crypto.diffieHellman({ privateKey: ephemeralKeys.privateKey,
                                                        publicKey: recipientKey });
            const epk = ephemeralKeys.publicKey.export({ format: 'jwk' });
            const otherInfo = _ecdhOtherInfo(enc, keyBits);
            contentKey = crypto.createHash('sha256')
                .update(_uint32be(1))
                .update(sharedSecret)
                .update(otherInfo)
                .digest()
                .subarray(0, keyBytes);
            encryptedContentKey = Buffer.alloc(0);
            Object.assign(headerData, { epk });
        }
        break;
    default:
        throw new Error('Internal error');
    }
    if (jwk.kid && (typeof(jwk.kid) === 'string')) {
        headerData.kid = jwk.kid;
    } else if (! [ null, undefined, '' ].includes(jwk.kid)) {
        throw new Error('Invalid JWK key identifier');
    }
    // RFC 7516 places no restriction on the plaintext content; tr-jwe carries
    // any JSON-serialisable value (object, array, string, number, boolean,
    // or null). JSON.stringify(undefined) yields `undefined`, which is not a
    // valid JSON value — reject that case explicitly.
    const rawJson = JSON.stringify(data);
    if (typeof rawJson !== 'string') {
        throw new Error('Invalid input data');
    }
    const rawPlaintext = Buffer.from(rawJson);
    var plaintext = rawPlaintext;
    if (compressOpt === true) {
        plaintext = zlib.deflateRawSync(rawPlaintext);
        headerData.zip = 'DEF';
    } else if (compressOpt === 'auto') {
        const deflated = zlib.deflateRawSync(rawPlaintext);
        if (deflated.length < rawPlaintext.length) {
            plaintext = deflated;
            headerData.zip = 'DEF';
        }
    }
    const header = Buffer.from(JSON.stringify(headerData)).toString('base64url');
    const iv =  crypto.randomBytes(12);
    const cipher = (crypto
                    .createCipheriv(encAlgOpts[headerData.enc].nodeJsCipherId, contentKey, iv)
                    .setAAD(Buffer.from(header, 'ascii')));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const token = (header + '.' +
                   encryptedContentKey.toString('base64url') + '.' +
                   iv.toString('base64url') + '.' +
                   ciphertext.toString('base64url') + '.' +
                   tag.toString('base64url'));
    if (extendedReturn) {
        return {
            token,
            contentEncryptionKey: {
                kty: 'oct',
                alg: headerData.enc,
                k: contentKey.toString('base64url'),
                key_ops: [ 'encrypt', 'decrypt' ]
            }
        };
    }
    return token;
}

function parse(token) {
    if (! (token && (typeof(token) === 'string'))) {
        throw new Error('Invalid JWE token');
    }
    const t = token.split('.');
    if (t.length != 5) {
        throw new Error('Invalid JWE token');
    }
    if (t.find((x) => (! /^[0-9a-zA-Z_-]*$/.test(x)))) {
        throw new Error('Invalid JWE token');
    }
    let r = { token,
              header: Buffer.from(t[0], 'ascii'),
              headerData: null,
              key: Buffer.from(t[1], 'base64url'),
              iv: Buffer.from(t[2], 'base64url'),
              ciphertext: Buffer.from(t[3], 'base64url'),
              tag:  Buffer.from(t[4], 'base64url') }
    try {
        const json = Buffer.from(t[0], 'base64url').toString('utf8');
        if (! /^\s*\{.*\}\s*$/.test(json)) {
            throw new Error('Invalid JWE header (not a JSON object)');
        }
        r.headerData = JSON.parse(json);
    } catch (_) {
        throw new Error('Invalid JWE header');
    }
    return r;
}

function decrypt(token, jwk) {
    const t = parse(token);
    const enc = t.headerData?.enc;
    if (! encAlgOpts[enc]) {
        throw new Error('Invalid encryption algorithm');
    }
    if (! [ null, undefined, 'DEF' ].includes(t.headerData?.zip)) {
        throw new Error('Invalid payload compression');
    }
    var plaintext;
    try {
        let key;
        if ((kwAlgOpts[t.headerData?.alg] &&
             encAlgOpts[t.headerData?.enc] &&
             [ null, undefined, 'DEF' ].includes(t.headerData?.zip) &&
             /^[0-9a-zA-Z_-]{2,}$/.test(t.headerData?.iv) &&
             /^[0-9a-zA-Z_-]{2,}$/.test(t.headerData?.tag))) {
            key = _dec(t.key,
                       jwk,
                       Buffer.from(t.headerData.iv, 'base64url'),
                       Buffer.from(t.headerData.tag, 'base64url'));
        } else if ((simpleKwAlgOpts[t.headerData?.alg] &&
                    encAlgOpts[t.headerData?.enc] &&
                    (t.key.length > 0))) {
            key = _simpleKwUnwrap(t.key, t.headerData.alg, jwk);
        } else if ((rsaAlgOpts[t.headerData?.alg] &&
                    encAlgOpts[t.headerData?.enc] &&
                    (t.key.length > 0))) {
            key = _rsaUnwrap(t.key, t.headerData.alg, jwk);
        } else if ((t.headerData?.alg === 'dir') &&
                   encAlgOpts[t.headerData?.enc] &&
                   (t.key.length === 0)) {
            if (! (jwk && (jwk?.kty === 'oct') && (/^[0-9a-zA-Z_-]{22,43}$/.test(jwk.k)))) {
                throw new Error('Invalid JWK key for direct decryption');
            }
            const dirKey = Buffer.from(jwk.k, 'base64url');
            if (dirKey.length * 8 !== encAlgOpts[t.headerData.enc].keyLength) {
                throw new Error('Key length does not match enc algorithm');
            }
            key = dirKey;
        } else if ((t.headerData?.alg === 'ECDH-ES') &&
                   encAlgOpts[t.headerData?.enc] &&
                   (t.key.length === 0) &&
                   (t.headerData?.epk?.kty === 'EC') &&
                   ecdhCurveOpts[t.headerData?.epk?.crv]) {
            key = _ecdhKey(t.headerData.enc, t.headerData.epk, jwk, t.headerData.apu, t.headerData.apv);
        } else {
            throw new Error('Invalid token encryption');
        }
        plaintext = _dec(t.ciphertext,
                         { kty: 'oct',
                           alg: t.headerData.enc,
                           k: key.toString('base64url') },
                         t.iv,
                         t.tag,
                         t.header);
        switch (t.headerData.zip) {
        case 'DEF':
            plaintext = zlib.inflateRawSync(plaintext);
            break;
        default:
            /*NOTHING*/
        }
    } catch (_) {
        plaintext = undefined;
    }
    if (! plaintext) {
        // Just try if the submitted key happens to be content key instead.
        try {
            if (! [ null, undefined, 'DEF' ].includes(t.headerData?.zip)) {
                throw new Error('Invalid token encryption');
            }
            plaintext = _dec(t.ciphertext, jwk, t.iv, t.tag, t.header);
            switch (t.headerData.zip) {
            case 'DEF':
                plaintext = zlib.inflateRawSync(plaintext);
                break;
            default:
                /*NOTHING*/
            }
        } catch (_) {
            plaintext = undefined;
        }
    }
    if (! plaintext) {
        throw new Error('Unable to decrypt JWE token');
    }
    var payload = _jsonBufToObj(plaintext);
    return payload;
}

function unwrap(token, jwk) {
    const t = parse(token);
    const enc = t.headerData?.enc;
    if (! encAlgOpts[enc]) {
        throw new Error('Invalid token encryption');
    }
    try {
        let key;
        if ((kwAlgOpts[t.headerData?.alg] &&
             encAlgOpts[t.headerData?.enc] &&
             /^[0-9a-zA-Z_-]{2,}$/.test(t.headerData?.iv) &&
             /^[0-9a-zA-Z_-]{2,}$/.test(t.headerData?.tag))) {
            key = _dec(t.key,
                       jwk,
                       Buffer.from(t.headerData.iv, 'base64url'),
                       Buffer.from(t.headerData.tag, 'base64url'));
        } else if ((simpleKwAlgOpts[t.headerData?.alg] &&
                    encAlgOpts[t.headerData?.enc] &&
                    (t.key.length > 0))) {
            key = _simpleKwUnwrap(t.key, t.headerData.alg, jwk);
        } else if ((rsaAlgOpts[t.headerData?.alg] &&
                    encAlgOpts[t.headerData?.enc] &&
                    (t.key.length > 0))) {
            key = _rsaUnwrap(t.key, t.headerData.alg, jwk);
        } else if ((t.headerData?.alg === 'dir') &&
                   encAlgOpts[t.headerData?.enc] &&
                   (t.key.length === 0)) {
            if (! (jwk && (jwk?.kty === 'oct') && (/^[0-9a-zA-Z_-]{22,43}$/.test(jwk.k)))) {
                throw new Error('Invalid JWK key for direct decryption');
            }
            const dirKey = Buffer.from(jwk.k, 'base64url');
            if (dirKey.length * 8 !== encAlgOpts[t.headerData.enc].keyLength) {
                throw new Error('Key length does not match enc algorithm');
            }
            key = dirKey;
        } else if ((t.headerData?.alg === 'ECDH-ES') &&
                   encAlgOpts[t.headerData?.enc] &&
                   (t.key.length === 0) &&
                   (t.headerData?.epk?.kty === 'EC') &&
                   ecdhCurveOpts[t.headerData?.epk?.crv]) {
            key = _ecdhKey(t.headerData.enc, t.headerData.epk, jwk, t.headerData.apu, t.headerData.apv);
        } else {
            throw new Error('Invalid token encryption');
        }
        const wrappedJwk = { kty: 'oct',
                             alg: t.headerData.enc,
                             k: key.toString('base64url'),
                             key_ops: [ 'encrypt', 'decrypt' ] };
        return wrappedJwk;
    } catch (_) {
        throw new Error('Unable to unwrap JWE wrapped key');
    }
}

function _dec(ciphertext, jwk, iv, tag, aad) {
    const algOpts = encAlgOpts[jwk?.alg] ?? kwAlgOpts[jwk?.alg] ?? null
    if (! algOpts) {
        throw new Error('Invalid cipher algorithm');
    }
    if (! (jwk && (jwk.kty === 'oct') && (/^[0-9a-zA-Z_-]{22,43}$/.test(jwk.k)))) {
        throw new Error('Invalid JWK key');
    }
    const key = Buffer.from(jwk.k, 'base64url');
    if (key.length * 8 != algOpts.keyLength) {
        throw new Error('Invalid JWK key length');
    }
    try {
        const decipher = crypto.createDecipheriv(algOpts.nodeJsCipherId, key, iv).setAuthTag(tag);
        if (aad) {
            decipher.setAAD(aad);
        }
        const plaintext = Buffer.concat([ decipher.update(ciphertext), decipher.final() ]);
        return plaintext;
    } catch (_) {
        throw new Error('Unable to decrypt token payload');
    }
}

function _ecdhKey(enc, epk, jwk, apu, apv) {
    if (! (jwk && (jwk?.kty === 'EC') && (jwk?.crv === epk?.crv))) {
        throw new Error('Invalid JWK key for ECDH');
    }
    const keyBits = encAlgOpts[enc].keyLength;
    const keyBytes = Math.ceil(keyBits / 8);
    const privateKey = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
    const publicKey = crypto.createPublicKey({ key: epk, format: 'jwk' });
    const sharedSecret = crypto.diffieHellman({ privateKey, publicKey });
    return (crypto
            .createHash('sha256')
            .update(_uint32be(1))
            .update(sharedSecret)
            .update(_ecdhOtherInfo(enc, keyBits, apu, apv))
            .digest()
            .subarray(0, keyBytes));
}

function _ecdhOtherInfo(enc, keyBits, apu, apv) {
    const apuBytes = apu ? Buffer.from(apu, 'base64url') : Buffer.alloc(0);
    const apvBytes = apv ? Buffer.from(apv, 'base64url') : Buffer.alloc(0);
    return Buffer.concat([ _uint32be(enc.length),
                           Buffer.from(enc, 'ascii'),
                           _uint32be(apuBytes.length),
                           apuBytes,
                           _uint32be(apvBytes.length),
                           apvBytes,
                           _uint32be(keyBits) ]);
}

function _jsonBufToObj(b) {
    try {
        return JSON.parse(b.toString('utf8'));
    } catch (_) {
        throw new Error('Unable to decode JSON data');
    }
}

function _simpleKwUnwrap(encryptedKey, alg, jwk) {
    const opts = simpleKwAlgOpts[alg];
    if (! opts) {
        throw new Error('Invalid key wrap algorithm');
    }
    if (! (jwk && (jwk?.kty === 'oct') && (/^[0-9a-zA-Z_-]{22,43}$/.test(jwk.k)))) {
        throw new Error('Invalid JWK key for key unwrap');
    }
    const wrapKey = Buffer.from(jwk.k, 'base64url');
    if (wrapKey.length * 8 !== opts.keyLength) {
        throw new Error('Invalid JWK key length');
    }
    try {
        const decipher = crypto.createDecipheriv(opts.nodeJsCipherId, wrapKey, AES_KW_IV);
        return Buffer.concat([ decipher.update(encryptedKey), decipher.final() ]);
    } catch (_) {
        throw new Error('Unable to unwrap key');
    }
}

function _rsaUnwrap(encryptedKey, alg, jwk) {
    const opts = rsaAlgOpts[alg];
    if (! opts) {
        throw new Error('Invalid RSA algorithm');
    }
    if (! (jwk && (jwk?.kty === 'RSA'))) {
        throw new Error('Invalid JWK key for RSA decryption');
    }
    try {
        const privateKey = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
        return crypto.privateDecrypt({ key: privateKey, ...opts }, encryptedKey);
    } catch (_) {
        throw new Error('Unable to decrypt RSA-encrypted key');
    }
}

function _uint32be(n) {
    const r = Buffer.alloc(4);
    r.writeUInt32BE(n);
    return r;
}

module.exports = { encrypt, decrypt, unwrap };
