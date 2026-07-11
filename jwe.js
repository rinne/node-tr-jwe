'use strict';

const crypto = require('node:crypto');
const zlib = require("node:zlib");
const { promisify } = require('node:util');

const { cipherKeyGen, cipherKeyGenAsync } = require('tr-jwk');
const { kmac256 } = require('tr-kmac');

const randomBytes = promisify(crypto.randomBytes);
const generateKeyPair = promisify(crypto.generateKeyPair);
const encapsulate = promisify(crypto.encapsulate);
const decapsulate = promisify(crypto.decapsulate);
const deflateRaw = promisify(zlib.deflateRaw);
const inflateRaw = promisify(zlib.inflateRaw);

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

// ML-KEM direct key encapsulation following draft-ietf-jose-pqc-kem-05.
// The algorithm identifiers carry a collision-resistant suffix (RFC 7515
// section 4.1.1) because the draft is not final; the construction is frozen
// at draft-05 semantics for these names regardless of later draft changes.
const mlKemAlgOpts = {
    'ML-KEM-512@spinium.com': { jwkAlg: 'ML-KEM-512', ctLength: 768, enc: 'A256GCM' },
    'ML-KEM-768@spinium.com': { jwkAlg: 'ML-KEM-768', ctLength: 1088, enc: 'A256GCM' },
    'ML-KEM-1024@spinium.com': { jwkAlg: 'ML-KEM-1024', ctLength: 1568, enc: 'A256GCM' }
};

function encrypt(alg, jwk, data, options) {
    const p = _encryptPrelude(alg, jwk, options);
    var headerData = { alg, enc: p.enc }, contentKey, encryptedContentKey;
    switch (p.mode) {
    case 'kw':
        contentKey = Buffer.from(cipherKeyGen(p.enc).k, 'base64url');
        encryptedContentKey = _kwWrapCek(alg, jwk, p.keyBytes, contentKey,
                                         crypto.randomBytes(12), headerData);
        break;
    case 'skw':
        contentKey = Buffer.from(cipherKeyGen(p.enc).k, 'base64url');
        encryptedContentKey = _skwWrapCek(alg, jwk, p.keyBytes, contentKey);
        break;
    case 'rsa':
        contentKey = Buffer.from(cipherKeyGen(p.enc).k, 'base64url');
        encryptedContentKey = _rsaWrapCek(alg, jwk, contentKey);
        break;
    case 'dir':
        contentKey = Buffer.from(jwk.k, 'base64url');
        encryptedContentKey = Buffer.alloc(0);
        break;
    case 'ecdh':
        contentKey = _ecdhCek(p.enc, p.keyBits, p.keyBytes, jwk,
                              crypto.generateKeyPairSync('ec', { namedCurve: jwk.crv }),
                              headerData);
        encryptedContentKey = Buffer.alloc(0);
        break;
    case 'mlkem':
        contentKey = _mlKemCek(alg, p.keyBits, p.keyBytes,
                               crypto.encapsulate(crypto.createPublicKey({ key: jwk, format: 'jwk' })),
                               headerData);
        encryptedContentKey = Buffer.alloc(0);
        break;
    default:
        throw new Error('Internal error');
    }
    _headerKid(headerData, jwk);
    const rawPlaintext = _rawPlaintext(data);
    var plaintext = rawPlaintext;
    if (p.compressOpt === true) {
        plaintext = zlib.deflateRawSync(rawPlaintext);
        headerData.zip = 'DEF';
    } else if (p.compressOpt === 'auto') {
        const deflated = zlib.deflateRawSync(rawPlaintext);
        if (deflated.length < rawPlaintext.length) {
            plaintext = deflated;
            headerData.zip = 'DEF';
        }
    }
    return _encryptFinish(headerData, contentKey, encryptedContentKey,
                          plaintext, crypto.randomBytes(12), p.extendedReturn);
}

async function encryptAsync(alg, jwk, data, options) {
    const p = _encryptPrelude(alg, jwk, options);
    var headerData = { alg, enc: p.enc }, contentKey, encryptedContentKey;
    switch (p.mode) {
    case 'kw':
        contentKey = Buffer.from((await cipherKeyGenAsync(p.enc)).k, 'base64url');
        encryptedContentKey = _kwWrapCek(alg, jwk, p.keyBytes, contentKey,
                                         await randomBytes(12), headerData);
        break;
    case 'skw':
        contentKey = Buffer.from((await cipherKeyGenAsync(p.enc)).k, 'base64url');
        encryptedContentKey = _skwWrapCek(alg, jwk, p.keyBytes, contentKey);
        break;
    case 'rsa':
        contentKey = Buffer.from((await cipherKeyGenAsync(p.enc)).k, 'base64url');
        encryptedContentKey = _rsaWrapCek(alg, jwk, contentKey);
        break;
    case 'dir':
        contentKey = Buffer.from(jwk.k, 'base64url');
        encryptedContentKey = Buffer.alloc(0);
        break;
    case 'ecdh':
        contentKey = _ecdhCek(p.enc, p.keyBits, p.keyBytes, jwk,
                              await generateKeyPair('ec', { namedCurve: jwk.crv }),
                              headerData);
        encryptedContentKey = Buffer.alloc(0);
        break;
    case 'mlkem':
        contentKey = _mlKemCek(alg, p.keyBits, p.keyBytes,
                               await encapsulate(crypto.createPublicKey({ key: jwk, format: 'jwk' })),
                               headerData);
        encryptedContentKey = Buffer.alloc(0);
        break;
    default:
        throw new Error('Internal error');
    }
    _headerKid(headerData, jwk);
    const rawPlaintext = _rawPlaintext(data);
    var plaintext = rawPlaintext;
    if (p.compressOpt === true) {
        plaintext = await deflateRaw(rawPlaintext);
        headerData.zip = 'DEF';
    } else if (p.compressOpt === 'auto') {
        const deflated = await deflateRaw(rawPlaintext);
        if (deflated.length < rawPlaintext.length) {
            plaintext = deflated;
            headerData.zip = 'DEF';
        }
    }
    return _encryptFinish(headerData, contentKey, encryptedContentKey,
                          plaintext, await randomBytes(12), p.extendedReturn);
}

function _encryptPrelude(alg, jwk, options) {
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
    } else if (mlKemAlgOpts[alg]) {
        if (! (jwk && (jwk?.kty === 'AKP') && (jwk?.alg === mlKemAlgOpts[alg].jwkAlg))) {
            throw new Error('Invalid JWK key for ML-KEM');
        }
        mode = 'mlkem';
        enc = mlKemAlgOpts[alg].enc;
        keyBits = encAlgOpts[enc]?.keyLength ?? 0;
        keyBytes = Math.ceil(keyBits / 8);
    }
    if (! (keyBits && keyBytes)) {
        throw new Error('Invalid encryption algorithm');
    }
    return { compressOpt, extendedReturn, mode, enc, keyBits, keyBytes };
}

function _kwWrapCek(alg, jwk, keyBytes, contentKey, kwIv, headerData) {
    if (! [ null, undefined, alg ].includes(jwk.alg)) {
        throw new Error('Invalid JWK key algorithm');
    }
    const kwKey = Buffer.from(jwk.k, 'base64url');
    if (kwKey.length != keyBytes) {
        throw new Error('Invalid JWK key length');
    }
    const kwCipher = crypto.createCipheriv(kwAlgOpts[alg].nodeJsCipherId, kwKey, kwIv);
    const encryptedContentKey = Buffer.concat([kwCipher.update(contentKey), kwCipher.final()]);
    const kwTag = kwCipher.getAuthTag();
    Object.assign(headerData, { iv: kwIv.toString('base64url'),
                                tag: kwTag.toString('base64url') });
    return encryptedContentKey;
}

function _skwWrapCek(alg, jwk, keyBytes, contentKey) {
    if (! [ null, undefined, alg ].includes(jwk.alg)) {
        throw new Error('Invalid JWK key algorithm');
    }
    const skwKey = Buffer.from(jwk.k, 'base64url');
    if (skwKey.length != keyBytes) {
        throw new Error('Invalid JWK key length');
    }
    const skwCipher = crypto.createCipheriv(simpleKwAlgOpts[alg].nodeJsCipherId, skwKey, AES_KW_IV);
    return Buffer.concat([skwCipher.update(contentKey), skwCipher.final()]);
}

function _rsaWrapCek(alg, jwk, contentKey) {
    const rsaOpts = rsaAlgOpts[alg];
    const rsaPubKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    return crypto.publicEncrypt({ key: rsaPubKey, ...rsaOpts }, contentKey);
}

function _ecdhCek(enc, keyBits, keyBytes, jwk, ephemeralKeys, headerData) {
    const recipientKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    const sharedSecret = crypto.diffieHellman({ privateKey: ephemeralKeys.privateKey,
                                                publicKey: recipientKey });
    const epk = ephemeralKeys.publicKey.export({ format: 'jwk' });
    const otherInfo = _ecdhOtherInfo(enc, keyBits);
    const contentKey = crypto.createHash('sha256')
        .update(_uint32be(1))
        .update(sharedSecret)
        .update(otherInfo)
        .digest()
        .subarray(0, keyBytes);
    Object.assign(headerData, { epk });
    return contentKey;
}

function _mlKemCek(alg, keyBits, keyBytes, encapsulation, headerData) {
    Object.assign(headerData, { ek: encapsulation.ciphertext.toString('base64url') });
    return _mlKemKdf(alg, keyBits, keyBytes, encapsulation.sharedKey);
}

function _mlKemKdf(alg, keyBits, keyBytes, sharedKey) {
    // draft-ietf-jose-pqc-kem-05: CEK = KMAC256(SS, AlgorithmID || SuppPubInfo,
    // keydatalen, "") with AlgorithmID (the literal "alg" value) and SuppPubInfo
    // encoded as in RFC 7518 section 4.6.2.
    const algBytes = Buffer.from(alg, 'ascii');
    return kmac256(sharedKey,
                   Buffer.concat([ _uint32be(algBytes.length), algBytes, _uint32be(keyBits) ]),
                   keyBytes);
}

function _isMlKem(t) {
    // The enc is pinned: the frozen construction always uses the fixed
    // content encryption of the algorithm (A256GCM), so anything else
    // in the header is malformed and rejected up front.
    return !! (mlKemAlgOpts[t.headerData?.alg] &&
               (t.headerData?.enc === mlKemAlgOpts[t.headerData?.alg].enc) &&
               (t.key.length === 0) &&
               (typeof t.headerData?.ek === 'string') &&
               /^[0-9a-zA-Z_-]+$/.test(t.headerData.ek));
}

function _mlKemPrep(t, jwk) {
    const alg = t.headerData.alg;
    if (! (jwk && (jwk?.kty === 'AKP') && (jwk?.alg === mlKemAlgOpts[alg].jwkAlg))) {
        throw new Error('Invalid JWK key for ML-KEM');
    }
    const ct = Buffer.from(t.headerData.ek, 'base64url');
    if (ct.length !== mlKemAlgOpts[alg].ctLength) {
        throw new Error('Invalid ML-KEM ciphertext');
    }
    const keyBits = encAlgOpts[t.headerData.enc].keyLength;
    return { alg,
             privateKey: crypto.createPrivateKey({ key: jwk, format: 'jwk' }),
             ct,
             keyBits,
             keyBytes: Math.ceil(keyBits / 8) };
}

function _headerKid(headerData, jwk) {
    if (jwk.kid && (typeof(jwk.kid) === 'string')) {
        headerData.kid = jwk.kid;
    } else if (! [ null, undefined, '' ].includes(jwk.kid)) {
        throw new Error('Invalid JWK key identifier');
    }
}

function _rawPlaintext(data) {
    // RFC 7516 places no restriction on the plaintext content; tr-jwe carries
    // any JSON-serialisable value (object, array, string, number, boolean,
    // or null). JSON.stringify(undefined) yields `undefined`, which is not a
    // valid JSON value — reject that case explicitly.
    const rawJson = JSON.stringify(data);
    if (typeof rawJson !== 'string') {
        throw new Error('Invalid input data');
    }
    return Buffer.from(rawJson);
}

function _encryptFinish(headerData, contentKey, encryptedContentKey, plaintext, iv, extendedReturn) {
    const header = Buffer.from(JSON.stringify(headerData)).toString('base64url');
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
        const key = _recoverCek(t, jwk);
        plaintext = _dec(t.ciphertext,
                         { kty: 'oct',
                           alg: t.headerData.enc,
                           k: key.toString('base64url') },
                         t.iv,
                         t.tag,
                         t.header);
        if (t.headerData.zip === 'DEF') {
            plaintext = zlib.inflateRawSync(plaintext);
        }
    } catch (_) {
        plaintext = undefined;
    }
    if (! plaintext) {
        // Just try if the submitted key happens to be content key instead.
        try {
            plaintext = _dec(t.ciphertext, jwk, t.iv, t.tag, t.header);
            if (t.headerData.zip === 'DEF') {
                plaintext = zlib.inflateRawSync(plaintext);
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

async function decryptAsync(token, jwk) {
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
        const key = await _recoverCekAsync(t, jwk);
        plaintext = _dec(t.ciphertext,
                         { kty: 'oct',
                           alg: t.headerData.enc,
                           k: key.toString('base64url') },
                         t.iv,
                         t.tag,
                         t.header);
        if (t.headerData.zip === 'DEF') {
            plaintext = await inflateRaw(plaintext);
        }
    } catch (_) {
        plaintext = undefined;
    }
    if (! plaintext) {
        // Just try if the submitted key happens to be content key instead.
        try {
            plaintext = _dec(t.ciphertext, jwk, t.iv, t.tag, t.header);
            if (t.headerData.zip === 'DEF') {
                plaintext = await inflateRaw(plaintext);
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
        const key = _recoverCek(t, jwk);
        const wrappedJwk = { kty: 'oct',
                             alg: t.headerData.enc,
                             k: key.toString('base64url'),
                             key_ops: [ 'encrypt', 'decrypt' ] };
        return wrappedJwk;
    } catch (_) {
        throw new Error('Unable to unwrap JWE wrapped key');
    }
}

async function unwrapAsync(token, jwk) {
    const t = parse(token);
    const enc = t.headerData?.enc;
    if (! encAlgOpts[enc]) {
        throw new Error('Invalid token encryption');
    }
    try {
        const key = await _recoverCekAsync(t, jwk);
        const wrappedJwk = { kty: 'oct',
                             alg: t.headerData.enc,
                             k: key.toString('base64url'),
                             key_ops: [ 'encrypt', 'decrypt' ] };
        return wrappedJwk;
    } catch (_) {
        throw new Error('Unable to unwrap JWE wrapped key');
    }
}

function _recoverCek(t, jwk) {
    if ((kwAlgOpts[t.headerData?.alg] &&
         encAlgOpts[t.headerData?.enc] &&
         /^[0-9a-zA-Z_-]{2,}$/.test(t.headerData?.iv) &&
         /^[0-9a-zA-Z_-]{2,}$/.test(t.headerData?.tag))) {
        return _dec(t.key,
                    jwk,
                    Buffer.from(t.headerData.iv, 'base64url'),
                    Buffer.from(t.headerData.tag, 'base64url'));
    } else if ((simpleKwAlgOpts[t.headerData?.alg] &&
                encAlgOpts[t.headerData?.enc] &&
                (t.key.length > 0))) {
        return _simpleKwUnwrap(t.key, t.headerData.alg, jwk);
    } else if ((rsaAlgOpts[t.headerData?.alg] &&
                encAlgOpts[t.headerData?.enc] &&
                (t.key.length > 0))) {
        return _rsaUnwrap(t.key, t.headerData.alg, jwk);
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
        return dirKey;
    } else if ((t.headerData?.alg === 'ECDH-ES') &&
               encAlgOpts[t.headerData?.enc] &&
               (t.key.length === 0) &&
               (t.headerData?.epk?.kty === 'EC') &&
               ecdhCurveOpts[t.headerData?.epk?.crv]) {
        return _ecdhKey(t.headerData.enc, t.headerData.epk, jwk, t.headerData.apu, t.headerData.apv);
    } else if (_isMlKem(t)) {
        const m = _mlKemPrep(t, jwk);
        return _mlKemKdf(m.alg, m.keyBits, m.keyBytes, crypto.decapsulate(m.privateKey, m.ct));
    }
    throw new Error('Invalid token encryption');
}

async function _recoverCekAsync(t, jwk) {
    if (_isMlKem(t)) {
        const m = _mlKemPrep(t, jwk);
        return _mlKemKdf(m.alg, m.keyBits, m.keyBytes, await decapsulate(m.privateKey, m.ct));
    }
    return _recoverCek(t, jwk);
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

module.exports = { encrypt, encryptAsync, decrypt, decryptAsync, unwrap, unwrapAsync };
