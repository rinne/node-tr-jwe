'use strict';

const verbose = [ 'Y', 'YES' ].includes(process.env.VERBOSE);

const assert = require('node:assert/strict');

const crypto = require('node:crypto');

const { encrypt, decrypt, unwrap } = require('..');
const { cipherKeyGen, ecKeyGen, macKeyGen } = require('tr-jwk');

const payload = { kukkuu: 'reset' };

function parseHeader(token) {
    const t = token.split('.');
    assert.equal(t.length, 5);
    assert.ok(t.every((x) => /^[0-9a-zA-Z_-]*$/.test(x)));
    return JSON.parse(Buffer.from(t[0], 'base64url').toString('utf8'));
}

function expectedZip(compressOpt) {
    if (compressOpt === true) {
        return 'DEF';
    }
    if (compressOpt === 'auto') {
        // The tiny test payload deflates larger than the original, so 'auto' must skip compression.
        return undefined;
    }
    return undefined;
}

function verboseOutput(header, token, key, ck, vk) {
    if (verbose) {
        console.log('Header: ' + JSON.stringify(header));
        console.log('Encrypted token: ' + token);
        console.log('Encryption key: ' + JSON.stringify(key));
        console.log('Content encryption key: ' + JSON.stringify(ck));
        if (vk !== undefined) {
            console.log('Verification key: ' + JSON.stringify(vk));
        }
    }
}

function testKw(alg, compressPayload) {
    const k = cipherKeyGen(alg);
    const token = encrypt(k.alg, k, payload, { compressPayload });
    const header = parseHeader(token);

    assert.equal(header.alg, alg);
    assert.equal(header.zip, expectedZip(compressPayload));
    assert.match(header.iv, /^[0-9a-zA-Z_-]+$/);
    assert.match(header.tag, /^[0-9a-zA-Z_-]+$/);
    assert.deepEqual(decrypt(token, k), payload);

    const ck = unwrap(token, k);
    verboseOutput(header, token, k, ck);
    assert.deepEqual(decrypt(token, ck), payload);
    assert.equal(ck.alg, header.enc);
}

function testEcdh(crv, enc, compressPayload) {
    const k = ecKeyGen(crv);
    const token = encrypt('ECDH-ES', k.publicKey, payload, { compressPayload });
    const parts = token.split('.');
    const header = parseHeader(token);

    assert.equal(header.alg, 'ECDH-ES');
    assert.equal(header.enc, enc);
    assert.equal(header.zip, expectedZip(compressPayload));
    assert.equal(parts[1], '');
    assert.equal(header.epk.kty, 'EC');
    assert.equal(header.epk.crv, crv);
    assert.match(header.epk.x, /^[0-9a-zA-Z_-]+$/);
    assert.match(header.epk.y, /^[0-9a-zA-Z_-]+$/);
    assert.deepEqual(decrypt(token, k.secretKey), payload);

    const ck = unwrap(token, k.secretKey);
    verboseOutput(header, token, k.publicKey, ck, k.secretKey);
    assert.deepEqual(decrypt(token, ck), payload);
    assert.equal(ck.alg, header.enc);
}

function toPublicJwk(jwk) {
    const { d, p, q, dp, dq, qi, ...pub } = jwk;
    return pub;
}

function testSimpleKw(alg, compressPayload) {
    const keyLengths = { A128KW: 16, A192KW: 24, A256KW: 32 };
    const keyBytes = keyLengths[alg];
    const k = { kty: 'oct', alg, k: crypto.randomBytes(keyBytes).toString('base64url') };
    const token = encrypt(alg, k, payload, { compressPayload });
    const header = parseHeader(token);

    assert.equal(header.alg, alg);
    assert.equal(header.zip, expectedZip(compressPayload));
    assert.equal(header.iv, undefined);
    assert.equal(header.tag, undefined);
    assert.deepEqual(decrypt(token, k), payload);

    const ck = unwrap(token, k);
    verboseOutput(header, token, k, ck);
    assert.deepEqual(decrypt(token, ck), payload);
    assert.equal(ck.alg, header.enc);
}

function testRsa(alg, modulusLength, expectedEnc, compressPayload) {
    const rsaAlgForGen = modulusLength <= 1024 ? 'RS256' : (modulusLength <= 2048 ? 'RS384' : 'RS512');
    const privJwk = macKeyGen(rsaAlgForGen);
    const pubJwk = toPublicJwk(privJwk);
    const token = encrypt(alg, pubJwk, payload, { compressPayload });
    const header = parseHeader(token);

    assert.equal(header.alg, alg);
    assert.equal(header.enc, expectedEnc);
    assert.equal(header.zip, expectedZip(compressPayload));
    assert.deepEqual(decrypt(token, privJwk), payload);

    const ck = unwrap(token, privJwk);
    verboseOutput(header, token, pubJwk, ck, privJwk);
    assert.deepEqual(decrypt(token, ck), payload);
    assert.equal(ck.alg, header.enc);
}

function testDir(keyBytes, expectedEnc, compressPayload) {
    const k = { kty: 'oct', k: crypto.randomBytes(keyBytes).toString('base64url') };
    const token = encrypt('dir', k, payload, { compressPayload });
    const header = parseHeader(token);

    assert.equal(header.alg, 'dir');
    assert.equal(header.enc, expectedEnc);
    assert.equal(header.zip, expectedZip(compressPayload));
    assert.equal(token.split('.')[1], '');
    assert.deepEqual(decrypt(token, k), payload);

    const ck = unwrap(token, k);
    verboseOutput(header, token, k, ck);
    assert.deepEqual(decrypt(token, ck), payload);
    assert.equal(ck.alg, expectedEnc);
    assert.equal(ck.k, k.k);
}

[ true, false, 'auto' ].forEach((compressPayload) => {
    [ 'A128GCMKW', 'A192GCMKW', 'A256GCMKW' ].forEach((alg) => testKw(alg, compressPayload));

    [ 'A128KW', 'A192KW', 'A256KW' ].forEach((alg) => testSimpleKw(alg, compressPayload));

    [ [ 16, 'A128GCM' ],
      [ 24, 'A192GCM' ],
      [ 32, 'A256GCM' ] ].forEach((x) => testDir(...x, compressPayload));

    [ [ 'P-256', 'A128GCM' ],
      [ 'P-384', 'A192GCM' ],
      [ 'P-521', 'A256GCM' ] ].forEach((x) => testEcdh(...x, compressPayload));

    [ 'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256' ].forEach((alg) => {
        testRsa(alg, 1024, 'A128GCM', compressPayload);
        testRsa(alg, 2048, 'A256GCM', compressPayload);
    });
});

// 'auto' must actually compress when the payload is highly compressible.
(function autoChoosesCompression() {
    const big = { blob: 'a'.repeat(4096) };
    const k = cipherKeyGen('A256GCMKW');
    const token = encrypt('A256GCMKW', k, big, { compressPayload: 'auto' });
    assert.equal(parseHeader(token).zip, 'DEF');
    assert.deepEqual(decrypt(token, k), big);
})();

// 'auto' must skip compression when the payload deflates larger.
(function autoSkipsCompression() {
    const k = cipherKeyGen('A256GCMKW');
    const token = encrypt('A256GCMKW', k, { x: 1 }, { compressPayload: 'auto' });
    assert.equal(parseHeader(token).zip, undefined);
})();

// extendedReturn must produce { token, contentEncryptionKey } that decrypts standalone.
(function extendedReturnRoundTrips() {
    const cases = [
        () => ({ key: cipherKeyGen('A256GCMKW'), alg: 'A256GCMKW' }),
        () => ({ key: { kty: 'oct', alg: 'A256KW',
                        k: crypto.randomBytes(32).toString('base64url') },
                 alg: 'A256KW' }),
        () => {
            const priv = macKeyGen('RS384');
            return { key: toPublicJwk(priv), alg: 'RSA-OAEP-256', recovery: priv };
        },
        () => {
            const ec = ecKeyGen('P-256');
            return { key: ec.publicKey, alg: 'ECDH-ES', recovery: ec.secretKey };
        },
        () => {
            const dirKey = { kty: 'oct', k: crypto.randomBytes(32).toString('base64url') };
            return { key: dirKey, alg: 'dir' };
        }
    ];
    for (const make of cases) {
        const { key, alg, recovery } = make();
        const r = encrypt(alg, key, payload, { extendedReturn: true });
        assert.equal(typeof r, 'object');
        assert.equal(typeof r.token, 'string');
        assert.equal(r.contentEncryptionKey.kty, 'oct');
        assert.equal(r.contentEncryptionKey.alg, parseHeader(r.token).enc);
        // Decrypt with just the CEK — no access to the wrapping key.
        assert.deepEqual(decrypt(r.token, r.contentEncryptionKey), payload);
        // And — when applicable — also with the original recipient key.
        if (recovery) {
            assert.deepEqual(decrypt(r.token, recovery), payload);
        } else if (alg !== 'ECDH-ES' && alg !== 'RSA-OAEP-256') {
            assert.deepEqual(decrypt(r.token, key), payload);
        }
    }
})();

// Bad options must throw.
(function rejectsBadOptions() {
    const k = cipherKeyGen('A256GCMKW');
    assert.throws(() => encrypt('A256GCMKW', k, payload, 'nope'), /Invalid options/);
    assert.throws(() => encrypt('A256GCMKW', k, payload, { unknown: 1 }), /Unknown option/);
    assert.throws(() => encrypt('A256GCMKW', k, payload, { compressPayload: 'sometimes' }), /Invalid compressPayload/);
    assert.throws(() => encrypt('A256GCMKW', k, payload, { extendedReturn: 'yes' }), /Invalid extendedReturn/);
})();

console.log('JWE tests passed');
