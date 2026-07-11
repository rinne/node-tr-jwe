'use strict';

const verbose = [ 'Y', 'YES' ].includes(process.env.VERBOSE);

const assert = require('node:assert/strict');

const crypto = require('node:crypto');

const { encrypt, encryptAsync, decrypt, decryptAsync, unwrap, unwrapAsync } = require('..');
const { cipherKeyGen, ecKeyGen, macKeyGen, mlKemKeyGen } = require('tr-jwk');
const { kmac256 } = require('tr-kmac');

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

const mlKemPinnedKey = {"priv":"89X6HWRdPGriWTZ6IQZFt9SHF_5aa5k4HQXVC9Pl4WmgerdQsCMPAKTEniqEwOQdne5ghuVMM7iDe0gf2umPsQ","kty":"AKP","alg":"ML-KEM-768","pub":"-TCOsJgLnmSoObhcoUvKPcNGhGMvLlaol6m2ypaCD_SkoLeglSgbRKdmLPQWxcy_CxHNIMfDl7FlOhsAItRxTwwoUkKtCXAkkEyCCLxef8YH48x4HQNfJpeuR9w7MoW776NFGLER0eXFmQUq9lEtKOWPoXR1K8fC8rwxbUp87MnFPnYceMSkuouY-FRW2ASWB0m8eKO_w9d7YRm26AsNQiB3Y3EWhVoJGtGBQuUarSo4-ncnwGIsuUeLckrNQTYiOjsQzdtIk4odECey4dIDH6K0I3Gfe7it5-cbGDOGv7OJXzh4R3djDCCa7MASwGcG7XHCzzcqM-NQh9KotcofiEwxaxSDLZkAkxMo24uTR0YfXEs9ADWTn9Yj5wwp2ZRFagiNpaVa27NQ6dWBcok7tGqkD6tMEmUrFMFV_wUW-Dm-hcG3q2Z8AOSOFxZajst0GnpZmipBKRUOUeBdWMNCg4LPKgYEUVmXcudW1YpoGzY1UCvAcpJ7NOI38Icd2TUXKIEVatqfoBdCmJUqCBfJich_2MeU4fYKG9lrAP3DVPZkPMdOHXV22oUT5Pe8S7uMuchAxOYu9KE4KDYpa1V0E4BmwAxxKxsPcDFUtaDDzYdHCXDJvuMSZEVm6SQRsraWrpmBHmALiqyD1qi91Ayi1YxnERJNkyC8b_NDHQRGLeohvRgeN7kGenMJnpjJF5dtdiIjiuiavGu1ziOpLYIBvQFws5U53wolUvVdktG5t_xie9pMAHNZunCu2sVx5yjKhOOViKK-AVfAEIQa7awtXVWWACMLhtRWdWohNgI1K5mRYtskrmYcmapwA0tgsItYXxhOTPOY_hNAcHhLfNdAIiyz9NsVrrtzh1y9FrVUvUQMKPG5RJe_0KQXj6NQb9BEziXPcoBE2NoWO1kWacAWR0wjmIYAxod-OzOuCnYL6alsSzgegHOyc0cYJAfKK5UKW3SYclMICSnPHOO9zbpjhGiyh6uWbSgEnfAeuiVALVl3RIKv_imt8SqUuojDgOKWoLoUxZK7stlZqwxh_Gphbxi5X3Om0Pgjr0C19RKhtEIFrdClUuWlsImXtLZV58EhqCmIacYExuJXlCF5_cA4abQdH5wWwJK_Xutrs7s2HHpGTaFuffqWk3dX2Gt1_IHJrYrKM7W7WGVi5yEzs0kIYuohH5oRitMkROF88ymCKLSv2fwi4fmRKHlb51wFVOms_AbNujB5GttSs2MreDZs2vCTDXR6x5VwatovCzxxB5RzsyfKisq-abpx5DuFzvLNwuez-lMPZPsSgFESYOU-VnhIUgSYkoOHXAGjt9q3ZZA60Pkm5mkN3zyiYneM0YfMzBVCl5EvFrMPuyK5hIGujfRighFfiFQJLWmFg_QojXhDtsMAljQyWPmKSPY0MvN85Fak_sUKuxdeBIUwwZoa4sUzADFittMLchQj8cmjXpOu-yBesjVQuQwKgeFd9xZdJIp8gFop7ZitTbc4EnmlENMoPlDJ6EhZSmdECziOO6GgBxG3svyyNjKtgWkRb2B8qoPM1MSZaSREOR_laObLHory12CRSglb10OU6XgvB7A"};

const mlKemPinnedToken = (
    'eyJhbGciOiJNTC1LRU0tNzY4QHNwaW5pdW0uY29tIiwiZW5jIjoiQTI1NkdDTSIsImVrIjoiZTht' +
    'LWhHYjJTSko5SU9xM0JkQ2J1WUIxMTdKMjVOTm9QVTF6SnA3T3Z6ZzQxa1FWdDF3bE9YYUJybmJD' +
    'NjFtYzlINDZJV003bFNUYW5DbmVSTU1GVHZDN09fRGpQdm9TMmgxWXpCN2p3TjZxUjZqMTBFSXZR' +
    'VVZOUGpOcTJ2VUhheW02ckhGU2loU0lnU1FfeWs2VjdFd1pQcS04cEU1OWRTd3lkRmRKck5sbkhU' +
    'NnNqNUxwUmdKQzJRSnJVTmRKSU9vb2Ric2ZtOV92LWgtTEtJOHk2N3gxbWllREtBcVY5c2VXSlVN' +
    'dVNSTThYSGE3SGpaTGdZc0xsMk1Ydk9CeHNTcmwtVkh5NFUxWjBwWERXZlpyQVo5RllfNDUxS09K' +
    'WkJGVHBBMnZtcV83ek8wRVQxNjU5bFdsTVJFbHVTcUFFNGhodGZHS3JYVFEyUXJfM1NvbEFyaW1I' +
    'MURHb0dMM3Y4dng4ZzMxTVdPMXQ3dXRyY3hQR2l5ODVZWkZxdUkxbGVqVkUxeTl6LWhMR19SV2l3' +
    'MGNOQkxvNF9ndWN0YTFXSTJKdTktRXozNER0TzczdXJiWHJac3ZrRExfSUJrQ3RKaGxmWGFxUldt' +
    'cVBqY244WWRZZFhSMUxEVDFQeG1ZZGlURFJiX0kyTlVydU9abHJZT2hMU1FTZ1gzMy1TbkU1UGFv' +
    'd3hxWEFYcWZRNkpWYk1NMHlYaXVKVmlKYWhEcnRzLU9iUS16bVlqZ0NaOG0yenYzVmVQZkVTYXN1' +
    'bl9ldS10a0dkb2ZjSVgwOC0yWDdVbjFKeGw0NE5GQkxwY1k4REFGZ0Ffakh5SG5QR2g0d1FKMzVs' +
    'M1pNSVowMHg0VjlTQjBfWWgyak9aZWhSWDdjZUtJbHZlcktRQk54ZHRhaXJobENJQmtjeVdtMTNl' +
    'ejR0TjhQc0U4MWM0aFhfTllEb1FqdEc2M3hTMm9yTHBxTEpTbzFkNXlOQmtsWFEzekJrSTRwbkVi' +
    'SDNaWFBBMkRSSWFJeGJYYzJCM1kxcl9jS0tvdTlJVURHM2NyQi1KWFNWcnVLRlBqd3pNRmFKUFls' +
    'SXh3NDlKNmp6YkkxT1RTNmNsYnlsWEZBSlFrS1lPQXVaeFQ5Xy14azdvTlgtckhqUnhkTEZtckdo' +
    'UDQ1ZGR2MnRvTWYtVEx3TktoaTlkYWd4a1RaOGNTYVVnN0kwS3dRbEdlQi1zYUpNTDM0S0hjVFhu' +
    'cjFSWEdkTzlNWHhMSTNtejRCc09NRmYyMDU5dHViSFpRVkF4ZWdWT1RUeUhQb2RWVm9EaXUwZmJ4' +
    'by12UnpVOWpZLW9hRHpvcTd5end3Mm1aZlNzSjM2Z0I2MVhYRWhWd0llQ2swejVlVnF5aXhSZElx' +
    'NU9LT2E1cDNUcnEySzI3eUhUY0FaX2ZDN2lRT0dCN3NMYXlOeE5ERWZ5U2twTExHcjVrYmFxSlZu' +
    'YTZnNUNVVFAxRDFvZVJSNW43ZUZ4U2pvNVFMSU1ZVk96Z3JCV3FzOHhDcjVQZ3ZrM05mVjRJU0Ny' +
    'Um5HcFRzamwxTGItaURrR05qSlEwSE42NWU4ai13ZFctVlM5VE1KQVRlbGlpSF9SaGxOSk5hOEwx' +
    'eWRBR0s0Q0oyWTZtdkVJSWJkbU9aTmlYY2laYk9LSkRFclR0NFNIR0ZPYkU5cUFhdlhuNUpmQ1Zo' +
    'Umx6cXhudTQ4aW1hTExFUngtWWg3NlVrRHpLMm9IRHZudEpmSHNpeTRXendqcmN5c0ZQVDdIZXd3' +
    'dnRsdTNzT3BPNzhEbDJwQW5xWE9pYXlNMlNVcVpYT2FSQzl5VUFFalp1VVJjTjBySl93MF9qaHdQ' +
    'bHE4Z01QaFBJT2w3LWRHNmE0dE9fY1piamJhTXhVVEhwd3JSUVhuaGl2anE3eXJrZTI4X3FQMFJj' +
    'eFpDc01nV25QREdmUmc4eVVRMkNoVEEifQ..BLlUWTthZKebwY0k.1EGIOCfU6hAHqKJ3aR-ihPo' +
    'pBGePO5LvqQ._0_PH-wjRqeDlCUyzUnFFw');

const mlKemCtLengths = { 'ML-KEM-512': 768, 'ML-KEM-768': 1088, 'ML-KEM-1024': 1568 };
const mlKemVariants = Object.keys(mlKemCtLengths);

function testMlKem(variant, compressPayload) {
    const alg = variant + '@spinium.com';
    const kp = mlKemKeyGen(variant);
    const token = encrypt(alg, kp.publicKey, payload, { compressPayload });
    const parts = token.split('.');
    const header = parseHeader(token);

    assert.equal(header.alg, alg);
    assert.equal(header.enc, 'A256GCM');
    assert.equal(header.zip, expectedZip(compressPayload));
    assert.equal(parts[1], '');
    assert.match(header.ek, /^[0-9a-zA-Z_-]+$/);
    assert.equal(Buffer.from(header.ek, 'base64url').length, mlKemCtLengths[variant]);
    assert.equal(header.kid, kp.publicKey.kid);
    assert.deepEqual(decrypt(token, kp.secretKey), payload);

    const ck = unwrap(token, kp.secretKey);
    verboseOutput(header, token, kp.publicKey, ck, kp.secretKey);
    assert.deepEqual(decrypt(token, ck), payload);
    assert.equal(ck.alg, 'A256GCM');

    // The private JWK is acceptable for encryption as well.
    assert.deepEqual(decrypt(encrypt(alg, kp.secretKey, payload), kp.secretKey), payload);

    // Wrong recipient key fails generically. ML-KEM implicit rejection makes
    // decapsulation "succeed" with an unrelated shared key, so (as with
    // ECDH-ES) unwrap returns a wrong CEK and only the GCM tag check fails.
    const kp2 = mlKemKeyGen(variant);
    assert.throws(() => decrypt(token, kp2.secretKey), /Unable to decrypt/);
    assert.throws(() => decrypt(token, unwrap(token, kp2.secretKey)), /Unable to decrypt/);

    // Tampered and truncated KEM ciphertexts fail generically.
    const headerData = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    for (const badEk of [ (headerData.ek[0] === 'A' ? 'B' : 'A') + headerData.ek.slice(1),
                          headerData.ek.slice(0, -4) ]) {
        const badHeader = Buffer.from(JSON.stringify({ ...headerData, ek: badEk })).toString('base64url');
        const badToken = [ badHeader, ...parts.slice(1) ].join('.');
        assert.throws(() => decrypt(badToken, kp.secretKey), /Unable to decrypt/);
    }
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

    mlKemVariants.forEach((variant) => testMlKem(variant, compressPayload));
});

// ML-KEM key/algorithm mismatches must throw on encrypt; the unsuffixed
// draft algorithm names are not implemented.
(function mlKemRejectsBadKeys() {
    const kp = mlKemKeyGen('ML-KEM-768');
    assert.throws(() => encrypt('ML-KEM-512@spinium.com', kp.publicKey, payload), /Invalid JWK key for ML-KEM/);
    assert.throws(() => encrypt('ML-KEM-768@spinium.com', ecKeyGen('P-256').publicKey, payload), /Invalid JWK key for ML-KEM/);
    assert.throws(() => encrypt('ML-KEM-768', kp.publicKey, payload), /Invalid encryption algorithm/);
})();

// The CEK derivation is frozen at draft-ietf-jose-pqc-kem-05 semantics:
// CEK = KMAC256(sharedKey, AlgorithmID || SuppPubInfo, keydatalen, "") with
// RFC 7518 section 4.6.2 encodings and the literal alg value as AlgorithmID.
// Recompute it here from the primitives, independently of jwe.js internals.
(function mlKemKdfIsDraft05() {
    const crypto = require('node:crypto');
    const alg = 'ML-KEM-768@spinium.com';
    const kp = mlKemKeyGen('ML-KEM-768');
    const token = encrypt(alg, kp.publicKey, payload);
    const header = parseHeader(token);
    const sharedKey = crypto.decapsulate(crypto.createPrivateKey({ key: kp.secretKey, format: 'jwk' }),
                                         Buffer.from(header.ek, 'base64url'));
    const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
    const cek = kmac256(sharedKey,
                        Buffer.concat([ u32(alg.length), Buffer.from(alg, 'ascii'), u32(256) ]),
                        32);
    assert.equal(unwrap(token, kp.secretKey).k, cek.toString('base64url'));
})();

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
        },
        () => {
            const kp = mlKemKeyGen('ML-KEM-768');
            return { key: kp.publicKey, alg: 'ML-KEM-768@spinium.com', recovery: kp.secretKey };
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
        assert.equal(r.contentEncryptionKey.k,
                     unwrap(r.token, recovery ?? key).k);
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

// Asynchronous API. Round-trips every key management mode and checks
// sync/async interop in both directions.
async function testAsyncMode(alg, encKey, decKey, compressPayload) {
    const p = encryptAsync(alg, encKey, payload, { compressPayload });
    assert.ok(p instanceof Promise);
    const token = await p;
    const header = parseHeader(token);

    assert.equal(header.alg, alg);
    assert.equal(header.zip, expectedZip(compressPayload));
    assert.deepEqual(await decryptAsync(token, decKey), payload);

    // Sync/async interop in both directions.
    assert.deepEqual(decrypt(token, decKey), payload);
    assert.deepEqual(await decryptAsync(encrypt(alg, encKey, payload, { compressPayload }), decKey),
                     payload);

    const ck = await unwrapAsync(token, decKey);
    assert.equal(ck.alg, header.enc);
    assert.deepEqual(await decryptAsync(token, ck), payload);
    assert.deepEqual(unwrap(token, decKey), ck);
}

(async () => {
    for (const compressPayload of [ true, false, 'auto' ]) {
        for (const alg of [ 'A128GCMKW', 'A192GCMKW', 'A256GCMKW' ]) {
            const k = cipherKeyGen(alg);
            await testAsyncMode(alg, k, k, compressPayload);
        }
        for (const alg of [ 'A128KW', 'A192KW', 'A256KW' ]) {
            const keyBytes = { A128KW: 16, A192KW: 24, A256KW: 32 }[alg];
            const k = { kty: 'oct', alg, k: crypto.randomBytes(keyBytes).toString('base64url') };
            await testAsyncMode(alg, k, k, compressPayload);
        }
        for (const keyBytes of [ 16, 24, 32 ]) {
            const k = { kty: 'oct', k: crypto.randomBytes(keyBytes).toString('base64url') };
            await testAsyncMode('dir', k, k, compressPayload);
        }
        for (const crv of [ 'P-256', 'P-384', 'P-521' ]) {
            const k = ecKeyGen(crv);
            await testAsyncMode('ECDH-ES', k.publicKey, k.secretKey, compressPayload);
        }
        for (const alg of [ 'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256' ]) {
            const priv = macKeyGen('RS384');
            await testAsyncMode(alg, toPublicJwk(priv), priv, compressPayload);
        }
        for (const variant of mlKemVariants) {
            const kp = mlKemKeyGen(variant);
            await testAsyncMode(variant + '@spinium.com', kp.publicKey, kp.secretKey, compressPayload);
        }
    }

    // Pinned ML-KEM decrypt vector. The construction for the @spinium.com
    // algorithm names is frozen; this token must decrypt identically forever.
    {
        assert.deepEqual(decrypt(mlKemPinnedToken, mlKemPinnedKey), { kukkuu: 'reset', n: 42 });
        assert.deepEqual(await decryptAsync(mlKemPinnedToken, mlKemPinnedKey), { kukkuu: 'reset', n: 42 });
        assert.equal(unwrap(mlKemPinnedToken, mlKemPinnedKey).alg, 'A256GCM');
        await assert.rejects(decryptAsync(mlKemPinnedToken, mlKemKeyGen('ML-KEM-768').secretKey),
                             /Unable to decrypt/);
    }

    // 'auto' must compress asynchronously too when it pays off.
    {
        const big = { blob: 'a'.repeat(4096) };
        const k = cipherKeyGen('A256GCMKW');
        const token = await encryptAsync('A256GCMKW', k, big, { compressPayload: 'auto' });
        assert.equal(parseHeader(token).zip, 'DEF');
        assert.deepEqual(await decryptAsync(token, k), big);
    }

    // extendedReturn must work asynchronously.
    {
        const k = cipherKeyGen('A256GCMKW');
        const r = await encryptAsync('A256GCMKW', k, payload, { extendedReturn: true });
        assert.equal(typeof r.token, 'string');
        assert.equal(r.contentEncryptionKey.kty, 'oct');
        assert.equal(r.contentEncryptionKey.alg, parseHeader(r.token).enc);
        assert.deepEqual(await decryptAsync(r.token, r.contentEncryptionKey), payload);
    }

    // Bad input must reject (not throw synchronously).
    {
        const k = cipherKeyGen('A256GCMKW');
        await assert.rejects(encryptAsync('A256GCMKW', k, payload, 'nope'), /Invalid options/);
        await assert.rejects(encryptAsync('A256GCMKW', k, payload, { unknown: 1 }), /Unknown option/);
        await assert.rejects(encryptAsync('A256GCMKW', k, payload, { compressPayload: 'sometimes' }), /Invalid compressPayload/);
        await assert.rejects(encryptAsync('A256GCMKW', k, payload, { extendedReturn: 'yes' }), /Invalid extendedReturn/);
        await assert.rejects(decryptAsync('not-a-token', k), /Invalid JWE token/);
        await assert.rejects(unwrapAsync('not-a-token', k), /Invalid JWE token/);
    }

    console.log('JWE tests passed');
})().catch((e) => {
    console.error(e);
    process.exit(1);
});
