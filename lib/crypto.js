/*!
 * pk.js - public key algorithms for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const bcrypto = require('@hansekontor/checkout-components').bcrypto;
const {
  SHA224,
  SHA256, 
  SHA384,
  SHA512,
  rsa, 
  p224,
  p256,
  p384,
  p521 
} = bcrypto;

/**
 * Verify signature with public key.
 * @param {String} alg - Hash algorithm.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Object} key
 * @returns {Boolean}
 */

exports.verify = function verify(alg, msg, sig, key) {
  const hash = getHash(alg);

  if (!hash)
    return false;

  switch (key.alg) {
    case 'rsa': {
      return rsa.verify(hash, hash.digest(msg), sig, key.data);
    }

    case 'ecdsa': {
      const ec = getCurve(key.curve);

      if (!ec)
        return false;

      return ec.verifyDER(hash.digest(msg), sig, key.data);
    }

    default: {
      throw new Error(`Unsupported algorithm: ${key.alg}.`);
    }
  }
};

/**
 * Sign message with private key.
 * @param {String} alg - Hash algorithm.
 * @param {Buffer} msg
 * @param {Object} key
 * @returns {Buffer}
 */

exports.sign = function sign(alg, msg, key) {
  const hash = getHash(alg);

  if (!hash)
    throw new Error(`Unsupported hash algorithm: ${alg}.`);

  switch (key.alg) {
    case 'rsa': {
      return rsa.sign(hash, hash.digest(msg), key.data);
    }

    case 'ecdsa': {
      const ec = getCurve(key.curve);

      if (!ec)
        throw new Error(`Unsupported curve: ${key.curve}.`);

      return ec.signDER(hash.digest(msg), key.data);
    }

    default: {
      throw new Error(`Unsupported algorithm: ${key.alg}.`);
    }
  }
};

/*
 * Helpers
 */

function getHash(alg) {
  assert(typeof alg === 'string');
  switch (alg) {
    case 'sha224':
      return SHA224;
    case 'sha256':
      return SHA256;
    case 'sha384':
      return SHA384;
    case 'sha512':
      return SHA512;
    default:
      return null;
  }
}

function getCurve(curve) {
  assert(typeof curve === 'string');
  switch (curve) {
    case 'p224':
      return p224;
    case 'p256':
      return p256;
    case 'p384':
      return p384;
    case 'p521':
      return p521;
    default:
      return null;
  }
}
