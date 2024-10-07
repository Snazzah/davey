import crypto from 'node:crypto';
import { serializeResolvers } from './serialize';
import { p256 } from '@noble/curves/p256';

const EMPTY_BUFFER = new Uint8Array(0);
const subtle = crypto.webcrypto.subtle;

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-2.1.2 */
export function readVarint(buf: Uint8Array, start: number) {
  let v = buf[start]!;
  const prefix = v >> 6; // first 2 bits of first byte
  if (prefix === 3) throw new Error('Invalid variable length integer prefix');

  const length = 1 << prefix;
  v = v & 0x3f;

  for (let i = 1; i < length; i++) {
    v = (v << 8) + buf[start + i]!;
  }

  if (prefix >= 1 && v < (1 << (8*(length/2) - 2))) {
    throw new Error('Minimum encoding was not used');
  }

  return { offset: length, v };
}


// TODO errors when going over buffer
export class DataCursor {
  index = 0;

  constructor(public length: number, public buffer: Buffer) {}

  move(to: number) {
    this.index += to;
    return this.ended;
  }

  get lengthLeft() {
    return this.length - (this.index + 1);
  }

  get ended() {
    return this.index >= this.length;
  }

  readVector() {
    const { offset, v } = readVarint(this.buffer, this.index);
    const result = this.buffer.subarray(this.index + offset, this.index + offset + v);
    this.move(offset + v);
    return result;
  }

  readU8() {
    const result = this.buffer.readUInt8(this.index);
    this.move(1);
    return result;
  }

  readU16() {
    const result = this.buffer.readUInt16BE(this.index);
    this.move(2);
    return result;
  }

  readU32() {
    const result = this.buffer.readUInt32BE(this.index);
    this.move(4);
    return result;
  }

  readU64() {
    const result = this.buffer.readBigUInt64BE(this.index);
    this.move(8);
    return result;
  }
}

enum PKCS8Type {
  OCTET_STRING = 0x04,
  PARAMETERS = 0xA0,
  SEQUENCE = 0x30
}
const OID_EC_PUBLIC_KEY = Buffer.from([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);
const OID_P_256 = Buffer.from([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);

// FIXME: this is formatted wrong, but node still handles it properly
export function rawToPKCS8(rawKey: Uint8Array) {
  function vectorHeaderLength(length: number) {
    if (length >= 0x10000) throw new Error('Buffer length too long');
    return length < 0x80 ? 1 : length < 0x100 ? 2 : 3;
  }

  function vector(type: PKCS8Type, buffer: Uint8Array) {
    const length = buffer.length;
    const headerLength = vectorHeaderLength(length);
    const result = Buffer.alloc(headerLength + 1 + length);
    result[0] = type;
    if (headerLength < 0x80) {
      result[1] = length;
    } else if (headerLength < 0x100) {
      result[1] = 0x81;
      result[2] = length;
    } else if (headerLength < 0x10000) {
      result[1] = 0x82;
      result[2] = length >> 8;
      result[3] = length & 0xFF;
    };
    result.set(buffer, headerLength + 1)
    return result;
  }


  const ecPrivKey = vector(
    PKCS8Type.SEQUENCE, 
    Buffer.concat([
      Buffer.from([0x02, 0x01, 0x01]),    // version (integer, 1)
      vector(PKCS8Type.OCTET_STRING, rawKey),  // raw private key
      vector(PKCS8Type.PARAMETERS, OID_P_256), // curve OID as parameters
    ])
  );

  const formattedKey = vector(
    PKCS8Type.SEQUENCE,
    Buffer.concat([
      Buffer.from([0x02, 0x01, 0x01]),    // version (integer, 0)
      vector(PKCS8Type.SEQUENCE, Buffer.concat([
        OID_EC_PUBLIC_KEY, // algo OID
        OID_P_256          // curve OID
      ])),
      vector(PKCS8Type.OCTET_STRING, ecPrivKey), // key
    ])
  );

  return formattedKey;
}

export type HashAlgorithm = 'sha256' | 'sha512';

export function hash(algorithm: HashAlgorithm, data: crypto.BinaryLike) {
  return crypto.createHash(algorithm).update(data).digest();
}

export async function generateKey() {
  const keypair = await subtle.generateKey({
    name: 'ECDSA',
    namedCurve: 'P-256'
  }, true, ['sign', 'verify']);
  return keypair;
}

export async function getPublicKey(keyPair: crypto.webcrypto.CryptoKeyPair) {
  return new Uint8Array(await subtle.exportKey('raw', keyPair.publicKey));
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.2 */
export async function verifyWithLabel(publicKey: Uint8Array | crypto.webcrypto.CryptoKey, label: string, sig: Uint8Array, msg: Uint8Array) {
  const labelledData = serializeResolvers([
    ['v', Buffer.from('MLS 1.0 ' + label)],
    ['v', msg]
  ]);
  const key = publicKey instanceof Uint8Array ? await subtle.importKey(
    'raw', publicKey, {
      name: 'ECDSA',
      namedCurve: 'P-256'
    }, false, ['verify'],
  ) : publicKey;
  return await subtle.verify({
    name: 'ECDSA',
    hash: 'SHA-256'
  }, key, sig, labelledData);
}

// TODO auto-detect pkcs8 and raw keys maybe
/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.2 */
export async function signWithLabel(privateKey: Uint8Array | crypto.webcrypto.CryptoKey, label: string, msg: Uint8Array) {
  const labelledData = serializeResolvers([
    ['v', Buffer.from('MLS 1.0 ' + label)],
    ['v', msg]
  ]);
  // if (privateKey instanceof Uint8Array) return p256.sign(labelledData, privateKey).toDERRawBytes(false);
  const key = privateKey instanceof Uint8Array ? await subtle.importKey(
    'pkcs8', privateKey, {
      name: 'ECDSA',
      namedCurve: 'P-256'
    }, false, ['sign'],
  ) : privateKey;
  return new Uint8Array(
    await subtle.sign(
      { 
        name: 'ECDSA',
        hash: 'SHA-256'
      },
      key, labelledData,
    ),
  );
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.3 */
export async function encryptWithLabel(publicKey: Uint8Array, label: string, context: Uint8Array, plaintext: Uint8Array) {
  const encryptContext = serializeResolvers([
    ['v', Buffer.from('MLS 1.0 ' + label)],
    ['v', context]
  ]);
  const key = await subtle.importKey(
      'raw', publicKey, 'AES-GCM', false, ['decrypt'],
  );
  return new Uint8Array(
    await subtle.decrypt(
      { name: 'AES-GCM', iv: encryptContext, additionalData: EMPTY_BUFFER },
      key, plaintext,
    ),
  );
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.3 */
export async function decryptWithLabel(privateKey: Uint8Array, label: string, context: Uint8Array, kemOutput: Uint8Array, ciphertext: Uint8Array) {
  const encryptContext = serializeResolvers([
    ['v', Buffer.from('MLS 1.0 ' + label)],
    ['v', context]
  ]);
  const key = await subtle.importKey(
      'raw', privateKey, 'AES-GCM', false, ['decrypt'],
  );
  return new Uint8Array(
    await subtle.decrypt(
      { name: 'AES-GCM', iv: encryptContext, additionalData: EMPTY_BUFFER },
      key, ciphertext,
    ),
  );
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-5.2 */
export function refHash(algorithm: HashAlgorithm, label: string, value: Uint8Array) {
  const refHashInput = serializeResolvers([
    ['v', Buffer.from(label)],
    ['v', value]
  ]);
  return hash(algorithm, refHashInput);
}

let zeroKey: crypto.webcrypto.CryptoKey | null = null;
async function createZeroKey() {
  if (!zeroKey) {
      const key = new Uint8Array(64);
      zeroKey = await subtle.importKey(
        "raw", new Uint8Array(64), {name: "HMAC", hash: 'SHA-256', length: key.byteLength * 8},
        false, ["sign", "verify"],
      );
  }
  return zeroKey;
}

export async function mac(key: Uint8Array, data: Uint8Array) {
  const cryptoKey = key.length === 0 
    ? await createZeroKey() 
    : await subtle.importKey(
      "raw", key, {name: "HMAC", hash: 'SHA-256', length: key.byteLength * 8},
      false, ["sign"],
    );
  return new Uint8Array(await subtle.sign('HMAC', cryptoKey, data));
}

export async function verifyMac(key: Uint8Array, data: Uint8Array, mac: Uint8Array) {
  const cryptoKey = key.length === 0 
    ? await createZeroKey() 
    : await subtle.importKey(
      "raw", key, {name: "HMAC", hash: 'SHA-256', length: key.byteLength * 8},
      false, ["verify"],
    );
  return await subtle.verify('HMAC', cryptoKey, mac, data);
}