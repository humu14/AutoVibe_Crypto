/** sha-256 */

// initial hash values
const H_INITIAL = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

// round constants
const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

/** rotate right */
function rotr(n, x) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

/** shift right */
function shr(n, x) {
  return (x >>> n) >>> 0;
}

/** sigma helpers */
function sigma0(x) {
  return (rotr(2, x) ^ rotr(13, x) ^ rotr(22, x)) >>> 0;
}

function sigma1(x) {
  return (rotr(6, x) ^ rotr(11, x) ^ rotr(25, x)) >>> 0;
}

function gamma0(x) {
  return (rotr(7, x) ^ rotr(18, x) ^ shr(3, x)) >>> 0;
}

function gamma1(x) {
  return (rotr(17, x) ^ rotr(19, x) ^ shr(10, x)) >>> 0;
}

/** choice */
function ch(x, y, z) {
  return ((x & y) ^ (~x & z)) >>> 0;
}

/** majority */
function maj(x, y, z) {
  return ((x & y) ^ (x & z) ^ (y & z)) >>> 0;
}

/** string to bytes */
function stringToBytes(str) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);
    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6));
      bytes.push(0x80 | (code & 0x3f));
    } else if (code < 0x10000) {
      bytes.push(0xe0 | (code >> 12));
      bytes.push(0x80 | ((code >> 6) & 0x3f));
      bytes.push(0x80 | (code & 0x3f));
    } else {
      bytes.push(0xf0 | (code >> 18));
      bytes.push(0x80 | ((code >> 12) & 0x3f));
      bytes.push(0x80 | ((code >> 6) & 0x3f));
      bytes.push(0x80 | (code & 0x3f));
    }
  }
  return bytes;
}

/** pad message */
function padMessage(bytes) {
  const originalLength = bytes.length;
  const bitLength = originalLength * 8;

  // add 0x80
  bytes.push(0x80);

  // pad to 56 mod 64
  while (bytes.length % 64 !== 56) {
    bytes.push(0x00);
  }

  // append length
  // js numbers are enough
  const highBits = Math.floor(bitLength / 0x100000000);
  const lowBits = bitLength & 0xffffffff;
  
  bytes.push((highBits >>> 24) & 0xff);
  bytes.push((highBits >>> 16) & 0xff);
  bytes.push((highBits >>> 8) & 0xff);
  bytes.push(highBits & 0xff);
  bytes.push((lowBits >>> 24) & 0xff);
  bytes.push((lowBits >>> 16) & 0xff);
  bytes.push((lowBits >>> 8) & 0xff);
  bytes.push(lowBits & 0xff);

  return bytes;
}

/** parse blocks */
function parseBlocks(bytes) {
  const blocks = [];
  for (let i = 0; i < bytes.length; i += 64) {
    const block = [];
    for (let j = 0; j < 16; j++) {
      const offset = i + j * 4;
      block.push(
        ((bytes[offset] << 24) |
         (bytes[offset + 1] << 16) |
         (bytes[offset + 2] << 8) |
         bytes[offset + 3]) >>> 0
      );
    }
    blocks.push(block);
  }
  return blocks;
}

/** compute sha-256 */
function sha256(input) {
  // to bytes
  let bytes;
  if (typeof input === 'string') {
    bytes = stringToBytes(input);
  } else if (Array.isArray(input)) {
    bytes = [...input]; // clone input
  } else {
    throw new Error('Input must be a string or byte array');
  }

  // pad message
  const padded = padMessage(bytes);

  // split blocks
  const blocks = parseBlocks(padded);

  // init hash
  let [h0, h1, h2, h3, h4, h5, h6, h7] = H_INITIAL;

  // process blocks
  for (const block of blocks) {
    // prepare schedule
    const W = new Array(64);
    for (let t = 0; t < 16; t++) {
      W[t] = block[t];
    }
    for (let t = 16; t < 64; t++) {
      W[t] = (gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16]) >>> 0;
    }

    // init working vars
    let a = h0, b = h1, c = h2, d = h3;
    let e = h4, f = h5, g = h6, h = h7;

    // 64 rounds
    for (let t = 0; t < 64; t++) {
      const T1 = (h + sigma1(e) + ch(e, f, g) + K[t] + W[t]) >>> 0;
      const T2 = (sigma0(a) + maj(a, b, c)) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + T1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (T1 + T2) >>> 0;
    }

    // update hash
    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  // final hash
  const hash = [h0, h1, h2, h3, h4, h5, h6, h7];
  return hash.map(h => h.toString(16).padStart(8, '0')).join('');
}

/** sha-256 bytes */
function sha256Bytes(input) {
  const hex = sha256(input);
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return bytes;
}

export { sha256, sha256Bytes, stringToBytes };
