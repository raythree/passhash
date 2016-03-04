/**
* These algorithms were ported from the Java version found here:
*
* https://crackstation.net/hashing-security.htm
*/
var crypto = require('crypto'),
  ITERATIONS = 1000, // hashing constants
  SALT_LEN = 24,
  HASH_LEN = 24,
  ALGORITHM = 'sha1';

// should be constant time, see net.crackstation
function constCompare(buf1, buf2) {
  var diff = buf1.length ^ buf2.length;
  for(var i = 0; i < buf1.length && i < buf2.length; i++)
      diff |= buf1[i] ^ buf2[i];
  return diff == 0;
}

function hashParts(s) {
  var res = { iterations: 0, salt: '', hash: '', alg: ALGORITHM }, parts;
  if (!s) return res;
  parts = s.split(':');
  if (parts.length < 3) return res;
  iterations = parseInt(parts[0]);
  if (iterations <= 0) return res;
  res.iterations = iterations;
  res.salt = new Buffer(parts[1], 'hex');
  res.hash = new Buffer(parts[2], 'hex');
  if (parts.length === 4) {
    res.alg = parts[3];
  }
  return res;
}

module.exports = {
  configure: function (opts) {
    if (opts.iterations && typeof opts.iterations === 'number') ITERATIONS = opts.iterations
    if (opts.algorithm && typeof opts.algorithm === 'string') ALGORITHM = opts.algorithm
    if (opts.saltLength && typeof opts.saltLength === 'number') SALT_LEN = opts.saltLength
    HASH_LEN = SALT_LEN
  },
  //
  // Generate a hash of the given password.
  //
  generate: function (pass, cb) {
    if (!pass) cb('Null password');
    crypto.randomBytes(SALT_LEN, function(err, sbuf) {
      if (err) return cb(err);
      var salt = sbuf.toString('hex');
      crypto.pbkdf2(pass, sbuf, ITERATIONS, HASH_LEN, ALGORITHM, function (err, key) {
        if (err) cb(err);
        cb(null, ITERATIONS + ':' + salt.toString('hex') + ':' + key.toString('hex') + ':' + ALGORITHM);
      });
    });
  },
  //
  // Check a password against a hashed password. If they match
  // callback is invoked with a result of true, othereise false
  //
  verify: function (pass, hashedPass, cb) {
    var parts;
    if (!hashedPass) return cb('null hash');
    if (!pass) return cb('null password');

    parts = hashParts(hashedPass);
    if (!parts.iterations) return cb('invalid hash value');
    crypto.pbkdf2(pass, parts.salt, parts.iterations, HASH_LEN, parts.alg, function (err, res) {
      if (err) return cb(err);
      cb(null, constCompare(parts.hash, res));
    });
  },
  //
  // Generate a random key.
  //
  rand: function (cb) {
    crypto.randomBytes(SALT_LEN, function(err, sbuf) {
      if (err) return cb(err);
      var key = sbuf.toString('hex');
      cb(null, key);
    });
  },
  getConfig: function () {
    return {
      iterations: ITERATIONS,
      algorithm: ALGORITHM,
      saltLength: SALT_LEN
    }
  }
}
