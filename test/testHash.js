var assert = require('assert')
var passhash = require('../passhash')

describe('password hashing tests', function () {

  it('should generate hashed passwords and verify with defaults', function (done) {
    passhash.generate('secret', function (err, hashed) {
      assert(!err)
      console.log('hash generated: ' + hashed);  
      passhash.verify('secret', hashed, function (err, ok) {        
        console.log('hashed ' + hashed + ' for secret ' + ' returned ' + ok)
        assert(ok)
        // configure different algorithm, make sure it uses sha1 stored in hashed
        passhash.configure({ algorithm: 'sha256' });
        passhash.verify('secret1', hashed, function (err, ok) {
          assert(passhash.getConfig().algorithm === 'sha256');
          assert(!ok)
          console.log(ok)
          done()
        })
      })
    })
  });

  it('should generate hashed passwords and verify using options', function (done) {
    passhash.configure({
      iterations: 3000,
      algorithm: 'sha256',
      saltLength: 64
    })

    var opts = passhash.getConfig();
    assert(opts.saltLength === 64)
    assert(opts.iterations === 3000)
    assert(opts.algorithm === 'sha256')

    passhash.generate('secret', function (err, h) {
      if (err) console.log('ERROR in generate: ' + err)
      console.log(h)
      assert(h)
      passhash.verify('secret', h, function (err, ok) {
        if (err) console.log('ERROR ind verify: ' + err)
        console.log(ok)
        assert(ok)
        passhash.verify('secret1', h, function (err, ok) {
          assert(!ok)
          console.log(ok)
          done()
        })
      })
    });
  });
})
