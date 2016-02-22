var assert = require('assert')
var passhash = require('../passhash')

describe('password hashing tests', function () {

  it('should generate hashed passwords and authenticate', function (done) {
    passhash.generate('secret', function (err, hashed) {
      assert(!err)
      assert(hashed)
      console.log(hashed)
      passhash.verify('secret', hashed, function (err, ok) {
        console.log(ok)
        assert(ok)
        passhash.verify('secret1', hashed, function (err, ok) {
          assert(!ok)
          console.log(ok)
          done()
        })
      })
    })
  })
})
