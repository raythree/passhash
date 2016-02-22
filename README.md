# pass-hash

`npm install pass-hash`

A salted password hash ported from the Java version from [crackstation.net](https://crackstation.net/hashing-security.htm)

### Usage

```
var passhash = require('pass-hash')

passhash.config(opts) // optionally configure

passhash.generate('secret', function (err, hashed) {
  passhash.verify('secret', hashed, function (err, ok) {
  	assert(ok) // will be false if password does not match
  })
})

```

### Options

* `iterations` - Default is 1000
* `algorithm` - Defaults to `'sha1'`
* `saltLength` - Default is 24



