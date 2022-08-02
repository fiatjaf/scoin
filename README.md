scoin
==========

A simple Bitcoin library for Scala that is mostly copied from [ACINQ](https://github.com/acinq)'s projects.

## JavaScript dependencies

When using `scoin` from Scala.js we require two dependencies from NPM:

- "@noble/secp256k1" -> "1.6.3",
- "hash.js" -> "1.1.7"

Because scalajs-bundler doesn't work, these must be available as **globals** (with the following names), so you must do something like

```
window.Secp256k1 = require('@noble/secp256k1')
window.Secp256k1Utils = require('@noble/secp256k1').utils
window.Curve = require('@noble/secp256k1').CURVE
window.Point = require('@noble/secp256k1').Point
window.HashJS = require('hash.js')
```

And use a JavaScript bundler to bundle these modules and include that somehow before including your ScalaJS `fastLinkJS` output file.

Suggestions on how to do this better are accepted.
