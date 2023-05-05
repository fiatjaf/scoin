scoin
=====

A simple Bitcoin library for Scala that is mostly copied from [ACINQ](https://github.com/acinq)'s projects, then sanitized and shuffled around. It works on Scala JVM, Scala Native and Scala JS.

See API documentation on https://javadoc.io/doc/com.fiatjaf/scoin_3/latest/.

## Projects using scoin

  - https://github.com/fiatjaf/soma
  - https://github.com/fiatjaf/snow
  - https://github.com/nbd-wtf/poncho
  - https://github.com/nbd-wtf/immortan

## libsecp256k1 dependencies

When using `scoin` with Scala Native or Scala JVM it is necessary to have `libsecp256k1` available as a shared library. You can get it from your OS package manager where it is usually called either `secp256k1` or `libsecp256k1`, or install it [from the source](https://github.com/bitcoin-core/secp256k1) which isn't hard at all.

## JavaScript dependencies

When using `scoin` from Scala.js we require some dependencies from [npm](https://npmjs.com/). If you are using [sbt-npm-dependencies](https://github.com/davenverse/sbt-npm-dependencies) they are available under `Compile / npmTransitiveDependencies` and [sbt-esbuild](https://github.com/fiatjaf/sbt-esbuild) is recommended if you need to bundle everything for the browser.
