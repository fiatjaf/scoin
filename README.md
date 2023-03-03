scoin
=====

A simple Bitcoin library for Scala that is mostly copied from [ACINQ](https://github.com/acinq)'s projects, then sanitized and shuffled around. It works on Scala JVM, Scala Native and Scala JS.

See API documentation on https://javadoc.io/doc/com.fiatjaf/scoin_3/latest/.

### Latest Features
  - construct and spend [**taproot outputs**](https://github.com/fiatjaf/scoin/blob/master/shared/src/test/scala/TaprootTest.scala)

## Projects using scoin

  - https://github.com/fiatjaf/poncho
  - https://github.com/fiatjaf/immortan
  - https://github.com/fiatjaf/openchain

### Experiments with scoin

`scoin` is a good choice for experimenting with bitcoin primitives or constructing complex custom transactions.
  - [small experiments and examples](https://gist.github.com/VzxPLnHqr/acc4fd4ee399196e7723a7d36a90834b)
  - [larger experimental project](https://github.com/VzxPLnHqr/sig-pow)

## libsecp256k1 dependencies

When using `scoin` with Scala Native or Scala JVM it is necessary to have `libsecp256k1` available as a shared library. You can get it from your OS package manager where it is usually called either `secp256k1` or `libsecp256k1`, or install it [from the source](https://github.com/bitcoin-core/secp256k1) which isn't hard at all.

## JavaScript dependencies

When using `scoin` from Scala.js we require some dependencies from [npm](https://npmjs.com/). If you are using [sbt-npm-dependencies](https://github.com/davenverse/sbt-npm-dependencies) they are available under `Compile / npmTransitiveDependencies` and [sbt-esbuild](https://github.com/fiatjaf/sbt-esbuild) is recommended if you need to bundle everything for the browser.
