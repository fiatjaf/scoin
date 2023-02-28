package scoin

import scala.scalajs.js
import scala.scalajs.js.annotation._
import scodec.bits._
import scala.scalajs.js.typedarray.Uint8Array

object ScoinJS {
  @JSExportTopLevel("Transaction")
  object TransactionJS {
    @JSExport
    def read(hex: String) = TransactionJS(Transaction.read(hex))
  }

  @JSExportAll
  class TransactionJS(tx: Transaction) {
    def version = tx.version.toInt
  }
}
