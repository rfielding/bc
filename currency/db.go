package currency

import (
	"crypto/ecdsa"
	"fmt"
)

// A multiple-input and multiple output account-based system:
//
//  (alice: 5, bob: 6) send: (charles: 10, taxman: 1)
//
type Db interface {
	// Try to insert transactions into the chain
	// Pushing onto This() receipt.
	// If it fails, then there is no effect.
	PushTransaction(txn Transaction) ErrTransaction

	// Move around the chain for things already inserted.
	// This is navigation among verified receipts.
	PushReceipt(i int) ErrTransaction
	PeekNextReceipts() []Receipt
	PopReceipt() bool
	CanPopReceipt() bool
	GotoReceipt(Receipt) bool

	// Locations.
	Genesis() Receipt
	This() Receipt
	Highest() []Receipt

	// Stupid hack to deal with accounts with negative balances, like treasuries
	// Something like proof-of-work will be needed to remove the Treasury hack
	AsBank(k PublicKey)

	// allow for partially signed transactions to go out,
	// so that everybody that needs to sign CAN sign.
	Sign(k *ecdsa.PrivateKey, txn *Transaction, i int) *Transaction
}

type ErrTransaction error

var (
	ErrMalformed       = fmt.Errorf("malformed")
	ErrGenesis         = fmt.Errorf("genesis")
	ErrBelowZero       = fmt.Errorf("belowzero")
	ErrSigFail         = fmt.Errorf("signaturefail")
	ErrNotFound        = fmt.Errorf("notfound")
	ErrWait            = fmt.Errorf("wait")
	ErrNonZeroSum      = fmt.Errorf("nonZeroSum")
	ErrReplay          = fmt.Errorf("replay")
	ErrTotalNonZeroSum = fmt.Errorf("totalnonzerosum")
)

/*
  ???

  Largest chain length with lowest hash.
  EC checksums commute with transaction order, because hashes are of the database state.
  ie:

  s1_x = H(s0_x)

  p_a = s0_a * G
  p_b = s0_b * G
  p_t = s0_t * G

  n_a = s1_a * G
  n_b = s1_b * G
  n_t = s1_t * G

  // ignoring nonces, this is a hash of database state:
  // zero balances do not affect the hash, to allow for states to be swept from the database
  -50 p_t + 20 p_a + 30 p_b

  with nonces that can ONLY be created by the owner:
   -50 p_t + 2 n_t + 20 p_a + 1 n_a + 30 p_b

  or....
	put a minimum of txns that must be kept around, and the txn will FAIL definitively to be applied to the chain
	after this.  this can also happen to a signed txn if all nodes ignore the txn until it's no longer
	going around the network.

	ex: at chainLength: 60, we issue a txn that must be included from [60,160].  after we see txn 161 confirmed, we know
	that the payment failed.  to try again, it must not overlap for [161,261].  Doing this, nonces do not show up
	in database state.  zero balances can be garbage collected, because there is no nonce state - purely balances.
	but dust accounts take up as much space as if there is no gc.



  // but it is important to include nonces to stop double-spending,
  // without a different method for preventing double-spend, such as:
  // - transaction expiration, due to a window in which it can be applied - and a horizon over which it must be checked


*/
