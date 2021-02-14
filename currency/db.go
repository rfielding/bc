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
	PushTransaction(txn Transaction) ErrTransaction

	// Move around the chain for things already inserted
	RePush(i int) ErrTransaction
	PeekNext() []Receipt
	PopTransaction() bool
	CanPopTransaction() bool
	Goto(Receipt) bool

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
  Appending a receipt into the chain:
  - every record has a chain length
  - the current head that we are on has a chain length

  So, walk back current chain, and proposed chain to have an equal chain length.
  Walk the two back in unison until they have an common receipt.
  Sort branches to put longest branch in position 0
*/
