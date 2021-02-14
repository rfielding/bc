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
	PushTransaction(txn Transaction) (Receipt, ErrTransaction)
	// Move around the chain
	RePush(i int) (Receipt, ErrTransaction)
	PeekNext() []Receipt
	PopTransaction() bool
	CanPopTransaction() bool
	// Locations.  Will need help navigating to longest chain.
	Genesis() Receipt
	This() Receipt
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
