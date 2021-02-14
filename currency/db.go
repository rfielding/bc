package currency

import (
	"crypto/ecdsa"
	"fmt"
)

// The database stores a bunch of records
type Db interface {
	PushTransaction(txn Transaction) (Receipt, ErrTransaction)
	RePush(i int) (Receipt, ErrTransaction)
	PeekNext() []Receipt
	PopTransaction() bool
	CanPopTransaction() bool
	Genesis() Receipt
	This() Receipt
	AsBank(k PublicKey) // hack to deal with accounts with negative balances, like treasuries
	Sign(k *ecdsa.PrivateKey, txn *Transaction, i int) *Transaction
}

type ErrTransaction error

var (
	ErrMalformed  = fmt.Errorf("malformed")
	ErrGenesis    = fmt.Errorf("genesis")
	ErrBelowZero  = fmt.Errorf("belowzero")
	ErrSigFail    = fmt.Errorf("signaturefail")
	ErrNotFound   = fmt.Errorf("notfound")
	ErrWait       = fmt.Errorf("wait")
	ErrNonZeroSum = fmt.Errorf("nonZeroSum")
	ErrReplay     = fmt.Errorf("replay")
)
