package currency

import (
	"crypto/ecdsa"
	"fmt"
)

// The database stores a bunch of records
type Db interface {
	PushTransaction(rcpt Receipt, txn Transaction) (Receipt, ErrTransaction)
	PopTransaction() (Receipt, ErrTransaction)
	Genesis() Receipt

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
