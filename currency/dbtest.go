package currency

import (
	"crypto/ecdsa"
)

type DbTest struct {
	IsBank         map[PublicKeyString]bool
	Accounts       map[PublicKeyString]*Account
	Receipts       map[HashPointer]*Receipt
	GenesisReceipt *Receipt
	Current        *Receipt
}

func NewDBTest() *DbTest {
	g := &Receipt{}
	return &DbTest{
		// hack to deal with banks that have negative balances
		IsBank:   make(map[PublicKeyString]bool),
		Receipts: make(map[HashPointer]*Receipt),
		// state at current location in the tree, required for validation!
		Accounts: make(map[PublicKeyString]*Account),
		// the beginning block that everything must reach
		GenesisReceipt: g,
		Current:        g,
	}
}

func (db *DbTest) Genesis() Receipt {
	return *db.GenesisReceipt
}

func (db *DbTest) AsBank(k PublicKey) {
	pks := NewPublicKeyString(k)
	db.IsBank[pks] = true
}

func (db *DbTest) Sign(k *ecdsa.PrivateKey, t *Transaction, i int) *Transaction {
	// one signer for now
	if len(t.Flows) != len(t.Signoffs) {
		return nil
	}
	t.Sign(k, i)
	return t
}
func (db *DbTest) SignTransaction(t *Transaction, k *ecdsa.PrivateKey, i int) error {
	return t.Sign(k, i)
}

func (db *DbTest) PopTransaction() (Receipt, ErrTransaction) {
	if db.Current == db.GenesisReceipt {
		return db.Genesis(), ErrGenesis
	}
	r, ok := db.Receipts[db.Current.Hashed.Previous]
	if !ok {
		return *r, ErrNotFound
	}
	return *r, nil
}

// receipt, pleaseWait, error
func (db *DbTest) PushTransaction(prevr Receipt, txn Transaction) (Receipt, ErrTransaction) {
	// if no error, then this is meaningful
	r := Receipt{}

	if len(txn.Flows) != len(txn.Signoffs) {
		return r, ErrMalformed
	}

	// bad signature
	result := txn.Verify()
	if result == false {
		return r, ErrSigFail
	}

	// Signed add to zero
	total := int64(0)
	for i := 0; i < len(txn.Flows); i++ {
		total -= txn.Flows[i].Amount
	}
	if total != 0 {
		return r, ErrNonZeroSum
	}

	// Inputs must match nonce on account
	for i := 0; i < len(txn.Flows); i++ {
		if txn.Flows[i].Amount > 0 {
			continue
		}
		// look up the account
		pks := NewPublicKeyString(txn.Flows[i].PublicKey)
		a := db.Accounts[pks]
		// if account not found, then add it as empty
		if a == nil {
			a = &Account{}
			a.PublicKey = txn.Flows[i].PublicKey
			a.Nonce = 0
		}
		if a.Amount+txn.Flows[i].Amount < 0 && db.IsBank[pks] == false {
			return r, ErrBelowZero
		}
		if a.Nonce < txn.Signoffs[i].Nonce {
			return r, ErrWait
		}
		// need a better solution to bank negative balance
		if a.Nonce > txn.Signoffs[i].Nonce {
			return r, ErrReplay
		}
		db.Accounts[pks] = a
	}

	for i := 0; i < len(txn.Flows); i++ {
		pks := NewPublicKeyString(txn.Flows[i].PublicKey)
		a := db.Accounts[pks]
		if a == nil {
			db.Accounts[pks] = &Account{
				PublicKey: txn.Flows[i].PublicKey,
			}
		}
		// Outflows decrement the nonce
		if txn.Flows[i].Amount < 0 {
			db.Accounts[pks].Nonce++
		}
		db.Accounts[pks].Amount += txn.Flows[i].Amount
	}

	// write out the receipt data
	r.Hashed.Transaction = txn
	r.Hashed.ChainLength = prevr.Hashed.ChainLength + 1
	r.Hashed.Previous = prevr.This
	r.This = r.HashPointer()

	// store it
	db.Receipts[r.This] = &r

	// modify our previous to point to us
	if db.Receipts[prevr.This] != nil {
		db.Receipts[prevr.This].Next = append(db.Receipts[prevr.This].Next, r.This)
	}
	db.Current = &r
	return r, nil
}

var _ Db = &DbTest{}
