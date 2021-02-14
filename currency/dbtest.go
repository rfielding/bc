package currency

import (
	"crypto/ecdsa"
	"sync"
)

type DbTest struct {
	Mutex          sync.Mutex
	IsBank         map[PublicKeyString]bool
	Accounts       map[PublicKeyString]*Account
	Receipts       map[HashPointer]*Receipt
	GenesisReceipt *Receipt
	Current        *Receipt
}

func NewDBTest() *DbTest {
	g := &Receipt{}
	db := &DbTest{
		// hack to deal with banks that have negative balances
		IsBank:   make(map[PublicKeyString]bool),
		Receipts: make(map[HashPointer]*Receipt),
		// state at current location in the tree, required for validation!
		Accounts: make(map[PublicKeyString]*Account),
		// the beginning block that everything must reach
		GenesisReceipt: g,
		Current:        g,
	}
	db.Receipts[g.This] = g
	return db
}

func (db *DbTest) Genesis() Receipt {
	return *db.GenesisReceipt
}

func (db *DbTest) AsBank(k PublicKey) {
	db.Mutex.Lock()
	defer db.Mutex.Unlock()
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

func (db *DbTest) verifyTransaction(txn Transaction) ErrTransaction {
	// basic malformedness
	if len(txn.Flows) != len(txn.Signoffs) {
		return ErrMalformed
	}

	// bad signature
	result := txn.Verify()
	if result == false {
		return ErrSigFail
	}

	// Flows add to zero
	total := int64(0)
	for i := 0; i < len(txn.Flows); i++ {
		total -= txn.Flows[i].Amount
	}
	if total != 0 {
		return ErrNonZeroSum
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
		// account below zero
		if a.Amount+txn.Flows[i].Amount < 0 && db.IsBank[pks] == false {
			return ErrBelowZero
		}
		// this can't be applied.  maybe later though.
		if a.Nonce < txn.Signoffs[i].Nonce {
			return ErrWait
		}
		// this is a replay according to our branch
		if a.Nonce > txn.Signoffs[i].Nonce {
			return ErrReplay
		}
	}

	return nil
}

func (db *DbTest) PopTransaction() bool {
	// If this crashes, then the database is corrupted
	db.Mutex.Lock()
	defer db.Mutex.Unlock()
	if db.Current == db.GenesisReceipt {
		return false
	}

	undo := db.Current
	txn := undo.Hashed.Transaction

	// we need to unapply the transaction in order to go back
	r, ok := db.Receipts[db.Current.Hashed.Previous]
	if !ok {
		return false
	}

	// the receipt is found.  now, undo it.
	for i := 0; i < len(txn.Flows); i++ {
		pks := NewPublicKeyString(txn.Flows[i].PublicKey)
		db.Accounts[pks].Amount -= txn.Flows[i].Amount
		if txn.Flows[i].Amount < 0 {
			db.Accounts[pks].Nonce--
		}
	}

	db.Current = r

	return true
}

func (db *DbTest) PeekNext() []Receipt {
	db.Mutex.Lock()
	defer db.Mutex.Unlock()
	return db.peekNext()
}

func (db *DbTest) peekNext() []Receipt {
	peeks := make([]Receipt, 0)
	for i := 0; i < len(db.Current.Next); i++ {
		k := db.Current.Next[i]
		peeks = append(peeks, *db.Receipts[k])
	}
	return peeks
}

// receipt, pleaseWait, error
func (db *DbTest) PushTransaction(txn Transaction) (Receipt, ErrTransaction) {
	db.Mutex.Lock()
	defer db.Mutex.Unlock()
	prevr := *db.Current
	// if no error, then this is meaningful
	r := Receipt{}

	err := db.verifyTransaction(txn)
	if err != nil {
		return r, err
	}

	// everything is verified

	// If we don't make it to the end of this
	// will corrupt the database!!!!

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

func (db *DbTest) RePush(i int) (Receipt, ErrTransaction) {
	// If this crashes, then the database is corrupted
	db.Mutex.Lock()
	defer db.Mutex.Unlock()

	redos := db.peekNext()
	if len(redos) < i {
		return Receipt{}, ErrNotFound
	}
	txn := redos[i].Hashed.Transaction

	// the receipt is found.  now, undo it.
	for i := 0; i < len(txn.Flows); i++ {
		pks := NewPublicKeyString(txn.Flows[i].PublicKey)
		db.Accounts[pks].Amount += txn.Flows[i].Amount
		if txn.Flows[i].Amount < 0 {
			db.Accounts[pks].Nonce++
		}
	}

	db.Current = db.Receipts[redos[i].HashPointer()]

	return *db.Current, nil
}

func (db *DbTest) This() Receipt {
	return *db.Current
}

func (db *DbTest) CanPopTransaction() bool {
	return (db.Current == db.GenesisReceipt)
}

var _ Db = &DbTest{}
