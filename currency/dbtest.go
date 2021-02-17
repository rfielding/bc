package currency

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"sync"
)

type DbTest struct {
	Storage Storage
	Mutex   sync.Mutex
	IsBank  map[PublicKeyString]bool
}

func NewDBTest() *DbTest {
	g := Receipt{}
	g.This = g.HashPointer()
	db := &DbTest{
		Storage: NewStored(),
		// hack to deal with banks that have negative balances
		IsBank: make(map[PublicKeyString]bool),
	}
	db.Storage.SetGenesis(g)
	db.Storage.SetThis(g)
	db.Storage.InsertReceipt(g)
	db.verifyTransaction(g.Hashed.Transaction, false)
	return db
}

func (db *DbTest) Genesis() Receipt {
	return db.Storage.GetGenesis()
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

func (db *DbTest) verifyTransaction(txn Transaction, isBeforeApply bool) ErrTransaction {
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
		nonceDiff := Nonce(0)
		if !isBeforeApply {
			nonceDiff = Nonce(1)
		}

		// look up the account
		pks := NewPublicKeyString(txn.Flows[i].PublicKey)
		a := db.Storage.FindAccountByPublicKeyString(pks)
		// if account not found, then add it as empty
		if a.IsEmpty() {
			a.PublicKey = txn.Flows[i].PublicKey
			a.Nonce = 0
		}
		// account below zero
		if a.Amount+txn.Flows[i].Amount < 0 && db.IsBank[pks] == false {
			return ErrBelowZero
		}
		// this can't be applied.  maybe later though.
		if a.Nonce < txn.Signoffs[i].Nonce+nonceDiff {
			return ErrWait
		}
		// this is a replay according to our branch
		if a.Nonce > txn.Signoffs[i].Nonce+nonceDiff {
			return ErrReplay
		}
	}

	return nil
}

func (db *DbTest) PopReceipt() bool {
	// If this crashes, then the database is corrupted
	if db.This().Hashed.ChainLength == 0 {
		return false
	}

	txn := db.Storage.GetThis().Hashed.Transaction

	// we need to unapply the transaction in order to go back
	r := db.Storage.FindReceiptByHashPointer(db.Storage.GetThis().Hashed.Previous)
	if r.IsEmpty() {
		panic(fmt.Sprintf("we were unable to find a receipt that should exist! at %s", db.Storage.GetThis().Hashed.Previous))
	}

	// the receipt is found.  now, undo it.
	for i := 0; i < len(txn.Flows); i++ {
		pks := NewPublicKeyString(txn.Flows[i].PublicKey)
		a := db.Storage.FindAccountByPublicKeyString(pks)
		a.Amount -= txn.Flows[i].Amount
		if txn.Flows[i].Amount < 0 {
			a.Nonce--
		}
		db.Storage.InsertAccount(a)
	}

	db.Storage.SetThis(r)
	err := db.verifyTransaction(db.Storage.GetThis().Hashed.Transaction, false)
	if err != nil {
		panic(err)
	}

	return true
}

func (db *DbTest) PeekNextReceipts() []Receipt {
	return db.peekNext()
}

func (db *DbTest) nexts(p HashPointer) []Receipt {
	h := db.Storage.FindNextReceipts(p)
	r := make([]Receipt, 0)
	for i := range h {
		r = append(r, db.Storage.FindReceiptByHashPointer(h[i]))
	}
	return r
}

func (db *DbTest) peekNext() []Receipt {
	return db.nexts(db.Storage.GetThis().This)
}

// receipt, pleaseWait, error
func (db *DbTest) PushTransaction(txn Transaction) ErrTransaction {
	prevr := db.Storage.GetThis()
	// if no error, then this is meaningful
	r := Receipt{}

	err := db.verifyTransaction(txn, true)
	if err != nil {
		return err
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
		a := db.Storage.FindAccountByPublicKeyString(pks)
		// if account not found, then add it as empty
		if a.IsEmpty() {
			a.PublicKey = txn.Flows[i].PublicKey
			a.Nonce = 0
		}
		db.Storage.InsertAccount(a)
	}

	for i := 0; i < len(txn.Flows); i++ {
		pks := NewPublicKeyString(txn.Flows[i].PublicKey)
		a := db.Storage.FindAccountByPublicKeyString(pks)
		if a.IsEmpty() {
			a.PublicKey = txn.Flows[i].PublicKey
		}
		// Outflows decrement the nonce
		if txn.Flows[i].Amount < 0 {
			a.Nonce++
		}
		a.Amount += txn.Flows[i].Amount
		db.Storage.InsertAccount(a)
	}

	// write out the receipt data
	r.Hashed.Transaction = txn
	r.Hashed.ChainLength = prevr.Hashed.ChainLength + 1
	r.Hashed.Previous = prevr.This
	r.This = r.HashPointer()

	// store it
	db.Storage.InsertReceipt(r)
	db.Storage.SetThis(r)

	err = db.verifyTransaction(txn, false)
	if err != nil {
		panic(err)
	}

	return nil
}

func (db *DbTest) PushReceipt(i int) ErrTransaction {
	// If this crashes, then the database is corrupted
	redos := db.peekNext()
	if len(redos) < i {
		return ErrNotFound
	}
	txn := redos[i].Hashed.Transaction

	// the receipt is found.  now, undo it.
	for i := 0; i < len(txn.Flows); i++ {
		pks := NewPublicKeyString(txn.Flows[i].PublicKey)
		a := db.Storage.FindAccountByPublicKeyString(pks)
		a.Amount += txn.Flows[i].Amount
		if txn.Flows[i].Amount < 0 {
			a.Nonce++
		}
		db.Storage.InsertAccount(a)
	}

	db.Storage.SetThis(db.Storage.FindReceiptByHashPointer(redos[i].HashPointer()))

	err := db.verifyTransaction(txn, false)
	if err != nil {
		panic(err)
	}

	return nil
}

func (db *DbTest) This() Receipt {
	return db.Storage.GetThis()
}

func (db *DbTest) CanPopReceipt() bool {
	return db.This().Hashed.ChainLength > 0
}

func (db *DbTest) Highest() []Receipt {
	h := db.Storage.HighestReceipts()
	r := make([]Receipt, 0)
	for i := range h {
		v := db.Storage.FindReceiptByHashPointer(h[i])
		r = append(r, v)
	}
	return r
}

type istack []int

func (s *istack) Push(v int) {
	*s = append(*s, v)
}

func (s *istack) Peek() int {
	return (*s)[len(*s)-1]
}

func (s *istack) Pop() int {
	res := (*s)[len(*s)-1]
	*s = (*s)[:len(*s)-1]
	return res
}

func (s *istack) CanPop() bool {
	return len(*s) > 0
}

func (db *DbTest) GotoReceipt(rcpt Receipt) bool {
	// Walk them back to a receipt that they have in common
	// and remember the path for there when we do it
	// RePush the stack to get to there

	for db.This().Hashed.ChainLength > rcpt.Hashed.ChainLength && db.CanPopReceipt() {
		log.Printf("%s", db.This().This)
		db.PopReceipt()
	}
	if db.This().This == rcpt.This {
		return true
	}
	there := rcpt
	st := istack{}
	for db.This().Hashed.ChainLength < there.Hashed.ChainLength {
		nexts := db.Storage.FindNextReceipts(there.Hashed.Previous)
		idx := 0
		for i := 0; i < len(nexts); i++ {
			if nexts[i] == there.This {
				idx = i
				break
			}
		}
		if db.Storage.FindNextReceipts(there.Hashed.Previous)[idx] != there.This {
			panic(fmt.Sprintf("we are not where we expected: %s vs %s",
				db.Storage.FindNextReceipts(there.Hashed.Previous)[idx],
				there.This,
			))
		}
		st.Push(idx)
		there = db.Storage.FindReceiptByHashPointer(there.Hashed.Previous)
	}
	if db.This().This == rcpt.This {
		return true
	}
	if db.This().Hashed.ChainLength != there.Hashed.ChainLength {
		panic(fmt.Sprintf("we expect to be at same chain length now! %d vs %d",
			db.This().Hashed.ChainLength,
			there.Hashed.ChainLength,
		))
	}
	for db.This().This != there.This && db.CanPopReceipt() {
		nexts := db.Storage.FindNextReceipts(there.Hashed.Previous)
		idx := 0
		for i := 0; i < len(nexts); i++ {
			if nexts[i] == there.This {
				idx = i
				break
			}
		}
		st.Push(idx)
		there = db.Storage.FindReceiptByHashPointer(there.Hashed.Previous)
		db.PopReceipt()
	}
	for st.CanPop() {
		db.PushReceipt(st.Pop())
	}

	if db.This().This == there.This {
		return true
	}
	return false
}

var _ Db = &DbTest{}
