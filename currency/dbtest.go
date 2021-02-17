package currency

import (
	"crypto/ecdsa"
	"fmt"
	"sync"
)

type Stored struct {
	Accounts                   map[PublicKeyString]Account
	Receipts                   map[HashPointer]Receipt
	NextReceipts               map[HashPointer][]HashPointer
	HighestReceiptHashPointers []HashPointer
}

func (s *Stored) InsertReceipt(rcpt Receipt) {
	// ensure that every receipt indexes next
	p := rcpt.Hashed.Previous
	rFound := false
	for _, r := range s.NextReceipts[p] {
		if r == rcpt.This {
			rFound = true
		}
	}
	if !rFound {
		s.NextReceipts[p] = append(s.NextReceipts[p], rcpt.This)
	}
	// receipt goes into the database
	s.Receipts[rcpt.This] = rcpt

	// Remember the highest ChainLength
	hi := ChainLength(0)
	for i := 0; i < len(s.HighestReceiptHashPointers); i++ {
		h := s.HighestReceiptHashPointers[i]
		r := s.Receipts[h]
		if hi < r.Hashed.ChainLength {
			hi = r.Hashed.ChainLength
		}
	}
	if hi == rcpt.Hashed.ChainLength {
		s.HighestReceiptHashPointers = append(s.HighestReceiptHashPointers, rcpt.This)
	}
	if hi < rcpt.Hashed.ChainLength {
		s.HighestReceiptHashPointers = []HashPointer{rcpt.This}
	}
}

func (s *Stored) FindNextReceipts(r HashPointer) []HashPointer {
	return s.NextReceipts[r]
}

func (s *Stored) FindReceiptByHashPointer(h HashPointer) Receipt {
	return s.Receipts[h]
}

func (s *Stored) InsertAccount(acct Account) {
	s.Accounts[NewPublicKeyString(acct.PublicKey)] = acct
}

func (s *Stored) FindAccountByPublicKeyString(k PublicKeyString) Account {
	return s.Accounts[k]
}

func (s *Stored) HighestReceipts() []HashPointer {
	return s.HighestReceiptHashPointers
}

var _ Storage = &Stored{}

type DbTest struct {
	Mutex              sync.Mutex
	IsBank             map[PublicKeyString]bool
	Accounts           map[PublicKeyString]*Account
	Receipts           map[HashPointer]*Receipt
	GenesisReceipt     *Receipt
	Current            *Receipt
	HighestChainLength ChainLength
	HighestReceipts    []Receipt
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
		if a.Nonce < txn.Signoffs[i].Nonce+nonceDiff {
			return ErrWait
		}
		// this is a replay according to our branch
		if a.Nonce > txn.Signoffs[i].Nonce+nonceDiff {
			return ErrReplay
		}
	}

	total = int64(0)
	for _, av := range db.Accounts {
		total += av.Amount
	}
	if total != 0 {
		return ErrTotalNonZeroSum
	}

	return nil
}

func (db *DbTest) PopReceipt() bool {
	// If this crashes, then the database is corrupted
	if db.This().Hashed.ChainLength == 0 {
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

	err := db.verifyTransaction(r.Hashed.Transaction, false)
	if err != nil {
		panic(err)
	}

	return true
}

func (db *DbTest) PeekNextReceipts() []Receipt {
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
func (db *DbTest) PushTransaction(txn Transaction) ErrTransaction {
	prevr := *db.Current
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

	// Keep track of highest chain length in use
	if r.Hashed.ChainLength == db.HighestChainLength {
		db.HighestReceipts = append(db.HighestReceipts, r)
	} else if r.Hashed.ChainLength > db.HighestChainLength {
		db.HighestChainLength = r.Hashed.ChainLength
		db.HighestReceipts = []Receipt{r}
	}

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
		db.Accounts[pks].Amount += txn.Flows[i].Amount
		if txn.Flows[i].Amount < 0 {
			db.Accounts[pks].Nonce++
		}
	}

	db.Current = db.Receipts[redos[i].HashPointer()]

	err := db.verifyTransaction(txn, false)
	if err != nil {
		panic(err)
	}

	return nil
}

func (db *DbTest) This() Receipt {
	return *db.Current
}

func (db *DbTest) CanPopReceipt() bool {
	return db.This().Hashed.ChainLength > 0
}

func (db *DbTest) Highest() []Receipt {
	return db.HighestReceipts
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
		db.PopReceipt()
	}
	if db.This().This == rcpt.This {
		return true
	}
	there := rcpt
	st := istack{}
	for db.This().Hashed.ChainLength < there.Hashed.ChainLength {
		nexts := db.Receipts[there.Hashed.Previous].Next
		idx := 0
		for i := 0; i < len(nexts); i++ {
			if nexts[i] == there.This {
				idx = i
				break
			}
		}
		if db.Receipts[there.Hashed.Previous].Next[idx] != there.This {
			panic(fmt.Sprintf("we are not where we expected: %s vs %s",
				db.Receipts[there.Hashed.Previous].Next[idx],
				there.This,
			))
		}
		st.Push(idx)
		there = *db.Receipts[there.Hashed.Previous]
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
		nexts := db.Receipts[there.Hashed.Previous].Next
		idx := 0
		for i := 0; i < len(nexts); i++ {
			if nexts[i] == there.This {
				idx = i
				break
			}
		}
		st.Push(idx)
		there = *db.Receipts[there.Hashed.Previous]
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
