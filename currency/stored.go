package currency

type Stored struct {
	Accounts                   map[PublicKeyString]Account
	Receipts                   map[HashPointer]Receipt
	NextReceipts               map[HashPointer][]HashPointer
	HighestReceiptHashPointers []HashPointer
	Genesis                    Receipt
	This                       Receipt
	Transactions               []Transaction
}

type TransactionIteratorImpl struct {
	Stored *Stored
	Index  int
}

func (it *TransactionIteratorImpl) Next() Transaction {
	v := it.Stored.Transactions[it.Index]
	if it.HasNext() {
		it.Index++
	}
	return v
}

func (it *TransactionIteratorImpl) HasNext() bool {
	if it.Index+1 < len(it.Stored.Transactions) {
		return true
	}
	return false
}

func (it *TransactionIteratorImpl) Remove() {
	head := it.Stored.Transactions[0:it.Index]
	tail := it.Stored.Transactions[:it.Index+1]
	it.Stored.Transactions = append(head, tail...)
}

func (s *Stored) IterateTransactions() TransactionIterator {
	return &TransactionIteratorImpl{
		Stored: s,
	}
}

func (s *Stored) InsertTransaction(txn Transaction) {
	s.Transactions = append(s.Transactions, txn)
}

func (s *Stored) SetGenesis(r Receipt) {
	s.Genesis = r
}

func (s *Stored) GetGenesis() Receipt {
	return s.Genesis
}

func (s *Stored) SetThis(r Receipt) {
	s.This = r
}

func (s *Stored) GetThis() Receipt {
	return s.This
}

func NewStored() *Stored {
	return &Stored{
		Accounts:     make(map[PublicKeyString]Account),
		Receipts:     make(map[HashPointer]Receipt),
		NextReceipts: make(map[HashPointer][]HashPointer),
	}
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
	hi := ChainLength(-1)
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
