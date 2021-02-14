package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
)

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

func AsJson(v interface{}) string {
	s, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("cannot marshal data: %v", err))
	}
	return string(s)
}

// Private keys are just bytes
type PrivateKey []byte

// Public keys and signatures are elliptic curve points
type Point struct {
	X *big.Int `json:"x"`
	Y *big.Int `json:"y"`
}

// A public key is an ec point
type PublicKey Point
type PublicKeyString string

func NewPublicKeyString(k PublicKey) PublicKeyString {
	j, err := json.Marshal(k)
	if err != nil {
		panic(err)
	}
	return PublicKeyString(j)
}

// A hash that should point to a previous transaction
type HashPointer string

// The nonce to stop double-spending
type Nonce int64

// The state of the whole system is
// an array of accounts, with a balance and a nonce
type Account struct {
	// input or output destination
	PublicKey PublicKey `json:"publickey"`

	// numeric amount
	Amount int64 `json:"amount"`

	// used to stop double-spending
	Nonce Nonce `json:"nonce"`
}

// Signatures are points
type Signature Point

// This is what is critical for Input keys to sign
type Signed struct {
	Inputs  []Input  `json:"inputs"`
	Outputs []Output `json:"outputs"`
}

// This is exactly what gets signed.
func (f *Signed) Serialize() []byte {
	j, err := json.Marshal(f)
	if err != nil {
		log.Printf("cannot serialize flow!")
		panic(err)
	}
	return j
}

// Inputs must be signed, because funds come out of it.
type Input struct {
	Amount    int64     `json:"amount"`
	PublicKey PublicKey `json:"publickey"`
}

// Outputs need not be signed, because they receive funds.
type Output struct {
	Amount    int64     `json:"amount"`
	PublicKey PublicKey `json:"publickey"`
}

type Signoff struct {
	Nonce     Nonce      `json:"nonce"`
	Signature *Signature `json:"signature"`
}

// every entity that is providing an input MUST sign,
// and include a nonce on when it's valid
type Transaction struct {
	Signed   Signed    `json:"signed"`
	Signoffs []Signoff `json:"signoffs"`
}

func (t *Transaction) flowHash(i int) []byte {
	// Translate into ecdsa package format
	hash := sha256.New()
	hash.Write(t.Signed.Serialize())
	hash.Write([]byte(fmt.Sprintf("%d", t.Signoffs[i].Nonce)))
	return hash.Sum(nil)
}

// Give each participant a chance to sign the flow
func (t *Transaction) Sign(k *ecdsa.PrivateKey, i int) error {
	h := t.flowHash(i)
	r, s, err := ecdsa.Sign(rand.Reader, k, h)
	if err != nil {
		return err
	}
	t.Signoffs[i].Signature = &Signature{X: r, Y: s}
	return nil
}

func (t *Transaction) Verify() bool {
	if len(t.Signoffs) != len(t.Signed.Inputs) {
		return false
	}
	for i := 0; i < len(t.Signoffs); i++ {
		h := t.flowHash(i)
		r := t.Signoffs[i].Signature.X
		s := t.Signoffs[i].Signature.Y
		k := &ecdsa.PublicKey{
			Curve: Curve,
			X:     t.Signed.Inputs[i].PublicKey.X,
			Y:     t.Signed.Inputs[i].PublicKey.Y,
		}
		v := ecdsa.Verify(k, h, r, s)
		if v == false {
			return v
		}
	}
	return true
}

type ChainLength int64

type Hashed struct {
	Transaction Transaction `json:"transaction"`
	ChainLength ChainLength `json:"chainlength"`
	Previous    HashPointer `json:"previous"`
}

// A transaction gets accepted, and resulting data is injected
// []Next is mutable!
type Receipt struct {
	Hashed Hashed        `json:"hashed"`
	This   HashPointer   `json:"this"`
	Next   []HashPointer `json:"-"`
}

// Serialize into a byte array
func (r *Receipt) Serialize() []byte {
	j, err := json.Marshal(r)
	if err != nil {
		log.Printf("cannot serialize receipt!")
		panic(err)
	}
	return j
}

// Hashes
func (r *Receipt) HashPointer() HashPointer {
	j, err := json.Marshal(r.Hashed)
	if err != nil {
		log.Printf("cannot serialize receipt!")
		panic(err)
	}
	h := sha256.Sum256(j)
	return HashPointer(hex.EncodeToString(h[:]))
}

var Curve = elliptic.P521()

func NewKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(Curve, rand.Reader)
}

// The database stores a bunch of records
type Db interface {
	AsBank(k PublicKey)

	PushTransaction(rcpt Receipt, txn Transaction) (Receipt, error)

	Sign(k *ecdsa.PrivateKey, txn *Transaction, i int) Transaction

	Find(h HashPointer) (Receipt, bool)

	// Find longest chain known
	FindLongest() (Receipt, bool)

	Genesis() Receipt
}

type DbTest struct {
	IsBank         map[PublicKeyString]bool
	Accounts       map[PublicKeyString]*Account
	Receipts       map[HashPointer]*Receipt
	GenesisReceipt Receipt
}

func NewDBTest() *DbTest {
	g := Receipt{}
	return &DbTest{
		IsBank:         make(map[PublicKeyString]bool),
		Accounts:       make(map[PublicKeyString]*Account),
		Receipts:       make(map[HashPointer]*Receipt),
		GenesisReceipt: g,
	}
}

func (db *DbTest) Genesis() Receipt {
	return db.GenesisReceipt
}

func (db *DbTest) AsBank(k PublicKey) {
	pks := NewPublicKeyString(k)
	db.IsBank[pks] = true
}

func (db *DbTest) Sign(k *ecdsa.PrivateKey, t *Transaction, i int) *Transaction {
	// one signer for now
	if len(t.Signed.Inputs) != len(t.Signoffs) {
		return nil
	}
	t.Sign(k, i)
	return t
}
func (db *DbTest) SignTransaction(t *Transaction, k *ecdsa.PrivateKey, i int) error {
	return t.Sign(k, i)
}

func Pub(k *ecdsa.PrivateKey) PublicKey {
	return PublicKey{X: k.PublicKey.X, Y: k.PublicKey.Y}
}

// receipt, pleaseWait, error
func (db *DbTest) PushTransaction(prevr Receipt, txn Transaction) (Receipt, error) {
	// if no error, then this is meaningful
	r := Receipt{}

	if len(txn.Signed.Inputs) != len(txn.Signoffs) {
		return r, ErrMalformed
	}

	// bad signature
	result := txn.Verify()
	if result == false {
		return r, ErrSigFail
	}

	// Signed add to zero
	total := int64(0)
	for i := 0; i < len(txn.Signed.Inputs); i++ {
		total -= txn.Signed.Inputs[i].Amount
	}
	for i := 0; i < len(txn.Signed.Outputs); i++ {
		total += txn.Signed.Outputs[i].Amount
	}
	if total != 0 {
		return r, ErrNonZeroSum
	}

	// Inputs must match nonce on account
	for i := 0; i < len(txn.Signed.Inputs); i++ {
		// look up the account
		pks := NewPublicKeyString(txn.Signed.Inputs[i].PublicKey)
		a := db.Accounts[pks]
		// if account not found, then add it as empty
		if a == nil {
			a = &Account{}
			a.PublicKey = txn.Signed.Inputs[i].PublicKey
			a.Nonce = 0
		}
		if a.Amount-txn.Signed.Inputs[i].Amount < 0 && db.IsBank[pks] == false {
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

	for i := 0; i < len(txn.Signed.Inputs); i++ {
		pks := NewPublicKeyString(txn.Signed.Inputs[i].PublicKey)
		db.Accounts[pks].Nonce++
		db.Accounts[pks].Amount -= txn.Signed.Inputs[i].Amount
	}
	for i := 0; i < len(txn.Signed.Outputs); i++ {
		pks := NewPublicKeyString(txn.Signed.Outputs[i].PublicKey)
		a := db.Accounts[pks]
		if a == nil {
			db.Accounts[pks] = &Account{
				PublicKey: txn.Signed.Outputs[i].PublicKey,
			}
		}
		db.Accounts[pks].Amount += txn.Signed.Outputs[i].Amount
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
	return r, nil
}

func (db *DbTest) Find(h HashPointer) (Receipt, error) {
	r := db.Receipts[h]
	if r == nil {
		return Receipt{}, ErrNotFound
	}
	return *r, nil
}

func main() {
	db := NewDBTest()

	alicePriv, err := NewKeyPair()
	if err != nil {
		panic(err)
	}

	bobPriv, err := NewKeyPair()
	if err != nil {
		panic(err)
	}

	treasuryPriv, err := NewKeyPair()
	if err != nil {
		panic(err)
	}
	// hack to deal with negative balances for now
	db.AsBank(Pub(treasuryPriv))

	mintAlice := &Transaction{
		Signoffs: []Signoff{{Nonce: 0}},
		Signed: Signed{
			Inputs:  []Input{{Amount: 100, PublicKey: Pub(treasuryPriv)}},
			Outputs: []Output{{Amount: 100, PublicKey: Pub(alicePriv)}},
		},
	}

	db.Sign(treasuryPriv, mintAlice, 0)

	receipt, err := db.PushTransaction(db.Genesis(), *mintAlice)

	if err != nil {
		log.Printf("treasury -> alice: 100")
		panic(err)
	}
	log.Printf("%s", AsJson(receipt))

	receipt, err = db.PushTransaction(
		receipt,
		*db.Sign(treasuryPriv, &Transaction{
			Signoffs: []Signoff{{Nonce: 1}},
			Signed: Signed{
				Inputs:  []Input{{Amount: 20, PublicKey: Pub(treasuryPriv)}},
				Outputs: []Output{{Amount: 20, PublicKey: Pub(bobPriv)}},
			},
		}, 0),
	)
	if err != nil {
		log.Printf("treasury -> bob: 20")
		panic(err)
	}
	log.Printf("%s", AsJson(receipt))

	receipt, err = db.PushTransaction(
		receipt,
		*db.Sign(alicePriv, &Transaction{
			Signoffs: []Signoff{{Nonce: 0}},
			Signed: Signed{
				Inputs:  []Input{{Amount: 5, PublicKey: Pub(alicePriv)}},
				Outputs: []Output{{Amount: 5, PublicKey: Pub(bobPriv)}},
			},
		}, 0),
	)
	if err != nil {
		log.Printf("alice -> bob: 5")
		panic(err)
	}
	log.Printf("%s", AsJson(receipt))
}
