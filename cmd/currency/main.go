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
type Flow struct {
	Inputs  []Input  `json:"inputs"`
	Outputs []Output `json:"outputs"`
}

// Serialize into a byte array
func (f *Flow) Serialize() []byte {
	j, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		log.Printf("cannot serialize flow!")
		panic(err)
	}
	return j
}

// Inputs must be signed, because funds come out of it.
type Input struct {
	Nonce     Nonce     `json:"nonce"`
	Amount    int64     `json:"amount"`
	PublicKey PublicKey `json:"publickey"`
}

// Outputs need not be signed, because they receive funds.
type Output struct {
	Amount    int64     `json:"amount"`
	PublicKey PublicKey `json:"publickey"`
}

type Transaction struct {
	Flow       Flow         `json:"flow"`
	Signatures []*Signature `json:"signature"`
}


// Give each participant a change to sign the flow
func (t *Transaction) Sign(k *ecdsa.PrivateKey) error {
	i := 0
	// Translate into ecdsa package format
	h := sha256.New().Sum(t.Flow.Serialize())
	r, s, err := ecdsa.Sign(rand.Reader, k, h)
	if err != nil {
		return err
	}
	t.Signatures[i] = &Signature{X: r, Y: s}
	return nil
}

func (t *Transaction) Verify() bool {
	for i := 0; i < len(t.Signatures); i++ {
		h := sha256.New().Sum(t.Flow.Serialize())
		r := t.Signatures[i].X
		s := t.Signatures[i].Y
		k := &ecdsa.PublicKey{
			Curve: Curve,
			X:     t.Flow.Inputs[i].PublicKey.X,
			Y:     t.Flow.Inputs[i].PublicKey.Y,
		}
		v := ecdsa.Verify(k, h, r, s)
		if v == false {
			return v
		}
	}
	return true
}

type ChainLength int64

type Checked struct {
	Transaction Transaction `json:"transaction"`
	ChainLength ChainLength `json:"chainlength"`
	Previous    HashPointer `json:"previous"`
}

// A transaction gets accepted, and resulting data is injected
// []Next is mutable!
type Receipt struct {
	Checked Checked        `json:"checked"`
	This    HashPointer    `json:"this"`
	Next    []HashPointer  `json:"-"`
}

// Serialize into a byte array
func (r *Receipt) Serialize() []byte {
	j, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		log.Printf("cannot serialize receipt!")
		panic(err)
	}
	return j
}

// Hashes
func (r *Receipt) HashPointer() HashPointer {
	j, err := json.MarshalIndent(r.Checked, "", "  ")
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

	// Insert, and sign it if we can
	InsertTransaction(rcpt Receipt, txn Transaction) (Receipt, error)

	Sign(k *ecdsa.PrivateKey, txn *Transaction) Transaction

	//	// Find a spot in the chain
	//	Find(h HashPointer) (Receipt, error)

	// Find longest chain known
	FindLongest() (Receipt, error)

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

func (db *DbTest) Sign(k *ecdsa.PrivateKey, t *Transaction) *Transaction {
	// one signer for now
	t.Signatures = make([]*Signature, 1)
	t.Sign(k)
	return t
}
func (db *DbTest) SignTransaction(t *Transaction, k *ecdsa.PrivateKey) error {
	return t.Sign(k)
}

func Pub(k *ecdsa.PrivateKey) PublicKey {
	return PublicKey{X: k.PublicKey.X, Y: k.PublicKey.Y}
}

// receipt, pleaseWait, error
func (db *DbTest) InsertTransaction(prevr Receipt, txn Transaction) (Receipt, error) {
	// if no error, then this is meaningful
	r := Receipt{}

	// bad signature
	result := txn.Verify()
	if result == false {
		return r, ErrSigFail
	}

	// Flows add to zero
	total := int64(0)
	for i := 0; i < len(txn.Flow.Inputs); i++ {
		total -= txn.Flow.Inputs[i].Amount
	}
	for i := 0; i < len(txn.Flow.Outputs); i++ {
		total += txn.Flow.Outputs[i].Amount
	}
	if total != 0 {
		return r, ErrNonZeroSum
	}

	// Inputs must match nonce on account
	for i := 0; i < len(txn.Flow.Inputs); i++ {
		// look up the account
		pks := NewPublicKeyString(txn.Flow.Inputs[i].PublicKey)
		a := db.Accounts[pks]
		// if account not found, then add it as empty
		if a == nil {
			a = &Account{}
			a.PublicKey = txn.Flow.Inputs[i].PublicKey
			a.Nonce = 0
		}
		if a.Amount - txn.Flow.Inputs[i].Amount < 0 && db.IsBank[pks]==false {
			return r, ErrBelowZero
		}
		if a.Nonce < txn.Flow.Inputs[i].Nonce {
			return r, ErrWait
		}
		// need a better solution to bank negative balance
		if a.Nonce > txn.Flow.Inputs[i].Nonce {
			return r, ErrReplay
		}
		db.Accounts[pks] = a
	}


	for i := 0; i < len(txn.Flow.Inputs); i++ {
		pks := NewPublicKeyString(txn.Flow.Inputs[i].PublicKey)
		db.Accounts[pks].Nonce++
		db.Accounts[pks].Amount -= txn.Flow.Inputs[i].Amount
	}
	for i := 0; i < len(txn.Flow.Outputs); i++ {
		pks := NewPublicKeyString(txn.Flow.Outputs[i].PublicKey)
		a := db.Accounts[pks]
		if a == nil {
			db.Accounts[pks] = &Account{
				PublicKey: txn.Flow.Outputs[i].PublicKey,
			}
		}
		db.Accounts[pks].Amount += txn.Flow.Outputs[i].Amount
	}

	// write out the receipt data
	r.Checked.Transaction = txn
	r.Checked.ChainLength = prevr.Checked.ChainLength + 1
	r.Checked.Previous = prevr.This
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
	db.AsBank(Pub(treasuryPriv))

	receipt, err := db.InsertTransaction(
		db.Genesis(),
		*db.Sign(treasuryPriv,&Transaction{
			Flow: Flow{
				Inputs: []Input{
					Input{
						Nonce:     0,
						Amount:    100,
						PublicKey: Pub(treasuryPriv),
					},
				},
				Outputs: []Output{
					Output{
						Amount:    100,
						PublicKey: Pub(alicePriv),
					},
				},
			},
		}),
	)
	if err != nil {
		panic(err)
	}
	log.Printf("%s", AsJson(receipt))

	receipt, err = db.InsertTransaction(
		receipt,
		*db.Sign(treasuryPriv,&Transaction{
			Flow: Flow{
				Inputs: []Input{
					Input{
						Nonce:     1,
						Amount:    20,
						PublicKey: Pub(treasuryPriv),
					},
				},
				Outputs: []Output{
					Output{
						Amount:    20,
						PublicKey: Pub(bobPriv),
					},
				},
			},
		}),
	)
	if err != nil {
		panic(err)
	}
	log.Printf("%s", AsJson(receipt))

	receipt, err = db.InsertTransaction(
		receipt,
		*db.Sign(alicePriv,&Transaction{
			Flow: Flow{
				Inputs: []Input{
					Input{
						Nonce:     0,
						Amount:    5,
						PublicKey: Pub(alicePriv),
					},
				},
				Outputs: []Output{
					Output{
						Amount:    5,
						PublicKey: Pub(bobPriv),
					},
				},
			},
		}),
	)
	if err != nil {
		panic(err)
	}
	log.Printf("%s", AsJson(receipt))
}
