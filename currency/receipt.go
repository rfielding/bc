package currency

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

type Flow struct {
	Amount    int64     `json:"amount"`
	PublicKey PublicKey `json:"publickey"`
}

type Flows []Flow

func (f Flows) Serialize() []byte {
	j, err := json.Marshal(f)
	if err != nil {
		log.Printf("cannot serialize flow!")
		panic(err)
	}
	return j
}

type Signoff struct {
	Nonce     Nonce      `json:"nonce"`
	Signature *Signature `json:"signature"`
}

type Transaction struct {
	Flows    Flows     `json:"flows"`
	Signoffs []Signoff `json:"signoffs"`
}

func (t *Transaction) flowHash(i int) []byte {
	// Translate into ecdsa package format
	hash := sha256.New()
	hash.Write(t.Flows.Serialize())
	hash.Write([]byte(fmt.Sprintf("%d", t.Signoffs[i].Nonce)))
	return hash.Sum(nil)
}

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
	if len(t.Signoffs) != len(t.Flows) {
		return false
	}
	for i := 0; i < len(t.Signoffs); i++ {
		// Only negative flows need to be signed
		if t.Flows[i].Amount > 0 {
			continue
		}
		h := t.flowHash(i)
		r := t.Signoffs[i].Signature.X
		s := t.Signoffs[i].Signature.Y
		k := &ecdsa.PublicKey{
			Curve: Curve,
			X:     t.Flows[i].PublicKey.X,
			Y:     t.Flows[i].PublicKey.Y,
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

type Receipt struct {
	Hashed Hashed        `json:"hashed"`
	This   HashPointer   `json:"this"`
	Next   []HashPointer `json:"-"`
}

func (r *Receipt) Serialize() []byte {
	j, err := json.Marshal(r)
	if err != nil {
		log.Printf("cannot serialize receipt!")
		panic(err)
	}
	return j
}

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

func Pub(k *ecdsa.PrivateKey) PublicKey {
	return PublicKey{X: k.PublicKey.X, Y: k.PublicKey.Y}
}
