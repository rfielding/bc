package main

import (
	"log"
)

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

	charlesPriv, err := NewKeyPair()
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
		Signoffs: []Signoff{{Nonce: 0}, {Nonce: 0}},
		Flows: Flows{
			Flow{Amount: -100, PublicKey: Pub(treasuryPriv)},
			Flow{Amount: 100, PublicKey: Pub(alicePriv)},
		},
	}

	// test signing even for receiver
	db.Sign(treasuryPriv, mintAlice, 0)
	db.Sign(alicePriv, mintAlice, 1)

	receipt, err := db.PushTransaction(db.Genesis(), *mintAlice)

	if err != nil {
		log.Printf("treasury -> alice: 100")
		panic(err)
	}
	log.Printf("%s", AsJson(receipt))

	receipt, err = db.PushTransaction(
		receipt,
		*db.Sign(treasuryPriv, &Transaction{
			Signoffs: []Signoff{{Nonce: 1}, {}},
			Flows: Flows{
				Flow{Amount: -20, PublicKey: Pub(treasuryPriv)},
				Flow{Amount: 20, PublicKey: Pub(bobPriv)},
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
			Signoffs: []Signoff{{Nonce: 0}, {}},
			Flows: Flows{
				Flow{Amount: -5, PublicKey: Pub(alicePriv)},
				Flow{Amount: 5, PublicKey: Pub(bobPriv)},
			},
		}, 0),
	)
	if err != nil {
		log.Printf("alice -> bob: 5")
		panic(err)
	}
	log.Printf("%s", AsJson(receipt))

	receipt, err = db.PushTransaction(
		receipt,
		*db.Sign(alicePriv, &Transaction{
			Signoffs: []Signoff{{Nonce: 1}, {}},
			Flows: Flows{
				Flow{Amount: -5, PublicKey: Pub(alicePriv)},
				Flow{Amount: 5, PublicKey: Pub(charlesPriv)},
			},
		}, 0),
	)
	if err != nil {
		log.Printf("alice -> charles: 5")
		panic(err)
	}
	log.Printf("%s", AsJson(receipt))
}
