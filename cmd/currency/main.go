package main

import (
	"log"

	"github.com/rfielding/bc/currency"
)

func main() {
	var db currency.Db
	var dbt *currency.DbTest
	dbt = currency.NewDBTest()
	db = dbt

	alicePriv, err := currency.NewKeyPair()
	if err != nil {
		panic(err)
	}

	bobPriv, err := currency.NewKeyPair()
	if err != nil {
		panic(err)
	}

	charlesPriv, err := currency.NewKeyPair()
	if err != nil {
		panic(err)
	}

	treasuryPriv, err := currency.NewKeyPair()
	if err != nil {
		panic(err)
	}
	// hack to deal with negative balances for now
	db.AsBank(currency.Pub(treasuryPriv))

	mintAlice := &currency.Transaction{
		Signoffs: []currency.Signoff{{Nonce: 0}, {Nonce: 0}},
		Flows: currency.Flows{
			currency.Flow{Amount: -100, PublicKey: currency.Pub(treasuryPriv)},
			currency.Flow{Amount: 100, PublicKey: currency.Pub(alicePriv)},
		},
	}

	// test signing even for receiver
	db.Sign(treasuryPriv, mintAlice, 0)
	db.Sign(alicePriv, mintAlice, 1)

	err = db.PushTransaction(*mintAlice)

	if err != nil {
		log.Printf("treasury -> alice: 100")
		panic(err)
	}
	log.Printf("%s", currency.AsJson(db.This()))

	err = db.PushTransaction(
		*db.Sign(treasuryPriv, &currency.Transaction{
			Signoffs: []currency.Signoff{{Nonce: 1}, {}},
			Flows: currency.Flows{
				currency.Flow{Amount: -20, PublicKey: currency.Pub(treasuryPriv)},
				currency.Flow{Amount: 20, PublicKey: currency.Pub(bobPriv)},
			},
		}, 0),
	)
	if err != nil {
		log.Printf("treasury -> bob: 20")
		panic(err)
	}
	log.Printf("%s", currency.AsJson(db.This()))

	err = db.PushTransaction(
		*db.Sign(alicePriv, &currency.Transaction{
			Signoffs: []currency.Signoff{{Nonce: 0}, {}},
			Flows: currency.Flows{
				currency.Flow{Amount: -5, PublicKey: currency.Pub(alicePriv)},
				currency.Flow{Amount: 5, PublicKey: currency.Pub(bobPriv)},
			},
		}, 0),
	)
	if err != nil {
		log.Printf("alice -> bob: 5")
		panic(err)
	}
	log.Printf("%s", currency.AsJson(db.This()))

	err = db.PushTransaction(
		*db.Sign(alicePriv, &currency.Transaction{
			Signoffs: []currency.Signoff{{Nonce: 1}, {}, {}},
			Flows: currency.Flows{
				currency.Flow{Amount: -10, PublicKey: currency.Pub(alicePriv)},
				currency.Flow{Amount: 5, PublicKey: currency.Pub(bobPriv)},
				currency.Flow{Amount: 5, PublicKey: currency.Pub(charlesPriv)},
			},
		}, 0),
	)
	if err != nil {
		log.Printf("alice -> bob,charles: 5")
		panic(err)
	}
	log.Printf("%s", currency.AsJson(db.This()))

	db.PopTransaction()
	db.RePush(0)
	log.Printf("dbt: %s", currency.AsJson(dbt.Accounts))

	for db.PopTransaction() {
	}
	for len(db.PeekNext()) > 0 {
		db.RePush(0)
	}
	log.Printf("dbt: %s", currency.AsJson(dbt))

	//db.PopTransaction()
	db.Goto(db.Genesis())
	his := db.Highest()
	for i := 0; i < len(his); i++ {
		db.Goto(his[i])
	}

	log.Printf("dbt: %s", currency.AsJson(dbt))

}
