package main

import (
	"log"

	"github.com/rfielding/bc/currency"
)

func main() {
	var db currency.Db
	var dbt *currency.DbImpl
	dbt = currency.NewDbImpl()
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

	txn1 := &currency.Transaction{
		Signoffs: []currency.Signoff{{Nonce: 0}, {Nonce: 0}},
		Flows: currency.Flows{
			currency.Flow{Amount: -100, PublicKey: currency.Pub(treasuryPriv)},
			currency.Flow{Amount: 100, PublicKey: currency.Pub(alicePriv)},
		},
	}
	db.Sign(treasuryPriv, txn1, 0)
	db.Sign(alicePriv, txn1, 1)

	txn2 := db.Sign(treasuryPriv, &currency.Transaction{
		Signoffs: []currency.Signoff{{Nonce: 1}, {}},
		Flows: currency.Flows{
			currency.Flow{Amount: -20, PublicKey: currency.Pub(treasuryPriv)},
			currency.Flow{Amount: 20, PublicKey: currency.Pub(bobPriv)},
		},
	}, 0)

	txn3 := db.Sign(alicePriv, &currency.Transaction{
		Signoffs: []currency.Signoff{{Nonce: 0}, {}},
		Flows: currency.Flows{
			currency.Flow{Amount: -5, PublicKey: currency.Pub(alicePriv)},
			currency.Flow{Amount: 5, PublicKey: currency.Pub(bobPriv)},
		},
	}, 0)

	txn4 := db.Sign(alicePriv, &currency.Transaction{
		Signoffs: []currency.Signoff{{Nonce: 1}, {}, {}},
		Flows: currency.Flows{
			currency.Flow{Amount: -10, PublicKey: currency.Pub(alicePriv)},
			currency.Flow{Amount: 5, PublicKey: currency.Pub(bobPriv)},
			currency.Flow{Amount: 5, PublicKey: currency.Pub(charlesPriv)},
		},
	}, 0)

	db.InsertTransaction(*txn1)
	db.InsertTransaction(*txn2)
	db.InsertTransaction(*txn3)
	db.InsertTransaction(*txn4)

	it := db.IterateTransactions()

	err = db.PushTransaction(it.Next())
	if err != nil {
		log.Printf("treasury -> alice: 100")
		panic(err)
	}
	log.Printf("%s", currency.AsJson(db.This()))

	err = db.PushTransaction(it.Next())
	if err != nil {
		log.Printf("treasury -> bob: 20")
		panic(err)
	}
	log.Printf("%s", currency.AsJson(db.This()))

	err = db.PushTransaction(it.Next())
	if err != nil {
		log.Printf("alice -> bob: 5")
		panic(err)
	}
	log.Printf("%s", currency.AsJson(db.This()))

	err = db.PushTransaction(it.Next())
	if err != nil {
		log.Printf("alice -> bob,charles: 5")
		panic(err)
	}
	log.Printf("%s", currency.AsJson(db.This()))

	db.PopReceipt()
	db.PushReceipt(0)
	for db.PopReceipt() {
	}
	for len(db.PeekNextReceipts()) > 0 {
		db.PushReceipt(0)
	}
	log.Printf("dbt: %s", currency.AsJson(dbt))

	//db.PopTransaction()
	db.GotoReceipt(db.Genesis())
	his := db.Highest()
	for i := 0; i < len(his); i++ {
		db.GotoReceipt(his[i])
	}

	log.Printf("dbt: %s", currency.AsJson(dbt))
}
