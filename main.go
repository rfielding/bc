package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
)

/*
  Experiment in an alternative "blockchain-style" database.
  Current blockchains (ie: hashpointered data structures)
  are integrity checking the EVENT STREAM that creates
  the database, rather than integrity checking the DATA.

  You should get the same signature on the database if
  the contents are the same.  The event stream grows
  ever larger, so it can't be garbage collected.

  But if the actual DATA created by the event stream
  has the same checksum after compaction as the checksum
  you get by creating it FROM the event stream, then
  this opens up the possibility of a garbage-collected
  block chain.

  Example:
  - records with TTL states on them.
  - each record insert increases a logical clock time.
  - when TTL passes for a record, it is permissible to remove the record.
  - in the hash of the database, so it can be physically removed.
  - In order for not grow indefinitely:
    - It must be possible for the Insert rate to match Remove rate
    - When insert rate is higher than remove rate, data usage grows indefinitely
    - Inactive data can be purged.

  The idea is to lease space in the database.  If it is to live for a long time,
  then this privilege must be paid for; or the lease must be periodically
  renewed.  Otherwise, orphans can never exit the system.

  The basic idea:

  - Instead of a block chain like:
     H( ... H( H(record0) + record1) ... )
  - Do more like this, so hashes commute:
     H(record0) + H(record1) + H(record2) + ...
  - Use Elliptic curve points to accumulate data
  - Remove records by subtracting them out of the point sum

  Use the "immutable" log to generate a mutable DATABASE,
  in a Paxos/Raft style.

  But DONT checksum the log.  Checksum the DATA.
  Trash-compacted data signatures should come out the same
  as signatures over the original event log.

  Events (mostly) commute.  If a record is inserted before removed,
  then the database result will be different from when it is
  removed before it is inserted.  But this is fine.
  We want to know if database states are consistent.

  Insert and Remove events should be maintained in a
  list from a given state.  This is used to efficiently diff two copies.
*/

type Reference struct {
	Shard Shard
	Id    Id
}

type DataRecord struct {
	Shard   Shard
	Id      Id
	TTL     int64
	Refs    map[string]Reference
	Name    string
	Strings map[string]string
}

func AsJson(v interface{}) string {
	s, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("cannot marshal data: %v", err))
	}
	return string(s)
}

type Id int64
type Shard int64

type Point struct {
	X *big.Int
	Y *big.Int
}

type Db struct {
	Shard   Shard
	Data    map[Shard]map[Id]*DataRecord
	State   map[Shard]Point
	KeyPair KeyPair
}

func NewDB(shard Shard) (*Db, error) {
	s, x, y, err := elliptic.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, err
	}
	kp := KeyPair{
		Curve:  elliptic.P521(),
		Secret: s,
		X:      x,
		Y:      y,
	}
	xInit, yInit := kp.Curve.ScalarBaseMult(nil)
	data := make(map[Shard]map[Id]*DataRecord)
	data[shard] = make(map[Id]*DataRecord)
	states := make(map[Shard]Point)
	states[shard] = Point{
		X: xInit,
		Y: yInit,
	}
	return &Db{
		Shard:   shard,
		Data:    data,
		KeyPair: kp,
		State:   states,
	}, nil
}

func (db *Db) sum(h []byte, neg bool) {
	x1, y1 := db.KeyPair.Curve.ScalarBaseMult(h)
	if neg {
		y1 = new(big.Int).Neg(y1)
	}
	p := db.State[db.Shard]
	x2, y2 := db.KeyPair.Curve.Add(p.X, p.Y, x1, y1)
	p.X = x2
	p.Y = y2
	db.State[db.Shard] = p
}

// Insert the record if it does not exist
// Delete and re-insert if it exists with a different
// value
func (db *Db) Insert(v *DataRecord) error {
	var hExisting []byte
	vExisting, ok := db.Data[db.Shard][v.Id]
	if ok {
		jExisting := AsJson(vExisting)
		hExisting = sha256.New().Sum([]byte(jExisting))
	}
	j := AsJson(v)
	h := sha256.New().Sum([]byte(j))
	// Do nothing if there was an attempt to double-add
	if bytes.Compare(hExisting, h) == 0 {
		return nil
	}
	// Remove and re-add
	if len(hExisting) > 0 {
		db.Remove(v.Id)
	}
	db.sum(h, false)
	db.Data[db.Shard][v.Id] = v
	return nil
}

// Remove the record if it is there
// or do nothing if it is not there
func (db *Db) Remove(id Id) (*DataRecord, error) {
	v, ok := db.Data[db.Shard][id]
	if !ok {
		return nil, nil
	}
	j := AsJson(v)
	h := sha256.New().Sum([]byte(j))
	db.sum(h, true)
	delete(db.Data[db.Shard], id)
	return v, nil
}

func (db *Db) Checksum() string {
	return fmt.Sprintf(
		"%s,%s",
		hex.EncodeToString(db.State[db.Shard].X.Bytes()),
		hex.EncodeToString(db.State[db.Shard].Y.Bytes()),
	)
}

type KeyPair struct {
	Curve  elliptic.Curve
	Secret []byte
	X      *big.Int
	Y      *big.Int
}

func main() {
	db, err := NewDB(42)
	if err != nil {
		panic(err)
	}
	fmt.Printf("initial checksum: %s\n\n", db.Checksum())
	db.Insert(&DataRecord{
		Shard: db.Shard,
		Id:   1,
		TTL:  20,
		Name: "initial",
	})
	fmt.Printf("id1: %s\n\n", db.Checksum())
	db.Insert(&DataRecord{
		Shard: db.Shard,
		Id:   2,
		TTL:  21,
		Name: "secondary",
	})
	fmt.Printf("id1 + id2: %s\n\n", db.Checksum())

	db.Remove(2)
	fmt.Printf("id1: %s\n\n", db.Checksum())

	db.Remove(1)
	fmt.Printf("empty checksum: %s\n\n", db.Checksum())
}
