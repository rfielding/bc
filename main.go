package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"sync"
)

type Action int

const ActionInsert = Action(0)
const ActionRemove = Action(1)

type Id int64
type Shard int64

type Reference struct {
	Shard Shard `json:"shard,omitempty"`
	Id    Id    `json:"id,omitempty"`
}

type Command struct {
	Action Action      `json:"action,omitempty"`
	Record *DataRecord `json:"record,omitempty"`
}

type DataRecord struct {
	Shard   Shard                `json:"shard,omitempty"`
	Id      Id                   `json:"id,omitempty"`
	TTL     int64                `json:"ttl,omitempty"`
	Refs    map[string]Reference `json:"refs,omitempty"`
	Ints    map[string]int64     `json:"ints,omitempty"`
	Strings map[string]string    `json:"strings,omitempty"`
}

type State struct {
	Data      map[Id]*DataRecord `json:"data,omitempty"`
	KeyPair   *ecdsa.PrivateKey  `json:"keypair,omitempty"`
	Checksum  *Point             `json:"checksum,omitempty"`
	PublicKey *Point             `json:"publickey,omitempty"`
	HighestId Id                 `json:"highestid,omitempty"`
}

type Point struct {
	X *big.Int `json:"x,omitempty"`
	Y *big.Int `json:"y,omitempty"`
}

type Db struct {
	State map[Shard]*State `json:"state,omitempty"`
	Lock  sync.Mutex       `json:-`
}

var Curve = elliptic.P521()
var zPoint = zeroPoint(Curve)

func AsJson(v interface{}) string {
	s, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("cannot marshal data: %v", err))
	}
	return string(s)
}

func newState() *State {
	return &State{
		Data:     make(map[Id]*DataRecord),
		Checksum: zPoint,
	}
}

func zeroPoint(curve elliptic.Curve) *Point {
	xInit, yInit := curve.ScalarBaseMult(nil)
	return &Point{
		X: xInit,
		Y: yInit,
	}
}

func newKeyPair(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(Curve, rand.Reader)
}

func NewDB(shard Shard) (*Db, error) {
	kp, err := newKeyPair(Curve)
	if err != nil {
		return nil, err
	}
	db := &Db{
		State: make(map[Shard]*State),
	}
	db.State[shard] = newState()
	db.State[shard].KeyPair = kp
	return db, nil
}

func (state *State) sum(h []byte, neg bool) {
	x1, y1 := Curve.ScalarBaseMult(h)
	if neg {
		y1 = new(big.Int).Neg(y1)
	}
	ck := state.Checksum
	x2, y2 := Curve.Add(ck.X, ck.Y, x1, y1)
	ck.X = x2
	ck.Y = y2
}

// Insert the object only if it does not already exist
func (db *Db) Insert(v *DataRecord) (*DataRecord, error) {
	db.Lock.Lock()
	defer db.Lock.Unlock()

	shard := v.Shard
	if db.State[shard] == nil {
		db.State[shard] = newState()
	}
	st := db.State[shard]
	if v.Id == 0 {
		st.HighestId++
		v.Id = st.HighestId
	}
	id := v.Id

	_, ok := st.Data[id]
	if ok {
		return nil, fmt.Errorf("object %d already exists", id)
	}
	j := AsJson(v)
	h := sha256.New().Sum([]byte(j))
	st.sum(h, false)
	st.Data[id] = v
	return v, nil
}

// Remove the record only if it is there
func (db *Db) Remove(vToRemove *DataRecord) (*DataRecord, error) {
	db.Lock.Lock()
	defer db.Lock.Unlock()

	shard := vToRemove.Shard

	if db.State[shard] == nil {
		db.State[shard] = newState()
	}
	st := db.State[shard]
	id := vToRemove.Id

	v, ok := st.Data[id]
	if !ok {
		return nil, fmt.Errorf(
			"object %d:%d cannot be removed, because it does not exist",
			shard, id,
		)
	}
	jToRemove := AsJson(vToRemove)
	hToRemove := sha256.New().Sum([]byte(jToRemove))
	j := AsJson(v)
	h := sha256.New().Sum([]byte(j))
	if bytes.Compare(hToRemove, h) != 0 {
		return nil, fmt.Errorf(
			"we are not removing the object %d:%d we think we are removing",
			shard, id,
		)
	}
	st.sum(h, true)
	delete(st.Data, id)
	return v, nil
}

func (db *Db) Do(cmd Command) (*DataRecord, error) {
	var r *DataRecord
	var err error
	if cmd.Action == ActionInsert {
		r, err = db.Insert(cmd.Record)
	}
	if cmd.Action == ActionRemove {
		r, err = db.Remove(cmd.Record)
	}
	if err != nil {
		log.Printf("error! %v", err)
	}
	log.Printf("%s", AsJson(cmd))
	return r, err
}

func (db *Db) Checksum(shard Shard) string {
	db.Lock.Lock()
	defer db.Lock.Unlock()
	st, ok := db.State[shard]
	if !ok {
		return fmt.Sprintf("%d:,", shard)
	}
	return fmt.Sprintf(
		"%d:%s,%s",
		shard,
		hex.EncodeToString(st.Checksum.X.Bytes()),
		hex.EncodeToString(st.Checksum.Y.Bytes()),
	)
}

func (db *Db) Sign(shard Shard) (*Point, error) {
	h := sha256.New().Sum([]byte(db.Checksum(shard)))
	r, s, err := ecdsa.Sign(rand.Reader, db.State[shard].KeyPair, h)
	return &Point{X: r, Y: s}, err
}

func (db *Db) Verify(shard Shard, sig *Point) bool {
	h := sha256.New().Sum([]byte(db.Checksum(shard)))
	r := sig.X
	s := sig.Y
	return ecdsa.Verify(&db.State[shard].KeyPair.PublicKey, h, r, s)
}

func (db *Db) Get(shard Shard, id Id) *DataRecord {
	return db.State[shard].Data[id]
}

func main() {
	dbShard := Shard(22)
	db, err := NewDB(dbShard)
	if err != nil {
		panic(err)
	}
	fmt.Printf("initial checksum: %s\n\n", db.Checksum(dbShard))
	db.Do(Command{
		Action: ActionInsert,
		Record: &DataRecord{
			Shard: dbShard,
			TTL:   20,
		},
	})
	fmt.Printf("id1: %s\n\n", db.Checksum(dbShard))
	sig, err := db.Sign(dbShard)
	if err != nil {
		panic(err)
	}
	fmt.Printf("sign %d: %s\n\n", dbShard, AsJson(sig))

	db.Do(Command{
		Action: ActionInsert,
		Record: &DataRecord{
			Shard: dbShard,
			TTL:   21,
		},
	})
	fmt.Printf("id1+id2: %s\n\n", db.Checksum(dbShard))

	db.Do(Command{Action: ActionRemove, Record: db.Get(dbShard, 2)})
	fmt.Printf("id1: %s\n\n", db.Checksum(dbShard))

	// BUG .... this should not affect dbShard at all!
	dbShard2 := Shard(202)
	db.Do(Command{
		Action: ActionInsert,
		Record: &DataRecord{
			Shard: dbShard2,
			TTL:   50,
		},
	})
	fmt.Printf("shard %d, id1: %s\n\n", dbShard2, db.Checksum(dbShard2))
	db.Do(Command{Action: ActionRemove, Record: db.Get(dbShard2, 1)})

	verified := db.Verify(dbShard, sig)
	fmt.Printf("verify: %t\n\n", verified)

	db.Do(Command{Action: ActionRemove, Record: db.Get(dbShard, 1)})
	fmt.Printf("empty checksum: %s\n\n", db.Checksum(dbShard))

	//fmt.Printf("%s\n\n", AsJson(db))
}
