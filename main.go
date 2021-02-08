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
	"sync"
)

type Reference struct {
	Shard Shard
	Id    Id
}

type Action int

const ActionInsert = Action(0)
const ActionRemove = Action(1)

type Command struct {
	Action Action
	Record *DataRecord
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
	KeyPair *KeyPair
	Shard   Shard
	Data    map[Shard]map[Id]*DataRecord
	State   map[Shard]*Point
	Lock    sync.Mutex
	Curve   elliptic.Curve
}

func zeroPoint(curve elliptic.Curve) *Point {
	xInit, yInit := curve.ScalarBaseMult(nil)
	return &Point{
		X: xInit,
		Y: yInit,
	}
}

func NewKeyPair(curve elliptic.Curve) (*KeyPair,error) {
	s, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Secret: s,
		Point: Point{
			X:      x,
			Y:      y,
		},
	},nil
}

var ZeroPoint = zeroPoint(elliptic.P521())

func NewDB(shard Shard) (*Db, error) {
	curve := elliptic.P521()
	kp,err := NewKeyPair(curve)
	if err != nil {
		return nil,err
	} 
	data := make(map[Shard]map[Id]*DataRecord)
	states := make(map[Shard]*Point)
	return &Db{
		Shard:   shard,
		Data:    data,
		KeyPair: kp,
		State:   states,
		Curve:   curve,
	}, nil
}

func (db *Db) sum(shard Shard, h []byte, neg bool) {
	x1, y1 := db.Curve.ScalarBaseMult(h)
	if neg {
		y1 = new(big.Int).Neg(y1)
	}
	p := db.State[shard]
	x2, y2 := db.Curve.Add(p.X, p.Y, x1, y1)
	p.X = x2
	p.Y = y2
	db.State[shard] = p
}

// Insert the object only if it does not already exist
func (db *Db) Insert(v *DataRecord) (*DataRecord, error) {
	db.Lock.Lock()
	defer db.Lock.Unlock()
	shard := v.Shard
	id := v.Id
	if db.Data[shard] == nil {
		db.Data[shard] = make(map[Id]*DataRecord)
	}
	if db.State[shard] == nil {
		db.State[shard] = ZeroPoint
	}
	_, ok := db.Data[shard][id]
	if ok {
		return nil, fmt.Errorf("object %d already exists", id)
	}
	j := AsJson(v)
	h := sha256.New().Sum([]byte(j))
	db.sum(shard, h, false)
	db.Data[shard][id] = v
	return nil, nil
}

// Remove the record only if it is there
func (db *Db) Remove(vToRemove *DataRecord) (*DataRecord, error) {
	db.Lock.Lock()
	defer db.Lock.Unlock()
	id := vToRemove.Id
	shard := vToRemove.Shard
	if db.Data[shard] == nil {
		db.Data[shard] = make(map[Id]*DataRecord)
	}
	if db.State[shard] == nil {
		db.State[shard] = ZeroPoint
	}
	v, ok := db.Data[shard][id]
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
	db.sum(shard, h, true)
	delete(db.Data[shard], id)
	if len(db.Data[shard]) == 0 {
		delete(db.Data, shard)
	}
	return v, nil
}

func (db *Db) Do(cmd Command) (*DataRecord, error) {
	if cmd.Action == ActionInsert {
		return db.Insert(cmd.Record)
	}
	if cmd.Action == ActionRemove {
		return db.Remove(cmd.Record)
	}
	return nil, nil
}

func (db *Db) Checksum(shard Shard) string {
	db.Lock.Lock()
	defer db.Lock.Unlock()
	s, ok := db.State[shard]
	if !ok {
		return ","
	}
	return fmt.Sprintf(
		"%s,%s",
		hex.EncodeToString(s.X.Bytes()),
		hex.EncodeToString(s.Y.Bytes()),
	)
}

type KeyPair struct {
	Secret []byte
	Point Point
}

func main() {
	db, err := NewDB(42)
	if err != nil {
		panic(err)
	}
	fmt.Printf("initial checksum: %s\n\n", db.Checksum(db.Shard))
	db.Do(Command{
		Action: ActionInsert,
		Record: &DataRecord{
			Shard: db.Shard,
			Id:    1,
			TTL:   20,
			Name:  "initial",
		},
	})
	fmt.Printf("id1: %s\n\n", db.Checksum(db.Shard))

	db.Do(Command{
		Action: ActionInsert,
		Record: &DataRecord{
			Shard: db.Shard,
			Id:    2,
			TTL:   21,
			Name:  "secondary",
		},
	})
	fmt.Printf("id1 + id2: %s\n\n", db.Checksum(db.Shard))

	db.Do(Command{Action: ActionRemove, Record: db.Data[db.Shard][2]})
	fmt.Printf("id1: %s\n\n", db.Checksum(db.Shard))

	db.Do(Command{Action: ActionRemove, Record: db.Data[db.Shard][1]})
	fmt.Printf("empty checksum: %s\n\n", db.Checksum(db.Shard))

	db.Do(Command{
		Action: ActionInsert,
		Record: &DataRecord{
			Shard: 101,
			Id:    1,
			TTL:   50,
			Name:  "otherdata",
		},
	})
	fmt.Printf("shard %d, id1: %s\n\n", 101, db.Checksum(101))

}
