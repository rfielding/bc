# bc

This is a POC for how you would garbage-collect a block-chained structure.
Normally, it's the EVENT stream that is blockchained, rather than the DATABASE
that contains all the data.  A few problems:

- A list of events always grows larger, by definition.
- If you use hashpointers, there isn't a straightforward mechanism to do trash-compacting without invalidating things.  That is the point, but it may be an _unnecessary_ point.
- What you really want is to validate that the DATABASE has the contents you expect.  It doesn't MATTER how you created the database.

So, instead of chaining hashes together to make every object transitively immutable:

```
((value0 * Hashfunc) + value1) * Hashfunc
```
Iterating this is non-commutative, and non-associative.


As an alternative, we can just iterate the contents:

```
(value0 * Hashfunc) + (value1 * Hashfunc) ....
```

The result is that including objects is associative, and mostly commutative.  (ie: Add then Delete is not the same result as Delete then Add.  If you want that to ALSO commute, then you have to hold a request to delete until it is actually added.  ie: a negative reference count, so that when it is added, it still doesn't appear in the database.)

The reason you want to do this is that:

- When you add an object into a database, its hash is added.
- When you delete an object from the database, its hash is removed.
- This is done by hashing objects into Elliptic Curve points


```
# The trash-compacted version of this data is fine.
obj1 + obj2 + obj3 + -obj2 = obj1 + obj3
```

So, if I sign a non-trash-compacted version of it, the signature is still unchanged after garbage collection.

Example:

```
go run main.go

011acfc8e174fe566b31d9d52973156c95baf9f4befa4742122706fee4c72e056c5ed0c098ef2ed8ee7dfc180f2eae2716fa5aa18a22a395d49a75a5c31da134cd46,3b0c5b1358ec4dfef20f26854df8afcca10ebad5776f23fad79404cb2c33db4a9795804925104f6718c27c2bc328295d75b19dc5ee4770030baef1a5261f9e4dd2

7e2b0a7095e1f431354e724fd9360554816ae9cdd63f84f5d01cda0deda08c65ce49823d14f4bbbe196840fec31fe66fee1939a638bc569fc3507e2970deca1f4b,9958ab798e7955c0c8db51a7925da800a9840e454f6fef9713bd0f1e760b1817da2f00ecd4fa1ac6f98441b89135d5609012719ed4e6ea277c11f58af08dcf5967

011acfc8e174fe566b31d9d52973156c95baf9f4befa4742122706fee4c72e056c5ed0c098ef2ed8ee7dfc180f2eae2716fa5aa18a22a395d49a75a5c31da134cd46,3b0c5b1358ec4dfef20f26854df8afcca10ebad5776f23fad79404cb2c33db4a9795804925104f6718c27c2bc328295d75b19dc5ee4770030baef1a5261f9e4dd2
```

This is:

```
insert event1
insert event2
remove event1
```

# Shards

![shards.png](shards.png)

The database is cut into shards.  Each shard is associated with a writer. The writer has the private key for signing off on contents of a shard.  The public key is obtainable for all shards.  The hashes being signed are over which objects are currently _in_ the database; not a signature over the event stream itself.

![trashcompact.png](trashcompact.png)

With trash compacting, the longer full stream of events should hash to the same value as the trash-compacted version.  Due to queueing theory, the size of the database will grow indefinitely unless the Insert rate is the same as the Remove rate.  If content is not leased (ie: written with some kind of expiration date, or deprecation on inactivity), then it may stay in the database too long.

![crdt.png](crdt.png)

The main synchronization is in getting eventual consistency between peers.  All pointers must point _back_ to existing data, so being up to date is consistent.  The running checksum per shard can be combined with signatures from the owner of the shard; to know that the owner signs off on the contents of the shard.


![steadystate.png](steadystate.png)

When events go into a system, we must be able to remove events at the same rate that they are inserted.  Otherwise, the event stream and database will grow to unbounded size.  We need to checksum the contents of the database.  A typical blockchain is checksumming the data stream.  But if there is high turnover in the database, with arrival rates equaling departure rates for records in the database; then the size of the database will stabilize.  When arrivals outpace departures, the database size increases.  Sharding also helps to eliminate bottlenecks, and only be limited by causality concerns.

# Cancellations

Since we are going for database consistency, we can use state to represent account balances.  The fact that transactions are offered and accepted can help here.

= An offered transaction can hash to a EC point.  An accepted transaction can be the side-effect of accepting it, minus the offered transaction.  That way, completed transactions cancel out of the system.
- For example: If I offer to move +20 from A to B, and sign the offer with an expiration date and a hash of 99, B can sign an acceptance that also moves +20 from A to B by simply making a transaction that increments and decrements the accounts and hashes to 52.  Accepting the offer would need to have B sign the negative of the offer so that (52 - 99) are hashed into the system.  Then the transaction that justified the movement can be garbage collected out.  The sum had gone up by 99.  Then the offer was accepted with a hash of (52-99), and the end result, the hash goes up by 52.  So, the positive and negative offer/accept transaction can be cancelled out.
= A set of balances and unaccepted offers would be what remains.  The actual transactions are not required to be carried around forever. 
