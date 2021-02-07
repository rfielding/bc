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
