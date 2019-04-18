# DeltaDB
A delta-based blob storage system

## Motivation
MediaWiki-like wiki systems usually store all history revisions. History revisions are highly related to each other, and can be better represented as a delta/diff format instead of storing redundant copies.

MediaWiki currently has some limited support for doing deltification. Its existing approaches is limited in a few ways:
* It batches up to 100 consecutive revisions (at most 10M in size) together. Relations outside then 100 revisions are lost.
* When extracting contents, it decompresses all items in a batch, but only uses the single revision needed.
* It is only performed in maintenance script, so new revisions will not enjoy the benefit until the script is run.
* Running the maintenance script is expensive.

Given the technologies used by MediaWiki, it probably couldn't do any better if no extra services are introduced. We would like to have an additional service, a blob database that takes the delta relationship as first-class citizen, and supports online deltification and compression.

## Operations
Three basic operations are supported:
* `insert`: add a blob into the database. The SHA-256 of the blob is returned.
* `get`: given SHA-256 of a blob, retrieve it from the database.
* `link`: hint the database that two blobs are related (e.g. one is based on another in revision history). DeltaDB will automatically try to find if any savings can be achieved by linking them together.

DeltaDB stores blobs using delta chains. This gives a significant compression ratio, but a long chain is bad for performance as loading an object requires multiple accesses to other objects. DeltaDB makes the trade-off to cut the chain when appropriate. It guarantees that no load will require loading twice the uncompressed size of the largest item on the delta chain. This effectively restricts the maximum length of delta chain.

## Performance
For 1.4M blobs with a total ~20GB bytes, the database size after compression is 550MB, a compression ratio of 36x. The maximum length of delta chain is 7. A reading speed of 600Mbps can be achieved.
