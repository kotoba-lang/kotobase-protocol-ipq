# kotobase-protocol-ipq

**IPQ/1 — bounded, verifiable selection over HTTP.** A trustless gateway
answers *give me this CID*. This surface answers *run this traversal and give
me the blocks that prove the result* — the operation kotobase's query plane
already performs, and the one it had no way to offer or to advertise.

```
GET  /ipq/v1                                              profile, limits, encodings
GET  /ipq/v1/selection/{root-cid}?selector=<base64url dag-cbor>
HEAD likewise
```

```clojure
(require '[kotobase.protocols.ipq :as ipq])

(ipq/handle ctx {:method :get
                 :path (str "/ipq/v1/selection/" root)
                 :query {"selector" param}})
;; => {:status 200
;;     :headers {"content-type" "application/vnd.ipld.car"
;;               "x-ipq-profile" "1" "x-ipq-matches" "1" "x-ipq-blocks" "2"}
;;     :body "…" :body-encoding :base64}
```

The handler is a **pure cljc function** over an injected block port —
`(handle ctx req) → resp`. No network I/O, no host JSON, no crypto dependency.
Authentication and transport belong to the deploy shell, exactly as in
[`kotobase-protocol-ipfs`](https://github.com/kotoba-lang/kotobase-protocol-ipfs).

## What a 200 from here means, exactly

The body is a CARv1 holding the blocks a bounded IPLD selector touched, root
first. Every one was rehashed before it was decoded, and the caller can replay
the same selector against the archive alone and reach the same matches without
trusting this server:

```clojure
(trustless/replay-selection car-bytes root selector-bytes ipq/limits)
;; => {:matches [{:path ["child" "title"] :value "selected"}]
;;     :loaded [root leaf] :unused []}
```

That round trip is the repo's central test. Without it this is an endpoint
that returns some bytes.

**It does not mean the answer is complete.** Replay proves that a named
traversal ran over verified bytes. Proving that a database range or a Datalog
answer omits nothing needs authenticated index boundaries, which do not exist
yet (kotobase `docs/adr/2609060000-ipld-adl-selector-car-boundaries.md`). That
is the whole reason the profile number is on the wire: this is IPQ/1, and a
later profile carrying completeness proofs would be a different number, not a
silently better version of this one.

## Why a separate path rather than `?selector=` on `/ipfs/`

kotobase ADR-2609060000, verbatim: *An arbitrary `?selector=` endpoint
returning CARv2 is a custom protocol, not automatically a standard trustless
gateway. Negotiate supported forms and versions explicitly.* Overloading
`/ipfs/` would make a non-standard response indistinguishable from a standard
one to a client that guessed wrong. `/ipq/v1/` says which protocol answered.

## Discovery

`ipni.metadata/ipq-selection-http-bytes` (in
[`io-ipni-specs`](https://github.com/kotoba-lang/io-ipni-specs)) is the
advertisement half: protocol identifier `0x300940`
(`transport-ipq-selection-http`) then one uvarint profile number. The code sits
in the multicodec **private use area** (`0x300000–0x3FFFFF`, "reserved for
internal use by applications"), offset by `0x0940` — the next free slot in the
registered transport family, which is what a registration would ask for.
Announcing an unregistered code outside that range would be squatting on a
registry we do not own.

This repo does not require `ipni` and does not advertise. Publishing is the
deploy shell's business.

## Refusals that are not the same refusal

| status | error | means |
|---|---|---|
| 400 | `selector-required` | no `?selector=` |
| 400 | `selector-not-base64url` | a character outside the alphabet — never dropped |
| 400 | `invalid-selector` | decodes, but outside the supported subset |
| 404 | `root-not-held` | this store never had the graph |
| 404 | `missing-block` | it has the root and is missing an interior block |
| 413 | `resource-limit` | a budget was exhausted **mid-traversal** |
| 502 | `cid-mismatch` | a stored block does not hash to its key |

The two 404s are both true and they are not interchangeable: one is a question
about content we do not hold, the other is a partially-collected store, and
only the second is something an operator can act on.

`resource-limit` is never a truncated 200. An incomplete retrieval that
returns 200 is the failure this surface exists to avoid.

## Budgets are published, not merely enforced

`GET /ipq/v1` carries `maxBlocks`, `maxBytes`, `maxDepth` and `maxMatches`. A
client that cannot read the budget before building a selector can only discover
it by being refused, and a refusal it did not anticipate is indistinguishable
from a server fault.

## Test

```bash
clojure -M:test                                        # JVM
nbb --classpath "$(clojure -Spath -A:test)" bin/run_tests.cljs   # nbb (first-class)
```

Both halves run the same `.cljc`.

## Namespace

`kotobase.protocols.ipq`, matching the other surface repos. Repo name and
namespace need not match, and renaming would break consumers for no benefit.

Split per superproject ADR-2608051000 (`1 repo = 1 capability`): this surface
needs a selector engine and a CAR codec, and pulling those into the
low-privilege gateway repo is exactly what that rule exists to prevent.
