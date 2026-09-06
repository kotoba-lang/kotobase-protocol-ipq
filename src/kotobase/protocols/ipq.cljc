(ns kotobase.protocols.ipq
  "IPQ/1 — bounded, verifiable selection over HTTP.

  A trustless gateway answers *give me this CID*. This surface answers *run
  this traversal and give me the blocks that prove the result*, which is the
  operation kotobase's query plane actually performs and the one it had no way
  to offer or to advertise.

  ## What a 200 from here means, exactly

  The body is a CARv1 containing the blocks a bounded IPLD selector touched,
  root first. Every one of them was rehashed before it was decoded, and the
  caller can replay the same selector against the archive alone
  (`ipld.car.trustless/replay-selection`) and reach the same matches without
  trusting this server.

  It does NOT mean the answer is complete. Replay proves that a named traversal
  ran over verified bytes; proving that a database range or a Datalog answer
  omits nothing needs authenticated index boundaries, which do not exist yet
  (kotobase ADR-2609060000). The profile number in the descriptor is where that
  distinction is recorded, and it is why this is IPQ/1 and not IPQ.

  ## Why a separate path, not `?selector=` on /ipfs/

  kotobase ADR-2609060000: *An arbitrary `?selector=` endpoint returning CARv2
  is a custom protocol, not automatically a standard trustless gateway.
  Negotiate supported forms and versions explicitly.* Overloading `/ipfs/`
  would make a non-standard response indistinguishable from a standard one to
  a client that guessed wrong. `/ipq/v1/` says which protocol answered.

  ## Surface

      GET  /ipq/v1                         profile, limits, encodings
      GET  /ipq/v1/selection/{root-cid}?selector=<base64url dag-cbor>
      HEAD likewise

  Handlers are pure: `(handle ctx req) -> resp`, over the block port injected
  in `ctx` as `:blocks {:get (fn [cid] -> block | nil)}` — required, see
  `block-port`. No network I/O, no host JSON, no crypto dependency."
  (:require [clojure.string :as str]
            [ipld.car.bytes :as b]
            [ipld.car.trustless :as trustless]
            [ipld.dag-json :as dag-json]
            [ipld.selector :as selector]
            [kotobase.protocols.http :as http]
            [kotobase.protocols.json :as json]))

(def ^:const profile
  "IPQ/1: a replayable traversal over CID-verified blocks. Not completeness."
  1)

(def limits
  "Every budget `ipld.graph/select-blocks` requires, fixed and published.

  Published rather than merely enforced: a client that cannot read the budget
  before it builds a selector can only discover it by being refused, and a
  refusal it did not anticipate is indistinguishable from a server fault. The
  descriptor at `/ipq/v1` carries these numbers."
  {:max-blocks 256
   :max-bytes 4194304
   :max-depth 32
   :max-matches 256})

(def descriptor
  {"protocol" "ipq"
   "profile" profile
   "selector" {"encoding" "dag-cbor" "transfer" "base64url"
               "parameter" "selector"}
   "response" {"content-type" trustless/content-type "car-version" 1}
   "limits" {"maxBlocks" (:max-blocks limits)
             "maxBytes" (:max-bytes limits)
             "maxDepth" (:max-depth limits)
             "maxMatches" (:max-matches limits)}
   "proves" "that this traversal ran over blocks that hash to their CIDs"
   "doesNotProve" "that a database range or Datalog answer is complete"})

;; ── selector transfer ────────────────────────────────────────────────────────

(defn base64url->bytes
  "Decode a base64url query parameter.

  `ipld.dag-json/base64-decode` is standard-alphabet and throws on any
  character outside it, which is the behaviour we want and the reason the
  translation happens HERE rather than by handing it the raw parameter: `-`
  and `_` are legal base64url and illegal base64, so passing them straight
  through would reject a correctly-encoded selector, and stripping unknown
  characters instead would decode a corrupted one into different bytes without
  saying so.

  Returns this runtime's byte container, or `{:error reason}`. Padding is
  optional; base64url normally omits it and both forms mean the same thing.

  The `as-bytes` at the end is not tidying. `base64-decode` returns a Clojure
  VECTOR of numbers, and the CBOR reader downstream measures its input with
  `.length` -- which on a vector is `undefined`, so the decoder sees zero bytes
  and reports `cbor: unexpected end of input`. The bytes were correct and the
  container was not, and the two are indistinguishable from a value comparison:
  measured while writing this, a round-trip test comparing `(vec decoded)` to
  the original passed while every request through the handler failed."
  [s]
  (cond
    (str/blank? s) {:error :empty}
    (re-find #"[^A-Za-z0-9\-_=]" s) {:error :not-base64url}
    :else
    (let [standard (-> s (str/replace "-" "+") (str/replace "_" "/")
                       (str/replace "=" ""))]
      (try (b/as-bytes (dag-json/base64-decode standard))
           (catch #?(:clj Exception :cljs :default) _ {:error :not-base64url})))))

(defn block-port
  "The `:blocks` port from `ctx`, or nil.

  This surface takes the port directly rather than going through
  `kotobase.protocols.blocks`, and the reason is the operation, not the
  dependency: that namespace falls back to an `IStore` document collection when
  `ctx` carries no port, and a document collection stores a block's bytes AS A
  DOCUMENT VALUE — which on the worker route becomes datoms (ADR-2608039970,
  and the measured 4 MiB ceiling that came with it). A selector engine reading
  blocks back out of the datom plane would work and would be the wrong shape,
  so the port is required here and its absence is refused rather than
  substituted for."
  [ctx]
  (get-in ctx [:blocks :get]))

(defn- block-bytes
  "`get-fn` for the traversal, over the injected block port.

  A block stored with `:encoding \"base64\"` is a transport encoding of binary
  content and is decoded back; one stored with any OTHER encoding is refused
  rather than passed through, because handing a selector the base64 TEXT of a
  DAG-CBOR node produces a CID mismatch several frames later, and the error a
  caller would see would name the wrong thing."
  [ctx]
  (let [get-block (block-port ctx)]
    (fn [cid]
      (when-let [{:keys [bytes encoding]} (get-block cid)]
        (cond
          (nil? encoding) bytes
          (= "base64" encoding) (b/as-bytes (dag-json/base64-decode bytes))
          :else (throw (ex-info "ipq: block has an encoding this surface cannot decode"
                                {:type :ipq/unsupported-block-encoding
                                 :cid cid :encoding encoding})))))))

;; ── responses ────────────────────────────────────────────────────────────────

(defn- json-resp [status body]
  (http/response status
                 {"content-type" "application/json; charset=utf-8"}
                 (json/encode body)))

(defn- refuse [status reason detail]
  (json-resp status (cond-> {"error" (name reason)}
                      detail (assoc "detail" detail))))

(defn- car-resp [req car-bytes]
  (http/response
   200
   {"content-type" trustless/content-type
    "cache-control" "public, max-age=29030400, immutable"
    "x-ipq-profile" (str profile)}
   (when (= :get (:method req)) (dag-json/base64-encode car-bytes))))

(defn- selection
  "Run one selection and map every failure onto a status that means something
  different from the others.

  `:ipld/missing-block` is 404 and not 502: this server holds a content-
  addressed store, and a traversal that reaches a CID we do not have is a
  question about content we do not hold, not a fault. `:ipld/resource-limit`
  is 413 and never a truncated 200 — a budget exhausted mid-traversal is an
  incomplete retrieval, and an incomplete retrieval that returns 200 is the
  failure this whole surface exists to avoid."
  [ctx req root selector-data]
  (try
    (let [result (trustless/selection-car (block-bytes ctx) root selector-data limits)]
      (-> (car-resp req (get-in result [:car :bytes]))
          (assoc :body-encoding :base64)
          (update :headers assoc
                  "x-ipq-matches" (str (count (:matches result)))
                  "x-ipq-blocks" (str (count (:blocks result))))))
    (catch #?(:clj Exception :cljs :default) e
      (let [t (:type (ex-data e))]
        (case t
          :ipld/missing-block (refuse 404 :missing-block (str (:cid (ex-data e))))
          :ipld/cid-mismatch (refuse 502 :cid-mismatch (str (:cid (ex-data e))))
          :ipld/resource-limit (refuse 413 :resource-limit (str (:limit (ex-data e))))
          :ipld/invalid-selector (refuse 400 :invalid-selector (ex-message e))
          :ipq/unsupported-block-encoding
          (refuse 502 :unsupported-block-encoding (str (:encoding (ex-data e))))
          (throw e))))))

(defn handle
  "IPQ/1 handler. `GET /ipq/v1` describes the profile; `GET|HEAD
  /ipq/v1/selection/{root}?selector=<base64url>` runs one bounded traversal."
  [ctx req]
  (let [segs (http/segments (:path req))]
    (cond
      (not (#{:get :head} (:method req)))
      (http/method-not-allowed)

      (nil? (block-port ctx))
      ;; Refused rather than degraded. A deployment that forgot the port would
      ;; otherwise answer every selection with `root-not-held`, which is a
      ;; sentence about the graph and not about the deployment.
      (refuse 501 :block-port-required
              "ctx must carry :blocks {:get (fn [cid] -> block | nil)}")

      (= ["ipq" "v1"] segs)
      (json-resp 200 descriptor)

      (and (= 4 (count segs))
           (= "ipq" (first segs))
           (= "v1" (second segs))
           (= "selection" (nth segs 2)))
      (let [root (nth segs 3)
            raw (http/query-param req "selector")]
        (if (nil? raw)
          (refuse 400 :selector-required
                  "pass ?selector=<base64url dag-cbor>; see GET /ipq/v1")
          (let [decoded (base64url->bytes raw)]
            (if (:error decoded)
              (refuse 400 :selector-not-base64url (name (:error decoded)))
              (let [parsed (try {:ok (selector/decode decoded)}
                                (catch #?(:clj Exception :cljs :default) e
                                  {:err e}))]
                (if-let [e (:err parsed)]
                  (if (= :ipld/invalid-selector (:type (ex-data e)))
                    (refuse 400 :invalid-selector (ex-message e))
                    (refuse 400 :selector-not-dag-cbor (ex-message e)))
                  (if (nil? ((block-port ctx) root))
                    (refuse 404 :root-not-held root)
                    (selection ctx req root (:ok parsed)))))))))

      (= "ipq" (first segs))
      (refuse 404 :unknown-ipq-path
              "this deployment serves /ipq/v1 and /ipq/v1/selection/{cid}")

      :else (http/not-found))))
