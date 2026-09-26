;; cbor.core — definite-length CBOR (RFC 8949) encode/decode.
;;
;; Across a kotoba/IPLD codebase CBOR keeps getting hand-rolled — the CACAO leash
;; issuer, the apqc/kabuto/isco coordinators each open-code the major-type headers.
;; This is that once, with two encoders:
;;
;;   (encode x)          — canonical/deterministic: map keys sorted dag-cbor style
;;                         (shorter key first, then bytewise) → stable bytes for IPLD
;;   (encode-ordered ps) — a map from an ORDERED [k v] seq, keys emitted as given
;;                         (CAIP-122 CACAO and other insertion-order-sensitive wire
;;                         formats need this — canonical sorting would corrupt them)
;;
;;   (decode bytes)      — → Clojure data (maps as {}, arrays as [], text as String,
;;                         byte strings as bytes, ints as Long/number, bool/nil)
;;
;; Supported major types: 0 uint · 1 negint · 2 byte-string · 3 text · 4 array ·
;; 5 map · 6 tag (as an explicit `Tagged` wrapper — see below) · 7
;; (false/true/null/finite float64). No indefinite lengths. Floats are always
;; emitted as IEEE-754 binary64: DAG-CBOR has one canonical float width and
;; excludes NaN and infinities from the IPLD Data Model.
;;
;;   (tagged 42 bytes)   — encodes as major type 6, tag `n`, then the wrapped
;;                         value; decodes back to a `Tagged`. Plain data never
;;                         silently becomes a tag and a tag never silently
;;                         becomes plain data — the wrapper is always explicit,
;;                         so canonical bytes stay unambiguous. IPLD's CID link
;;                         (tag 42) is layered on top by `kotoba-lang/ipld`;
;;                         this namespace stays codec-generic.
;;
;; PORTABLE (.cljc, real on both platforms — this used to be `.clj`-only despite
;; every downstream repo's docstring calling that out as a known gap). Byte
;; buffers are `java.io.ByteArrayOutputStream`/`ByteArrayInputStream` on :clj and
;; a plain growable JS array / an atom-backed cursor over a Uint8Array on :cljs;
;; `encode`/`decode`'s public contract (bytes in, bytes/Clojure-data out) is
;; unchanged on :clj and equivalent on :cljs (Uint8Array instead of byte-array,
;; JS string instead of java.lang.String — both are just "the platform's native
;; string/byte type").
(ns cbor.core
  #?(:clj (:import (java.io ByteArrayOutputStream ByteArrayInputStream)
                   (java.nio ByteBuffer))))

;; An order-preserving map (vs. a Clojure map, which `encode` canonical-sorts).
;; Nestable: an OrderedMap value inside another OrderedMap keeps its own order —
;; what CAIP-122 CACAO needs (the {h,p,s} envelope AND p's 8 fields are ordered).
;;
;; `defrecord`, not `deftype`: a bare `deftype` with no protocol impl uses JVM
;; identity equality (two OrderedMaps with the same pairs are NOT `=`), and
;; adding one via `#?@(:clj [Object ...] :cljs [IEquiv ...])` (the shape
;; `Tagged` below used to need) doesn't even work on nbb -- SCI's `deftype`
;; support does not dispatch a custom implementation of a BUILT-IN cljs.core
;; protocol (`IEquiv`/`IHash`) on a deftype, `extend-type` included (confirmed
;; empirically: `Protocol not found: IEquiv` either way, in total isolation
;; from this file). `defrecord` sidesteps this entirely -- structural
;; equality/hash are part of what the compiler generates for a record on
;; EVERY platform (JVM/self-hosted cljs/nbb's SCI), not a protocol extension
;; nbb has to resolve at all. No existing caller relied on OrderedMap's old
;; identity-equality default (only `encode`/`decode` round-trip bytes are
;; ever asserted on), so this is a strict gain, not a behavior change.
(defrecord OrderedMap [pairs])
(defn ordered
  "Wrap an ordered seq of [k v] pairs as a map whose key order `encode` preserves."
  [pairs] (OrderedMap. pairs))

;; A CBOR tag (major type 6): tag number `n` wrapping `value`. Encoded as the
;; tag head followed by the encoded `value`; `decode` reconstructs the wrapper.
;; Field access goes through `tag-number`/`tag-value` (NOT `:n`/`:value` map-
;; keyword access, unlike `OrderedMap` above -- kept as narrow accessor fns so
;; a future caller never has to know or care that a record is a map under the
;; hood). Same `defrecord`-not-`deftype` reasoning as `OrderedMap`'s comment:
;; structural equality/hash come for free on every platform including nbb,
;; instead of a hand-written `#?@(:clj [Object ...] :cljs [IEquiv ...])`
;; protocol block that nbb's SCI can't dispatch (confirmed empirically)."
(defrecord Tagged [n value])

(defn tagged
  "Wrap `value` in CBOR tag `n` (major type 6). `n` is a non-negative integer."
  [n value]
  (Tagged. n value))

(defn tagged? [x] (instance? Tagged x))
(defn tag-number [t] (:n t))
(defn tag-value [t] (:value t))

;; ── byte sink/source (the only platform-specific plumbing) ───────────────────
(defn- new-out []
  #?(:clj (ByteArrayOutputStream.)
     :cljs (array)))

(defn- write-byte! [o b]
  #?(:clj (.write ^ByteArrayOutputStream o (int b))
     :cljs (.push o (bit-and b 0xff))))

(defn- write-bytes! [o bs]
  #?(:clj (.write ^ByteArrayOutputStream o ^bytes bs)
     :cljs (doseq [b (seq bs)] (.push o (bit-and (int b) 0xff)))))

(defn- out->bytes [o]
  #?(:clj (.toByteArray ^ByteArrayOutputStream o)
     :cljs (js/Uint8Array. o)))

(defn- new-in [b]
  #?(:clj (ByteArrayInputStream. b)
     :cljs (atom {:data b :pos 0})))

(defn- read-byte! [in]
  #?(:clj (.read ^ByteArrayInputStream in)
     :cljs (let [{:keys [data pos]} @in]
             (if (< pos (alength data))
               (do (swap! in assoc :pos (inc pos)) (bit-and (aget data pos) 0xff))
               -1))))

(defn- read-bytes! [in n]
  ;; InputStream.read(byte[],off,len) (:clj) and .slice (:cljs) both silently
  ;; return fewer bytes than asked when the source runs out early -- neither
  ;; throws on its own. A truncated byte-string/text-string header would
  ;; otherwise decode into a zero-padded array wholly unlike the original
  ;; bytes, with no error, instead of failing like every other truncated
  ;; shape here (decode-from's own read-byte! check already catches a
  ;; truncated array/map/tag).
  #?(:clj (let [b (byte-array n)
                r (.read ^ByteArrayInputStream in b 0 n)]
            (when (and (pos? n) (not= r n))
              (throw (ex-info "cbor: unexpected end of input" {})))
            b)
     :cljs (let [{:keys [data pos]} @in
                 out (.slice data pos (+ pos n))]
             (when (< (.-length out) n)
               (throw (ex-info "cbor: unexpected end of input" {})))
             (swap! in assoc :pos (+ pos n))
             out)))

(defn- bytes->str [b]
  #?(:clj (String. ^bytes b "UTF-8")
     :cljs (.decode (js/TextDecoder.) b)))

(defn- str->bytes [s]
  #?(:clj (.getBytes ^String s "UTF-8")
     :cljs (.encode (js/TextEncoder.) s)))

(defn- finite-number? [x]
  #?(:clj (and (number? x) (Double/isFinite (double x)))
     :cljs (and (number? x) (js/Number.isFinite x))))

(defn- float64-bytes [x]
  #?(:clj (-> (ByteBuffer/allocate 8) (.putDouble (double x)) .array)
     :cljs (let [buffer (js/ArrayBuffer. 8)]
             (.setFloat64 (js/DataView. buffer) 0 x false)
             (js/Uint8Array. buffer))))

(defn- bytes->float64 [bytes]
  #?(:clj (.getDouble (ByteBuffer/wrap ^bytes bytes))
     :cljs (.getFloat64 (js/DataView. (.-buffer bytes)
                                     (.-byteOffset bytes)
                                     (.-byteLength bytes))
                        0 false)))

;; `byte-at` extracts the byte at bit-position `s` (a multiple of 8) from `n`.
;; :clj uses real 64-bit `long` bit ops. :cljs CANNOT use bit-and/bit-shift-*
;; for this once `n` exceeds 2^32 -- JS's bitwise operators coerce their
;; operand to Int32/Uint32 *first*, so e.g. `(unsigned-bit-shift-right
;; 4294967296 24)` silently truncates 4294967296 to 0 before shifting at all.
;; Division/mod are safe up to Number.MAX_SAFE_INTEGER (2^53), far more than
;; this profile's practical range (timestamps, counters, seq numbers).
(defn- byte-at [n s]
  #?(:clj (bit-and (unsigned-bit-shift-right (long n) s) 0xff)
     :cljs (mod (js/Math.floor (/ n (js/Math.pow 2 s))) 256)))

;; ── encode ────────────────────────────────────────────────────────────────────
(defn- write-head [o major n]
  (let [mt (bit-shift-left major 5)]
    (cond
      (< n 24)        (write-byte! o (bit-or mt n))
      (< n 0x100)     (do (write-byte! o (bit-or mt 24)) (write-byte! o n))
      (< n 0x10000)   (do (write-byte! o (bit-or mt 25))
                          (write-byte! o (bit-and (bit-shift-right n 8) 0xff))
                          (write-byte! o (bit-and n 0xff)))
      (< n 0x100000000) (do (write-byte! o (bit-or mt 26))
                            (doseq [s [24 16 8 0]] (write-byte! o (byte-at n s))))
      :else            (do (write-byte! o (bit-or mt 27))
                           (doseq [s [56 48 40 32 24 16 8 0]]
                             (write-byte! o (byte-at n s)))))))

(declare encode-into)

(defn- key-bytes [k]
  (str->bytes (cond (string? k) k (keyword? k) (name k) :else (str k))))

(defn- encoded-byte-count [b]
  #?(:clj (count ^bytes b)
     :cljs (.-length b)))

(defn- unsigned-key-byte [b i]
  #?(:clj (bit-and (aget ^bytes b (int i)) 0xff)
     :cljs (bit-and (aget b i) 0xff)))

(defn- dag-cbor-key< [a b]
  (let [ka (key-bytes a) kb (key-bytes b)
        la (encoded-byte-count ka) lb (encoded-byte-count kb)]
    (if (not= la lb)
      (< la lb)                                         ; shorter key first
      (loop [i 0]                                        ; then bytewise unsigned
        (cond (= i la) false
              (not= (unsigned-key-byte ka i) (unsigned-key-byte kb i))
              (< (unsigned-key-byte ka i) (unsigned-key-byte kb i))
              :else (recur (inc i)))))))

(defn- encode-pairs [o pairs]
  (write-head o 5 (count pairs))
  (doseq [[k v] pairs]
    (encode-into o (if (keyword? k) (name k) k))
    (encode-into o v)))

(defn- bytes-like? [x]
  #?(:clj (bytes? x)
     :cljs (or (instance? js/Uint8Array x) (instance? js/Int8Array x))))

(defn- encode-into [o x]
  (cond
    (nil? x)            (write-byte! o 0xf6)
    (true? x)           (write-byte! o 0xf5)
    (false? x)          (write-byte! o 0xf4)
    (integer? x)        (if (neg? x) (write-head o 1 (- (- x) 1)) (write-head o 0 x))
    (number? x)         (if (finite-number? x)
                          (do (write-byte! o 0xfb)
                              (write-bytes! o (float64-bytes x)))
                          (throw (ex-info "cbor: non-finite float unsupported"
                                          {:value x})))
    (string? x)         (let [b (str->bytes x)] (write-head o 3 (encoded-byte-count b)) (write-bytes! o b))
    (keyword? x)        (let [b (str->bytes (name x))] (write-head o 3 (encoded-byte-count b)) (write-bytes! o b))
    (bytes-like? x)     (do (write-head o 2 (encoded-byte-count x)) (write-bytes! o x))
    (instance? Tagged x) (do (write-head o 6 (tag-number x))
                             (encode-into o (tag-value x)))
    (instance? OrderedMap x) (encode-pairs o (:pairs x))
    (map? x)            (encode-pairs o (sort-by key dag-cbor-key< (seq x)))
    (sequential? x)     (do (write-head o 4 (count x)) (doseq [e x] (encode-into o e)))
    :else (throw (ex-info "cbor: unsupported type" {:type (type x) :value x}))))

(defn encode
  "Deterministic CBOR bytes for Clojure data. Map keys are sorted dag-cbor style."
  [x]
  (let [o (new-out)] (encode-into o x) (out->bytes o)))

(defn encode-ordered
  "CBOR-encode a MAP given as an ordered seq of [k v] pairs — keys emitted in the
   given order (NOT sorted). For CAIP-122 CACAO and other order-sensitive formats."
  [pairs]
  (let [o (new-out)] (encode-pairs o pairs) (out->bytes o)))

;; ── decode ────────────────────────────────────────────────────────────────────
;; Reconstructs a big-endian multi-byte integer via arithmetic (+ (* acc 256)
;; byte), NOT bit-or/bit-shift-left -- the same 32-bit JS bitwise truncation
;; `byte-at` above works around applies here too (an 8-byte read overflows
;; 2^32 well before the loop finishes). Arithmetic is exact up to 2^53 on
;; both platforms and identical to the bitwise version for non-negative
;; accumulation.
(defn- read-n [in cnt]
  (loop [i 0 acc 0] (if (< i cnt) (recur (inc i) (+ (* acc 256) (read-byte! in))) acc)))

(defn- read-arg [in info]
  (cond (< info 24) info
        (= info 24) (read-byte! in)
        (= info 25) (read-n in 2)
        (= info 26) (read-n in 4)
        (= info 27) (read-n in 8)
        :else (throw (ex-info "cbor: indefinite/reserved length unsupported" {:info info}))))

(declare decode-from)

(defn- decode-from [in]
  (let [ib (read-byte! in)]
    (when (neg? ib) (throw (ex-info "cbor: unexpected end of input" {})))
    (let [major (bit-shift-right ib 5) info (bit-and ib 0x1f)]
      (case (int major)
        0 (read-arg in info)
        1 (- (- (read-arg in info)) 1)
        2 (read-bytes! in (read-arg in info))
        3 (bytes->str (read-bytes! in (read-arg in info)))
        4 (vec (repeatedly (read-arg in info) #(decode-from in)))
        5 (into {} (repeatedly (read-arg in info) #(let [k (decode-from in)] [k (decode-from in)])))
        6 (Tagged. (read-arg in info) (decode-from in))
        7 (case (int info)
            20 false
            21 true
            22 nil
            27 (let [value (bytes->float64 (read-bytes! in 8))]
                 (when-not (finite-number? value)
                   (throw (ex-info "cbor: non-finite float unsupported"
                                   {:value value})))
                 value)
            (throw (ex-info "cbor: unsupported simple/float" {:info info})))
        (throw (ex-info "cbor: unsupported major type" {:major major}))))))

(defn decode
  "Decode exactly one CBOR value. Maps → {}, arrays → [], text → String,
   byte-strings → bytes (byte-array on :clj, Uint8Array on :cljs), ints and
   finite float64 → numbers, true/false/null. Trailing bytes are rejected."
  [b]
  (let [in (new-in b)
        value (decode-from in)]
    (when-not (neg? (read-byte! in))
      (throw (ex-info "cbor: trailing bytes after top-level value" {})))
    value))
