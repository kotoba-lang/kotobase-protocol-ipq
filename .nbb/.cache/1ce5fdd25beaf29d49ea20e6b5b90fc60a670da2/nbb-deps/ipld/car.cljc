(ns ipld.car
  "CARv1 — the Content Addressable aRchive: a header naming some roots,
  then a sequence of length-prefixed `CID || block-bytes` frames.

  What this repository adds to `kotoba-lang/io-ipld` is not another encoding.
  It is **where a block is**. `ipld.core` answers *what* a CID names; a CAR
  answers *at which byte range of which object those bytes live*, which is the
  only question a range read can act on. Every function here therefore returns
  absolute byte offsets alongside the data, and never a bare block.

  Reading is by design not a stream: `decode` takes the whole archive because
  a caller that already holds the bytes should not pretend it is streaming.
  A caller that holds only a range uses `ipld.car.v2` with an index and fetches
  exactly the frames it wants."
  (:require [ipld.car.bytes :as b]
            [ipld.core :as ipld]
            [multiformats.core :as mf]
            [multiformats.base32 :as base32]))

(def ^:const version 1)

;; ── CID framing ──────────────────────────────────────────────────────────────

(defn read-cid
  "Read the binary CID that starts at `off`.

  Returns `{:cid <base32 string> :length n :codec n :mh-code n :digest bytes}`.

  CIDv0 (a bare sha2-256 multihash, first byte 0x12) is recognised only to
  reject it by name: the whole kotoba stack is CIDv1, and a v0 CAR read as v1
  would misparse every following frame rather than fail here."
  [buf off]
  (when (= 0x12 (b/bget buf off))
    (throw (ex-info "car: CIDv0 block in archive; this stack is CIDv1 only"
                    {:type :car/cidv0-unsupported :offset off})))
  (let [{v :value vl :length} (b/read-varint buf off)]
    (when-not (= 1 v)
      (throw (ex-info "car: unsupported CID version"
                      {:type :car/cid-version :version v :offset off})))
    (let [{codec :value cl :length} (b/read-varint buf (+ off vl))
          {mh :value ml :length} (b/read-varint buf (+ off vl cl))
          {dlen :value dl :length} (b/read-varint buf (+ off vl cl ml))
          total (+ vl cl ml dl dlen)
          raw (b/slice buf off (+ off total))]
      {:cid (str "b" (base32/encode raw))
       :length total
       :codec codec
       :mh-code mh
       :digest (b/slice buf (+ off vl cl ml dl) (+ off vl cl ml dl dlen))})))

(defn cid->bytes
  "Binary CID for a base32 CIDv1 string."
  [cid]
  (mf/cid->bytes cid))

(defn frame
  "One CAR block frame: `varint(len(cid)+len(data)) || cid || data`."
  [{:keys [cid bytes]}]
  (let [cb (cid->bytes cid)
        payload (b/bcount cb)]
    (b/concat [(b/varint (+ payload (b/bcount bytes))) cb bytes])))

;; ── header ───────────────────────────────────────────────────────────────────

(defn header-bytes
  "The DAG-CBOR CARv1 header block for `roots`, without its length prefix."
  [roots]
  (ipld/encode {"roots" (mapv ipld/link roots) "version" version}))

(defn- framed-header [roots]
  (let [h (header-bytes roots)]
    (b/concat [(b/varint (b/bcount h)) h])))

;; ── encode ───────────────────────────────────────────────────────────────────

(defn encode
  "CARv1 bytes for `{:roots [cid...] :blocks [{:cid s :bytes b} ...]}`.

  Returns `{:bytes ... :entries [{:cid :frame-offset :frame-length
  :block-offset :block-length} ...] :header-length n}` — the entries are the
  point. An archive whose block positions the writer discards is an archive
  only its own reader can index."
  [{:keys [roots blocks]}]
  (let [hdr (framed-header (or roots []))
        h-len (b/bcount hdr)]
    (loop [bs (seq blocks) off h-len parts [hdr] entries []]
      (if-let [{:keys [cid bytes] :as blk} (first bs)]
        (let [f (frame blk)
              cb-len (b/bcount (cid->bytes cid))
              vl (b/bcount (b/varint (+ cb-len (b/bcount bytes))))]
          (recur (rest bs)
                 (+ off (b/bcount f))
                 (conj parts f)
                 (conj entries {:cid cid
                                :frame-offset off
                                :frame-length (b/bcount f)
                                :block-offset (+ off vl cb-len)
                                :block-length (b/bcount bytes)})))
        {:bytes (b/concat parts)
         :entries entries
         :header-length h-len}))))

;; ── decode ───────────────────────────────────────────────────────────────────

(defn decode
  "Parse a whole CARv1. Returns `{:roots [...] :entries [...] :blocks {cid bytes}}`.

  Offsets in `:entries` are relative to `base` (default 0) so that a CARv1
  embedded in a CARv2 payload reports offsets in the enclosing file."
  ([buf] (decode buf 0 (b/bcount buf)))
  ([buf base] (decode buf base (b/bcount buf)))
  ([buf base end]
   (let [{h-len :value h-vl :length} (b/read-varint buf base)
         header (ipld/decode (b/slice buf (+ base h-vl) (+ base h-vl h-len)))
         roots (mapv ipld/link-cid (get header "roots"))]
     (when-not (= version (get header "version"))
       (throw (ex-info "car: not a CARv1 header"
                       {:type :car/bad-version :version (get header "version")})))
     (loop [off (+ base h-vl h-len) entries [] blocks {}]
       (if (>= off end)
         {:roots roots :entries entries :blocks blocks}
         (let [{flen :value fvl :length} (b/read-varint buf off)
               body-start (+ off fvl)
               frame-end (+ body-start flen)]
           (when (> frame-end end)
             (throw (ex-info "car: block frame runs past end of archive"
                             {:type :car/frame-truncated :offset off})))
           (let [{:keys [cid length]} (read-cid buf body-start)
                 data (b/slice buf (+ body-start length) frame-end)]
             (recur frame-end
                    (conj entries {:cid cid
                                   :frame-offset off
                                   :frame-length (+ fvl flen)
                                   :block-offset (+ body-start length)
                                   :block-length (b/bcount data)})
                    (assoc blocks cid data)))))))))

(defn verify-block
  "Recompute the CID of `bytes` and compare. The only conforming read across a
  storage boundary — a CAR fetched over HTTP is exactly that boundary."
  [cid bytes]
  (let [actual (case (long (:codec (read-cid (cid->bytes cid) 0)))
                 0x71 (mf/cidv1-dag-cbor bytes)
                 0x55 (mf/cidv1-raw bytes)
                 (throw (ex-info "car: unsupported content codec for verification"
                                 {:type :car/unsupported-codec :cid cid})))]
    (when-not (= cid actual)
      (throw (ex-info "car: block CID mismatch"
                      {:type :car/cid-mismatch :expected-cid cid :actual-cid actual})))
    bytes))
