(ns kotobase.protocols.ipq-test
  (:require #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer [deftest is testing]])
            [clojure.string :as str]
            [ipld.car.bytes :as bytes]
            [ipld.car.trustless :as trustless]
            [ipld.core :as ipld]
            [ipld.dag-json :as dag-json]
            [ipld.graph :as graph]
            [ipld.selector :as selector]
            [kotobase.protocols.ipq :as ipq]
            [kotobase.protocols.json :as json]))

;; ── fixture ──────────────────────────────────────────────────────────────────

(defn fixture
  "A two-block DAG behind the ctx block port the handler is given."
  []
  (let [store (atom {})
        put! (fn [cid block-bytes] (swap! store assoc cid block-bytes))
        leaf (ipld/put-node! put! {"title" "selected" "null" nil})
        root (ipld/put-node! put! {"child" (ipld/link leaf) "other" true})]
    {:root root
     :leaf leaf
     :store store
     :ctx {:blocks {:get (fn [cid]
                           (when-let [b (get @store cid)]
                             {:bytes b :content-type "application/vnd.ipld.dag-cbor"}))
                    :list (fn [] (keys @store))}}}))

(defn base64url
  "Encode bytes the way a client puts a selector in a query string."
  [b]
  (-> (dag-json/base64-encode b)
      (str/replace "+" "-")
      (str/replace "/" "_")
      (str/replace "=" "")))

(defn path-selector-param [path]
  (base64url (selector/encode (graph/path-selector path))))

(defn req
  ([path] (req path nil))
  ([path sel] (req :get path sel))
  ([method path sel]
   (cond-> {:method method :path path :headers {}}
     sel (assoc :query {"selector" sel}))))

(defn body->car-bytes [resp]
  (bytes/as-bytes (dag-json/base64-decode (:body resp))))

(defn json-body [resp] (json/parse (:body resp)))

;; ── the descriptor is how a client learns the budget ─────────────────────────

(deftest descriptor-publishes-the-profile-and-the-budgets
  (let [{:keys [ctx]} (fixture)
        resp (ipq/handle ctx (req "/ipq/v1"))
        body (json-body resp)]
    (is (= 200 (:status resp)))
    (is (= "ipq" (get body "protocol")))
    (is (= 1 (get body "profile")) "IPQ/1, and the number is load-bearing")
    (is (= (:max-blocks ipq/limits) (get-in body ["limits" "maxBlocks"]))
        "a client that cannot read the budget can only discover it by refusal")
    (is (= "base64url" (get-in body ["selector" "transfer"])))
    (is (= trustless/content-type (get-in body ["response" "content-type"])))
    (is (str/includes? (get body "doesNotProve") "complete")
        "the descriptor states what a 200 does not establish")))

;; ── the payload is the point: it has to replay ───────────────────────────────

(deftest a-200-is-an-archive-the-caller-can-replay-without-us
  ;; This is the only assertion that distinguishes IPQ from "an endpoint that
  ;; returns some bytes". The producer says which blocks it touched; a verifier
  ;; re-derives the matches from the archive ALONE, binding to the root the
  ;; caller asked for rather than the one the archive names.
  (let [{:keys [root leaf ctx]} (fixture)
        sel-bytes (selector/encode (graph/path-selector ["child" "title"]))
        resp (ipq/handle ctx (req (str "/ipq/v1/selection/" root)
                                  (path-selector-param ["child" "title"])))]
    (is (= 200 (:status resp)))
    (is (= trustless/content-type (get-in resp [:headers "content-type"])))
    (is (= :base64 (:body-encoding resp)))
    (is (= "1" (get-in resp [:headers "x-ipq-profile"])))
    (let [replayed (trustless/replay-selection (body->car-bytes resp)
                                               root sel-bytes ipq/limits)]
      (is (= ["selected"] (mapv :value (:matches replayed)))
          "the verifier reaches the same answer from the archive alone")
      (is (= [root leaf] (mapv :cid (:loaded replayed)))
          "and needed exactly the blocks the producer said it touched")
      (is (empty? (:unused replayed))))))

(deftest head-carries-the-headers-and-no-body
  (let [{:keys [root ctx]} (fixture)
        resp (ipq/handle ctx (req :head (str "/ipq/v1/selection/" root)
                                  (path-selector-param ["child" "title"])))]
    (is (= 200 (:status resp)))
    (is (= trustless/content-type (get-in resp [:headers "content-type"])))
    (is (nil? (:body resp)))))

;; ── base64url, decoded rather than tolerated ─────────────────────────────────

(deftest base64url-is-translated-and-anything-else-is-refused
  (testing "- and _ are legal base64url and illegal base64"
    ;; 0xFB 0xFF encodes as \"+_8\" in standard base64 and \"-_8\" in base64url.
    ;; Handing the raw parameter to a standard decoder would reject a correct
    ;; selector; stripping the unknown characters would decode a different one.
    (is (= [0xFB 0xFF] (vec (ipq/base64url->bytes "-_8"))))
    (is (= [0xFB 0xFF] (vec (ipq/base64url->bytes "-_8=")))
        "padding is optional and means the same thing"))
  (testing "a character outside the alphabet is an error, never dropped"
    (is (= :not-base64url (:error (ipq/base64url->bytes "ab*d"))))
    (is (= :not-base64url (:error (ipq/base64url->bytes "ab cd")))))
  (testing "empty is empty, not zero bytes"
    (is (= :empty (:error (ipq/base64url->bytes ""))))))

;; ── refusals that must not be the same refusal ───────────────────────────────

(deftest a-root-we-do-not-hold-is-not-the-same-as-a-gap-mid-traversal
  ;; Both are 404 and both are true, and fusing them loses the only thing an
  ;; operator can act on: `root-not-held` means this store never had the graph,
  ;; `missing-block` means it has the root and is missing an interior block --
  ;; which is a partially-collected store, not a wrong request.
  (let [{:keys [root leaf store ctx]} (fixture)
        param (path-selector-param ["child" "title"])
        absent (ipq/handle ctx (req "/ipq/v1/selection/bafkreiabsent000000000000000000000000000000000000000000" param))]
    (is (= 404 (:status absent)))
    (is (= "root-not-held" (get (json-body absent) "error")))
    (swap! store dissoc leaf)
    (let [gap (ipq/handle ctx (req (str "/ipq/v1/selection/" root) param))]
      (is (= 404 (:status gap)))
      (is (= "missing-block" (get (json-body gap) "error")))
      (is (not= (get (json-body gap) "error") (get (json-body absent) "error"))))))

(deftest a-budget-exhausted-mid-traversal-is-413-and-never-a-shorter-200
  (let [{:keys [root ctx]} (fixture)
        param (path-selector-param ["child" "title"])]
    (with-redefs [ipq/limits (assoc ipq/limits :max-blocks 1)]
      (let [resp (ipq/handle ctx (req (str "/ipq/v1/selection/" root) param))]
        (is (= 413 (:status resp)))
        (is (= "resource-limit" (get (json-body resp) "error")))))))

(deftest a-missing-or-unusable-selector-says-which
  (let [{:keys [root ctx]} (fixture)
        path (str "/ipq/v1/selection/" root)]
    (testing "no parameter at all"
      (let [resp (ipq/handle ctx (req path))]
        (is (= 400 (:status resp)))
        (is (= "selector-required" (get (json-body resp) "error")))))
    (testing "not base64url"
      (let [resp (ipq/handle ctx (req path "not base64!"))]
        (is (= 400 (:status resp)))
        (is (= "selector-not-base64url" (get (json-body resp) "error")))))
    (testing "base64url, but not a selector this profile admits"
      ;; A well-formed DAG-CBOR map with an unknown selector tag. It decodes as
      ;; CBOR and is refused by `ipld.selector/decode`, which is where an
      ;; unsupported form has to be rejected -- quietly matching less would
      ;; return a 200 that proves a traversal nobody asked for.
      (let [resp (ipq/handle ctx (req path (base64url (ipld/encode {"zz" {}}))))]
        (is (= 400 (:status resp)))
        (is (= "invalid-selector" (get (json-body resp) "error")))))))

(deftest methods-and-paths-outside-the-profile
  (let [{:keys [ctx]} (fixture)]
    (is (= 405 (:status (ipq/handle ctx (req :post "/ipq/v1" nil)))))
    (let [resp (ipq/handle ctx (req "/ipq/v2/selection/x"))]
      (is (= 404 (:status resp)))
      (is (= "unknown-ipq-path" (get (json-body resp) "error"))
          "a version we do not serve is named, not a bare 404"))
    (is (= 404 (:status (ipq/handle ctx (req "/ipfs/bafkreiwhatever")))))))

(deftest a-deployment-without-a-block-port-is-refused-not-degraded
  ;; Without this the handler would answer every selection with
  ;; `root-not-held`, which is a sentence about the graph. The deployment is
  ;; what is wrong, and a 404 would send the operator looking at their data.
  (let [resp (ipq/handle {} (req "/ipq/v1/selection/bafkreianything"
                                 (path-selector-param ["child"])))]
    (is (= 501 (:status resp)))
    (is (= "block-port-required" (get (json-body resp) "error")))
    (is (not= "root-not-held" (get (json-body resp) "error")))))

(deftest a-block-whose-encoding-we-cannot-decode-is-502-not-a-miss
  ;; Handing a selector the base64 TEXT of a DAG-CBOR node would fail as a CID
  ;; mismatch several frames later and name the wrong thing.
  (let [{:keys [root store]} (fixture)
        ctx {:blocks {:get (fn [cid]
                             (when-let [b (get @store cid)]
                               {:bytes b :encoding "hex"}))}}
        resp (ipq/handle ctx (req (str "/ipq/v1/selection/" root)
                                  (path-selector-param ["child" "title"])))]
    (is (= 502 (:status resp)))
    (is (= "unsupported-block-encoding" (get (json-body resp) "error")))
    (is (= "hex" (get (json-body resp) "detail")))))
