(ns kotobase.local
  "LocalStore — the pure, in-process IStore. This is what an app uses STANDALONE
  (OSS, no cloud): an atom holding the doc space and the append streams, with a
  monotonic `:seq`. It is also the reference ORACLE the contract checks KotobaseStore
  against (`KotobaseStore ≡ LocalStore`). Runs identically on JVM and cljs (it is
  just maps + an atom), so the same store backs a desktop app, a test, or a worker
  with no network."
  (:require [kotobase.store :as st]))

(defn- revision-conflict [expected actual]
  (ex-info "IStore tenant revision conflict"
           {:type :kotobase.store/revision-conflict
            :expected-revision expected
            :current-revision actual}))

(deftype LocalStore [state]
  st/IStore
  (-put [_ coll k v]
    (swap! state #(-> % (assoc-in [:docs coll k] v) (update :revision inc)))
    v)
  (-get [_ coll k] (get-in @state [:docs coll k]))
  (-list [_ coll] (vec (keys (get-in @state [:docs coll]))))

  (-append [_ stream event]
    (let [result (volatile! nil)]
      (swap! state
             (fn [current]
               (let [seq' (inc (:seq current))
                     event' (assoc event :seq seq')]
                 (vreset! result event')
                 (-> current
                     (assoc :seq seq')
                     (update :revision inc)
                     (update-in [:streams stream] (fnil conj []) event')))))
      @result))

  (-read [_ stream since]
    (let [since (or since 0)]
      (->> (get-in @state [:streams stream])
           (filter #(> (long (:seq %)) (long since)))
           (sort-by :seq)
           vec)))

  st/ITransactionalStore
  (-snapshot [_ {:keys [collections streams]}]
    (let [current @state]
      {:revision (:revision current)
       :docs (select-keys (:docs current) collections)
       :streams (select-keys (:streams current) streams)}))

  (-transact [_ {:keys [tx-id expected-revision puts deletes appends] :as request}]
    (when-not (and (string? tx-id) (seq tx-id))
      (throw (ex-info "IStore transaction requires a non-empty string tx-id"
                      {:type :kotobase.store/invalid-transaction})))
    (let [result (volatile! nil)]
      (swap! state
             (fn [current]
               (if-let [{prior-request :request receipt :receipt}
                        (get-in current [:tx-receipts tx-id])]
                 (do
                   (when-not (= prior-request request)
                     (throw (ex-info "IStore tx-id reused with different request"
                                     {:type :kotobase.store/transaction-id-conflict
                                      :tx-id tx-id})))
                   (vreset! result receipt)
                   current)
                 (do
                   (when-not (= expected-revision (:revision current))
                     (throw (revision-conflict expected-revision
                                               (:revision current))))
                   (let [[next-state stamped]
                         (reduce
                          (fn [[acc events] [stream event]]
                            (let [seq' (inc (:seq acc))
                                  event' (assoc event :seq seq')]
                              [(-> acc
                                   (assoc :seq seq')
                                   (update-in [:streams stream] (fnil conj []) event'))
                               (conj events [stream event'])]))
                          [(reduce (fn [acc [coll key]]
                                     (update-in acc [:docs coll] dissoc key))
                                   (reduce (fn [acc [coll key value]]
                                             (assoc-in acc [:docs coll key] value))
                                           current puts)
                                   deletes)
                           []]
                          appends)
                         revision' (inc (:revision current))
                         receipt {:tx-id tx-id :revision revision'
                                  :appends stamped}
                         committed (-> next-state
                                       (assoc :revision revision')
                                       (assoc-in [:tx-receipts tx-id]
                                                 {:request request
                                                  :receipt receipt}))]
                     (vreset! result receipt)
                     committed)))))
      @result)))

(defn local-store
  "A fresh in-process store. Pass `:seed` to preload `{:docs … :streams … :seq …}`."
  ([] (local-store {}))
  ([{:keys [docs streams seq revision tx-receipts]
     :or {docs {} streams {} seq 0 revision 0 tx-receipts {}}}]
   (->LocalStore (atom {:docs docs :streams streams :seq seq
                        :revision revision :tx-receipts tx-receipts}))))

(defn snapshot
  "The store's full state as a value — for checkpointing / pushing to the cloud."
  [^LocalStore s]
  @(.-state s))
