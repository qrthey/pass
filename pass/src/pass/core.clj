(ns pass.core
  (:import [java.util Base64]
           [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec IvParameterSpec])
  (:require [clojure.set :as set]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:gen-class))

;; encrypt / decrypt
(defn bytes->base64
  [bs]
  (.encodeToString (Base64/getEncoder) bs))

(defn base64->bytes
  [base64]
  (.decode (Base64/getDecoder) base64))

(defn key-spec-aes
  [password]
  (let [digester (java.security.MessageDigest/getInstance "SHA-256")
        evolutions (iterate #(.digest digester %) password)
        key-bytes (nth evolutions (* 1000 1000))]
    (SecretKeySpec. key-bytes "AES")))

(defn rand-iv-bytes
  []
  (java.security.SecureRandom/getSeed 16))

(defn encrypt-cbc
  [text-bytes password-bytes iv-bytes]
  (let [cipher (doto (Cipher/getInstance "AES/CBC/PKCS5PADDING")
                 (.init Cipher/ENCRYPT_MODE
                        (key-spec-aes password-bytes)
                        (IvParameterSpec. iv-bytes)))]
    (.doFinal cipher text-bytes)))

(defn decrypt-cbc
  [encrypted-text-bytes password-bytes iv-bytes]
  (let [cipher (doto (Cipher/getInstance "AES/CBC/PKCS5PADDING")
                 (.init Cipher/DECRYPT_MODE
                        (key-spec-aes password-bytes)
                        (IvParameterSpec. iv-bytes)))]
    (.doFinal cipher encrypted-text-bytes)))

(defn persist-secured
  [data path password-bytes]
  (let [iv-bytes (rand-iv-bytes)
        encrypted-bytes (-> data
                            pr-str
                            (.getBytes "UTF-8")
                            (encrypt-cbc password-bytes iv-bytes))]
    (->> [encrypted-bytes iv-bytes]
         (map bytes->base64)
         (str/join "\n")
         (spit path))))

(defn read-secured
  [path password-bytes]
  (let [[encrypted-bytes iv-bytes] (-> (slurp path)
                                       (str/split #"\n")
                                       (#(map base64->bytes %)))]
    (-> (decrypt-cbc encrypted-bytes
                     password-bytes
                     iv-bytes)
        (String. "UTF-8")
        (edn/read-string))))

;; autogenerate passwords
(defn gen-password
  [length & {:as selected}]
  (let [char-choices {:numbers      "0123456789"
                      :lowers       "abcdefghijklmnopqrstuvwxyz"
                      :uppers       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                      :punctuations ".!?,;-_"
                      :spaces       " "}
        chars (->> (set/difference (set (keys char-choices))
                                   (set (map key (filter (complement val) selected))))
                   (select-keys char-choices)
                   vals
                   (apply concat))]
    (apply str (repeatedly length #(rand-nth chars)))))

;; integration with the clipboard
(defn copy-to-clipboard
  [text]
  (-> (java.awt.Toolkit/getDefaultToolkit)
      .getSystemClipboard
      (.setContents
       (java.awt.datatransfer.StringSelection. text)
       nil)))

(defn reset-clipboard
  []
  (copy-to-clipboard ""))

;; db operations and custom repl
(def db (atom []))
(def pwd (atom nil))

(def db-path
  (apply str (System/getenv "HOME")
         [\/ \. \_ \_ \p \a \s \s \p \a \s \s]))

(defn add-to-db
  [data]
  (swap! db conj data)
  (persist-secured @db db-path @pwd))

(defn delete-from-db
  [data]
  (swap! db #(filterv (fn [d] (not= d data)) %))
  (persist-secured @db db-path @pwd))

(defn- char-array->byte-array
  [chrs]
  (let [byte-buffer (.encode java.nio.charset.StandardCharsets/UTF_8 (java.nio.CharBuffer/wrap chrs))]
    (java.util.Arrays/copyOf (.array byte-buffer) (.limit byte-buffer))))

(defn- read-password-from-console
  [label]
  (print (str label ": "))
  (flush)
  (if-let [console (System/console)]
    (char-array->byte-array (.readPassword console))
    (.getBytes (read-line))))

(defn init-db
  [password]
  (reset! pwd password)
  (if (.exists (io/file db-path))
    (reset! db (read-secured db-path @pwd))
    (reset! db (do
                 (println "A database was not found. Please retype the password to create one.")
                 (let [pwd2 (read-password-from-console "repeat new master password")]
                   (if (= (seq password) (seq pwd2))
                     []
                     (do (reset! pwd nil)
                         (throw (Exception. "passwords didn't match..."))))))))
  nil)

(defn select-existing-entry
  []
  (let [indexed-entries (map-indexed (fn [idx entry] [idx entry]) @db)]
    (if (seq indexed-entries)
      (do
        (println "Select one of the following entries by typing the leading line number. Type 'c' to cancel.")
        (doseq [[idx {:keys [site username]}] indexed-entries]
          (println (str (format "%3d" idx) ": " site " (" username ")")))
        (let [response (read-line)]
          (when-not (= response "c")
            (get (into {} indexed-entries)
                 (Integer/parseInt response)))))
      (println "No entries found in the database!"))))

(defn show-entry
  []
  (when-let [{:keys [site username password]} (select-existing-entry)]
    (println)
    (println "site:" site)
    (println "username:" username)
    (copy-to-clipboard password)
    (println)
    (println (str "The password was copied to the clipboard. "
                  "Press enter to clear the password from the clipboard."))
    (read-line)
    (reset-clipboard)))

(defn read-label-val
  [label]
  (print (str label ": "))
  (flush)
  (read-line))

(defn add-entry
  []
  (let [new-site (read-label-val "site")
        new-username (read-label-val "user")]
    (if (some (fn [{:keys [site username]}]
                (and (= site new-site)
                     (= username new-username)))
              @db)
      (println "That combination already exist, delete and recreate to change.")
      (loop [password (gen-password 75)]
        (copy-to-clipboard password)
        (println (str "A new password was generated into the clipboard. "
                      "Try if the site accepts it."))
        (let [choice (read-label-val "pwd ok? (y/n)")]
          (if (= choice "y")
            (do
              (add-to-db {:site new-site :username new-username :password password})
              (reset-clipboard))
            (recur (gen-password 75))))))))

(defn delete-entry
  []
  (when-let [selected (select-existing-entry)]
    (delete-from-db selected)))

(defn pass-repl
  []
  (let [next-command (fn []
                       (let [choice (read-label-val "(l)ist, (a)dd, (d)elete, (q)uit")]
                         (case choice
                           "l" (show-entry)
                           "a" (add-entry)
                           "d" (delete-entry)
                           "q" :quit)))]
    (loop [response (next-command)]
      (if-not (= :quit response)
        (recur (next-command))))))

(defn -main
  []
  (init-db (read-password-from-console "master password"))
  (pass-repl))
