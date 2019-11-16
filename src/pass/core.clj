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
(defn transform-bytes
  [mode bytes secret-key iv]
  (.doFinal
   (doto (Cipher/getInstance "AES/CBC/PKCS5PADDING")
     (.init mode
            (SecretKeySpec. secret-key "AES")
            (IvParameterSpec. iv)))
   bytes))

(defn encrypt-cbc
  [bytes secret-key iv]
  (transform-bytes Cipher/ENCRYPT_MODE bytes secret-key iv))

(defn decrypt-cbc
  [bytes secret-key iv]
  (transform-bytes Cipher/DECRYPT_MODE bytes secret-key iv))

(def bytes->base64 #(.encodeToString (Base64/getEncoder) %))
(def base64->bytes #(.decode (Base64/getDecoder) %))
(def rand-iv-bytes #(java.security.SecureRandom/getSeed 16))

(defn persist-secured
  [data path secret-key]
  (let [iv-bytes (rand-iv-bytes)
        encrypted-bytes (-> data
                            pr-str
                            (.getBytes "UTF-8")
                            (encrypt-cbc secret-key iv-bytes))]
    (->> [encrypted-bytes iv-bytes]
         (map bytes->base64)
         (str/join "\n")
         (spit path))))

(defn read-secured
  [path secret-key]
  (let [[encrypted-bytes iv-bytes] (-> (slurp path)
                                       (str/split #"\n")
                                       (#(map base64->bytes %)))]
    (-> (decrypt-cbc encrypted-bytes
                     secret-key
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
(def secret (atom nil))

(def db-path (apply str (System/getenv "HOME") "/.__passpass"))

(defn persist-db
  []
  (persist-secured @db db-path @secret))

(defn add-to-db
  [data]
  (swap! db conj data)
  (persist-db))

(defn delete-from-db
  [data]
  (swap! db #(filterv (fn [d] (not= d data)) %))
  (persist-db))

(defn- char-array->byte-array
  [chrs]
  (let [byte-buffer (.encode java.nio.charset.StandardCharsets/UTF_8 (java.nio.CharBuffer/wrap chrs))]
    (java.util.Arrays/copyOf (.array byte-buffer) (.limit byte-buffer))))

(defn- read-secret-key
  [label]
  (print (str label ": "))
  (flush)
  (let [password-bytes (if-let [console (System/console)]
                         (char-array->byte-array (.readPassword console))
                         (.getBytes (read-line)))
        digester (java.security.MessageDigest/getInstance "SHA-256")]
    (nth (iterate #(.digest digester %) password-bytes)
         (* 1000 1000))))

(defn init-db
  [secret-key]
  (reset! secret secret-key)
  (if (.exists (io/file db-path))
    (reset! db (read-secured db-path @secret))
    (reset! db (do
                 (println "A database was not found. Please retype the password to create one.")
                 (let [secret-key2 (read-secret-key "repeat new master password")]
                   (if (= (seq secret-key) (seq secret-key2))
                     []
                     (do (reset! secret nil)
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
        new-username (read-label-val "user")
        password-length 72]
    (if (some (fn [{:keys [site username]}]
                (and (= site new-site)
                     (= username new-username)))
              @db)
      (println "That combination already exist, delete and recreate to change.")
      (loop [password (gen-password password-length)]
        (copy-to-clipboard password)
        (println (str "A new password was generated into the clipboard. "
                      "Try if the site accepts it."))
        (let [choice (read-label-val "pwd ok? (y/n)")]
          (if (= choice "y")
            (do
              (add-to-db {:site new-site :username new-username :password password})
              (reset-clipboard))
            (recur (gen-password password-length))))))))

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
  (init-db (read-secret-key "master password"))
  (pass-repl))
