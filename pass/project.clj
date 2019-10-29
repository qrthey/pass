(defproject pass "0.1.0"
  :description "Terminal based password manager"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.10.0"]]
  :repl-options {:init-ns pass.core}
  :main ^:skip-aot pass.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
