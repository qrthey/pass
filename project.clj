(defproject pass "0.1.0"
  :description "Terminal based password manager"
  :license {name "The MIT License"
            :url "http://opensource.org/licenses/MIT"
            :distribution :repo}
  :dependencies [[org.clojure/clojure "1.10.0"]]
  :repl-options {:init-ns pass.core}
  :main ^:skip-aot pass.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
