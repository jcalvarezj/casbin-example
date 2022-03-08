package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	sqladapter "github.com/Blank-Xu/sql-adapter"
	"github.com/casbin/casbin/v2"
	"github.com/go-chi/chi"
	_ "github.com/go-sql-driver/mysql"
)

func finalizer(db *sql.DB) {
	err := db.Close()
	if err != nil {
		panic(err)
	}
}

func Authorizer(e *casbin.Enforcer) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			role := r.Header.Get("Role")
			resource := r.URL.RequestURI()
			method := r.Method

			if role == "" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("ERROR - There is no role assigned\n"))
				return
			}

			allowed, err := e.Enforce(role, resource, method)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("ERROR - " + err.Error()))
				return
			}
			if allowed {
				next.ServeHTTP(w, r)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("ERROR - The current role (" + role + ") is not allowed to execute " + resource + " [" + method + "]\n"))
				return
			}
		}

		return http.HandlerFunc(fn)
	}
}

func testPolicies(enforcer *casbin.Enforcer) {
	// Policies mapping roles, resources, and methods
	enforcer.AddPolicy("treasury", "/", "GET")
	enforcer.AddPolicy("treasury", "/collection/*", "GET")
	enforcer.AddPolicy("treasury", "/collection/*", "PUT")
	enforcer.AddPolicy("treasury", "/collection/*", "PATCH")

	enforcer.AddPolicy("lawyer", "/collection/*", "GET")
	enforcer.AddPolicy("lawyer", "/collection/*", "POST")

	enforcer.AddPolicy("admin", "/*", "*")

	// Save policies in DB
	if err := enforcer.SavePolicy(); err != nil {
		log.Println("Could not save policies: ", err)
	}
}

func main() {
	dbName := "prueba"
	dbUser := "prueba"
	dbPass := "prueba"
	dbPort := "3306"

	connectionString := fmt.Sprintf("%s:%s@tcp(127.0.0.1:%s)/%s", dbUser, dbPass, dbPort, dbName)

	db, err := sql.Open("mysql", connectionString)
	if err != nil {
		panic(err)
	}
	if err = db.Ping(); err != nil {
		panic(err)
	}

	adapter, err := sqladapter.NewAdapter(db, "mysql", "casbin_rule_test")
	if err != nil {
		panic(err)
	}

	enforcer, err := casbin.NewEnforcer("config/basic_model.conf", adapter)
	if err != nil {
		panic(err)
	}

	if err = enforcer.LoadPolicy(); err != nil {
		log.Println("Could not load policy: ", err)
	}

	port := "8080"

	log.Printf("Starting up on http://localhost:%s", port)

	r := chi.NewRouter()

	testPolicies(enforcer)

	r.Use(Authorizer(enforcer))

	r.With(Authorizer(enforcer)).Get("/", func(w http.ResponseWriter, r *http.Request) {
		role := r.Header.Get("Role")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<h1>Hello World! - " + role + "</h1>\n"))
	})

	r.With(Authorizer(enforcer)).Post("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<h1>CREATED! </h1>\n"))
	})

	r.With(Authorizer(enforcer)).Get("/collection/cosa", func(w http.ResponseWriter, r *http.Request) {
		role := r.Header.Get("Role")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<h1>WORKS! - " + role + "</h1>\n"))
	})

	log.Fatal(http.ListenAndServe(":"+port, r))
}
