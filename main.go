package main

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"reflect"
	"runtime"
	"strings"

	"github.com/Dainsleif233/Edu-Auth/auths"
	"github.com/Dainsleif233/Edu-Auth/utils"
)

var authFns = make(map[string]reflect.Value)

func RegisterFunction(fn any) {
	fnValue := reflect.ValueOf(fn)
	funcName := runtime.FuncForPC(fnValue.Pointer()).Name()
	nameParts := strings.Split(funcName, ".")
	shortName := nameParts[len(nameParts)-1]
	authFns[shortName] = fnValue
}

func callAuth(funcName, login, password string) uint8 {
	fn, exists := authFns[funcName]
	if !exists {
		return 4
	}

	params := []reflect.Value{
		reflect.ValueOf(login),
		reflect.ValueOf(password),
	}
	return fn.Call(params)[0].Interface().(uint8)
}

func main() {

	RegisterFunction(auths.Eduroam)

	args := os.Args
	address := "127.0.0.1:2266"
	if len(args) > 1 {
		address = args[1]
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		login := r.FormValue("login")
		password := r.FormValue("password")

		id := strings.ToLower(path.Base(r.URL.Path))
		result := callAuth(utils.SnakeToCamel(id), login, password)

		switch result {
		case 0:
			w.Write([]byte("EAP Success\n<h3>测试结果: <span style=\"color: green;\">OK，认证过程正常</span></h3>"))
		case 1:
			w.Write([]byte("EAP Failure"))
		case 2:
			w.Write([]byte("illegal"))
		case 3:
			w.Write([]byte("error"))
		default:
			http.Error(w, "Handler not found: "+id, http.StatusNotFound)
		}
	})

	fmt.Println("Edu-Auth running on " + address)
	http.ListenAndServe(address, nil)
}
