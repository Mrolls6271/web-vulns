package main

import (
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
)

func main() {
	http.HandleFunc("/path-traversal", func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable to path traversal attack
		filename := r.URL.Query().Get("file")
		data, err := os.ReadFile("/home/user/" + filename)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		fmt.Fprintln(w, string(data))
		// Demo payload: /?file=../../../etc/passwd
	})

	http.HandleFunc("/rce", func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable to RCE
		cmd := exec.Command("echo", r.URL.Query().Get("name"))
		output, err := cmd.Output()
		if err != nil {
			http.Error(w, "Error running command", http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, string(output))
		// Demo payload: /?name=${{7*7}}
	})

	http.HandleFunc("/sqli", func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable to SQLI
		username := r.URL.Query().Get("username")
		query := fmt.Sprintf("SELECT * FROM users WHERE username='%s'", username)
		db.Query(query)
		// Demo payload: /?username=' OR 1=1 --
	})

	http.HandleFunc("/xss", func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable to XSS
		fmt.Fprintf(w, "<h1>Hello, %s!</h1>", r.URL.Query().Get("name"))
		// Demo payload: /?name=<script>alert('XSS')</script>
	})

	http.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable to redirect attacks
		http.Redirect(w, r, r.URL.Query().Get("url"), http.StatusTemporaryRedirect)
		// Demo payload: /?url=http://evil.com
	})

	http.HandleFunc("/ssti", func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable to SSTI
		tmpl := `
				{{define "main"}}
				{{index . "content"}}
				{{end}}
			`
		t, err := template.New("foo").Parse(tmpl)
		if err != nil {
			http.Error(w, "Error parsing template", http.StatusInternalServerError)
			return
		}
		err = t.Execute(w, map[string]string{"content": r.URL.Query().Get("content")})
		if err != nil {
			http.Error(w, "Error executing template", http.StatusInternalServerError)
			return
		}
		// Demo payload: /?content={{7*7}}
	})

	http.HandleFunc("/ssrf", func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable to SSRF
		resp, err := http.Get(r.URL.Query().Get("url"))
		if err != nil {
			http.Error(w, "Error fetching URL", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "Error reading response body", http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, string(body))
		// Demo payload: /?url=http://localhost:8080/path-traversal?file=/etc/passwd
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}