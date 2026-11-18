// MUESTRA FICTICIA — laboratorio del pipeline de seguridad. No se despliega.
// Vulnerabilidades sembradas a propósito para probar scan-go:
//   - command injection   → gosec G204 + Semgrep lab.go.command-injection
//   - bug de lógica        → staticcheck SA4006
//   - dependencia con CVE  → golang.org/x/text v0.3.7 (CVE-2022-32149), llamada de verdad
//     desde idiomaDemo para que govulncheck la marque como ALCANZABLE.
package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"

	"golang.org/x/text/language"
)

// VULNERABLE A PROPÓSITO: el parámetro "host" llega a una shell sin validar.
func pingDemo(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, err := exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput()
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(out)
}

// VULNERABLE A PROPÓSITO: ParseAcceptLanguage de x/text v0.3.7 (CVE-2022-32149, DoS).
func idiomaDemo(cabecera string) string {
	tags, _, err := language.ParseAcceptLanguage(cabecera)
	if err != nil || len(tags) == 0 {
		return "es"
	}
	return tags[0].String()
}

// BUG A PROPÓSITO (staticcheck SA4006): el primer valor de total nunca se usa.
func cuotaDemo(monto float64, meses int) float64 {
	total := monto * 1.02
	total = monto / float64(meses)
	return total
}

func main() {
	http.HandleFunc("/ping", pingDemo)
	fmt.Println(idiomaDemo(os.Getenv("ACCEPT_LANGUAGE_DEMO")))
	fmt.Println(cuotaDemo(1000, 12))
}
