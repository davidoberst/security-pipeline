// MUESTRA FICTICIA — prueba del pipeline (PR juanbustos67). No se despliega.
// Vulnerabilidad sembrada a propósito: command injection (CWE-78).
package main

import (
	"net/http"
	"os/exec"
)

// VULNERABLE A PROPÓSITO: "archivo" llega desde la petición y se arma
// un comando de shell con ese valor sin validarlo.
func backupDemo(w http.ResponseWriter, r *http.Request) {
	archivo := r.URL.Query().Get("archivo")
	out, err := exec.Command("bash", "-c", "tar -czf /tmp/backup.tgz "+archivo).CombinedOutput()
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(out)
}
