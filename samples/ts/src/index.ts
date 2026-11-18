// ⚠️ MUESTRA FICTICIA del laboratorio de seguridad. NO es código real ni se despliega.
// Contiene vulnerabilidades A PROPÓSITO para probar que el pipeline (scan-ts) las detecta
// y que el security gate bloquea. No copiar este patrón.
import { exec } from "child_process";

interface Entrada {
  formula: string;
  carpeta: string;
}

// FICTICIO: evalúa una expresión que llega desde afuera → ejecución de código arbitrario.
export function calcularDemo(entrada: Entrada): unknown {
  return eval(entrada.formula);
}

// FICTICIO: arma un comando de shell concatenando input → inyección de comandos.
export function listarDemo(entrada: Entrada): void {
  exec("ls -la " + entrada.carpeta, (err, stdout) => {
    if (err) return;
    console.log(stdout);
  });
}

// FICTICIO: bug de lógica (código inalcanzable) para la categoría LÓGICA.
export function estadoDemo(activo: boolean): string {
  return activo ? "activo" : "inactivo";
  console.log("nunca se ejecuta");
}
