// ⚠️ MUESTRA FICTICIA 
// Vulnerabilidades y secretos SEMBRADOS A PROPÓSITO para probar scan-ts + Gitleaks y que
// el security gate bloquee
import { exec } from "child_process";

// FICTICIO: secretos hardcodeados (formato ALOLAB_ propio del lab).
const PAYMENTS_API_KEY = "3K9F2QX7M1ZP8RT5VW4NB6HC0YJ1LD5G";      // FICTICIA
const WEBHOOK_SIGNING_SECRET = "8H4D1NC6RT2ZP9QX7M3VW5KB0YJ4LF2G"; // FICTICIA

interface Webhook {
  monto: string;    // llega como texto desde el request
  archivo: string;  // nombre de archivo para el recibo
}

// FICTICIO: eval sobre un valor externo → ejecución de código arbitrario (CWE-95).
export function calcularMonto(hook: Webhook): unknown {
  return eval(hook.monto);
}

// FICTICIO: input concatenado a una shell → inyección de comandos (CWE-78).
export function generarRecibo(hook: Webhook): void {
  exec("cat /tmp/recibos/" + hook.archivo, (err, stdout) => {
    if (err) return;
    console.log(stdout);
  });
}

// Usa los secretos para que no salgan además como "variable sin usar" (ruido LOW).
export function credenciales(): Record<string, string> {
  return { apiKey: PAYMENTS_API_KEY, webhookSecret: WEBHOOK_SIGNING_SECRET };
}
