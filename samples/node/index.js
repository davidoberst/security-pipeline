// MUESTRA FICTICIA — laboratorio del pipeline de seguridad. No se despliega.
// Vulnerabilidades sembradas a propósito para probar scan-node:
//   - code injection (eval)  → eslint security/detect-eval-with-expression + Semgrep lab.js.eval-injection
//   - command injection      → eslint security/detect-child-process + Semgrep lab.js.command-injection
//   - bug de lógica           → eslint no-unreachable
//   - dependencia con CVE     → lodash 4.17.20 (CVE-2021-23337, en _.template)
"use strict";

const { exec } = require("child_process");
const _ = require("lodash");

// VULNERABLE A PROPÓSITO: evalúa una expresión que llega desde afuera.
function calcularDemo(expr) {
  return eval(expr);
}

// VULNERABLE A PROPÓSITO: el input llega a una shell sin validar.
function listarDemo(dir, callback) {
  exec("ls -la " + dir, callback);
}

// VULNERABLE A PROPÓSITO: _.template de lodash 4.17.20.
function saludoDemo(nombre) {
  return _.template("Hola <%= nombre %>")({ nombre });
}

// BUG A PROPÓSITO (no-unreachable): el log nunca se ejecuta.
function estadoDemo(codigo) {
  return codigo === 200 ? "ok" : "error";
  console.log("estado calculado");
}

module.exports = { calcularDemo, listarDemo, saludoDemo, estadoDemo };
