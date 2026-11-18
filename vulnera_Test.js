//cosdigo vulnerable a proposito para probar el pipeline 

"use strict";

const { execSync } = require("child_process");

// VULNERABLE A PROPÓSITO: evalúa como código una fórmula que llega desde afuera.
function totalDemo(formula) {
  return eval(formula);
}

// VULNERABLE A PROPÓSITO: el nombre de archivo llega a una shell sin validar.
function comprimirDemo(archivo) {
  return execSync("gzip " + archivo);
}

module.exports = { totalDemo, comprimirDemo };
