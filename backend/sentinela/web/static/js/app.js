// Item 18 do plano de endurecimento pós-auditoria -- a CSP estrita
// (script-src 'self', sem 'unsafe-inline'; ver web/security_headers.py)
// bloqueia atributos de evento inline (onchange="...", onclick="..." etc).
// Este arquivo é o único lugar do HTML/HTMX (web/templates/) que precisa de
// JavaScript próprio além do htmx.min.js -- delegação de evento simples,
// ligada em elementos marcados com data-auto-submit em vez de onchange
// inline por elemento.
document.addEventListener("change", function (evento) {
  var alvo = evento.target.closest("[data-auto-submit]");
  if (alvo && alvo.form) {
    alvo.form.submit();
  }
});
