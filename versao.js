// versao.js — FONTE ÚNICA DA VERDADE
window.SISTEMA_VERSAO = {
  versao: " mv 0.33",
  //codinome: "milli vanily",
  data: "21/10/26",
  notas: "Versão inicial MV"
};

console.log(
  `%c Sistema Fiscal ${SISTEMA_VERSAO.versao} (${SISTEMA_VERSAO.codinome}) `,
  "background:#0b6b5d;color:#fff;padding:4px 8px;border-radius:6px;font-weight:bold"
);

document.addEventListener('DOMContentLoaded', () => {
  // Versão no footer
  const elVersao = document.getElementById('footer-versao');
  if (elVersao) {
    elVersao.textContent = `Versão ${SISTEMA_VERSAO.versao}`;
    elVersao.title = `Atualizado em ${SISTEMA_VERSAO.data}`;
  }
});