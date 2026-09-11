import './commands'

// Ignora erros não capturados da aplicação PHP legada
Cypress.on('uncaught:exception', (err, runnable) => {
  return false;
});
