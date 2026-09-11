describe("E-cidade DAST - Inclusão de Rotina e Captura de POST", () => {
  it("Abre rotina de cadastro, preenche dados e executa submissão POST", () => {
    cy.loginEcidade("dbseller", "");
    cy.url().should("include", "extension/desktop");

    // Abre a rotina diretamente pelo Desktop Window (simulando clique de menu terminal)
    cy.window().then((win) => {
      win.Desktop.Window.create("Categorias de Acordo", {
        action: "aco1_acordocategoria001.php",
        iInstitId: 1,
        iAreaId: 4,
        iModuloId: 604
      });
    });

    cy.wait(2000);

    // Encontra o iframe da janela aberta e preenche o formulário
    cy.findInAllIframes("input[name='ac50_descricao']", 30000).then(($input) => {
      cy.wrap($input).clear().type("Categoria Teste DAST", { force: true });
    });

    cy.screenshot("06_formulario_preenchido");

    // Clica no botão de ação 'Incluir' para submeter o formulário via POST
    cy.findInAllIframes("input[type='submit'][value*='Incluir'], #db_opcao, input[name='incluir']", 30000).then(($btn) => {
      cy.wrap($btn).first().click({ force: true });
    });

    cy.wait(3000);
    cy.screenshot("07_pos_submit_post");
  });
});
