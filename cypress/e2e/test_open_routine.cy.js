describe("Test Open Routine and Form Interaction", () => {
  it("Abre menu, navega ate rotina e interage com o formulario", () => {
    cy.loginEcidade("dbseller", "");
    cy.url().should("include", "extension/desktop");

    // Abre o menu CARDÁPIO
    cy.openEcidadeMenu();
    cy.get("#menu").should("be.visible");

    // Clica em CONFIGURAÇÃO
    cy.get("#areas span").filter(":contains('CONFIGURAÇÃO')").first().click({ force: true });
    cy.wait(1500);

    // Clica no primeiro módulo que aparecer em #modulos
    cy.get("#modulos span").first().click({ force: true });
    cy.wait(1500);

    // Tira screenshot das categorias que abriram à direita de módulos
    cy.screenshot("04_categorias_abertas");

    // Inspeciona os novos containers gerados
    cy.get(".menu-list-container").then(($containers) => {
      cy.log(`Containers de menu abertos: ${$containers.length}`);
    });

    // Clica recursivamente no primeiro item de cada coluna até achar uma rotina terminal (que tem data-action)
    function clickTerminalItem() {
      cy.get(".menu-list-container:visible").last().find(".menu-list span:visible").first().then(($item) => {
        cy.log(`Clicando no item: ${$item.text()}`);
        cy.wrap($item).click({ force: true });
        cy.wait(1500);

        cy.get("body").then(($body) => {
          const hasWindow = $body.find(".window, iframe").length > 0;
          if (hasWindow) {
            cy.log("Janela da rotina aberta com sucesso!");
          } else {
            clickTerminalItem();
          }
        });
      });
    }

    clickTerminalItem();
    cy.wait(3000);
    cy.screenshot("05_janela_rotina_aberta");
  });
});
