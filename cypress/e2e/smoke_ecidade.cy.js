describe("E-cidade DAST Smoke Test - Login e Menu", () => {
  it("Deve logar no E-cidade com dbseller (senha vazia) e abrir o Menu Principal / CARDÁPIO", () => {
    cy.loginEcidade("dbseller", "");

    cy.url().should("include", "extension/desktop");

    // Abre o Menu CARDÁPIO
    cy.openEcidadeMenu();

    // Aguarda o container do menu aparecer
    cy.wait(1500);

    cy.screenshot("02_menu_cardapio_aberto");

    // Inspeciona os elementos do menu no DOM para registrar no log
    cy.get("body").then(($body) => {
      const areas = $body.find("[class*='area_'], [class*='area-'], .x-tree-node, .menu-item");
      cy.log(`Elementos de menu encontrados: ${areas.length}`);
    });
  });
});
