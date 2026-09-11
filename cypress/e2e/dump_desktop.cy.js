describe("Dump Desktop DOM", () => {
  it("Dump DOM after login", () => {
    cy.loginEcidade("dbseller", "");
    cy.url().should("include", "extension/desktop");
    cy.wait(2000);
    cy.document().then((doc) => {
      cy.writeFile("cypress/desktop_dom.html", doc.documentElement.outerHTML);
    });
  });
});
