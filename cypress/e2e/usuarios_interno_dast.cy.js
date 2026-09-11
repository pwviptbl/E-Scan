describe("E-cidade DAST - Navegação DOM: Configuração > Cadastros > Cadastro de Usuários > Usuário Interno", () => {
  beforeEach(() => {
    cy.loginEcidade("dbseller", "");
    cy.url().should("include", "extension/desktop");
    cy.closeAllDesktopWindows();
  });

  // -------------------------------------------------------------
  // FUNÇÃO REUTILIZÁVEL DE NAVEGAÇÃO DOM ATÉ 'USUÁRIO INTERNO'
  // -------------------------------------------------------------
  const abrirMenuUsuarioInterno = () => {
    cy.openEcidadeMenu();
    cy.get("#menu", { timeout: 15000 }).should("be.visible");

    // 1. Área: CONFIGURAÇÃO
    cy.get("#areas span", { timeout: 15000 })
      .filter((i, el) => el.innerText.toUpperCase().includes("CONFIGURAÇÃO"))
      .first()
      .click({ force: true });

    cy.wait(800);

    // 2. Módulo: Configuração
    cy.get("#modulos span", { timeout: 15000 })
      .filter((i, el) => el.innerText.toUpperCase().includes("CONFIGURAÇÃO"))
      .first()
      .click({ force: true });

    cy.wait(800);

    // 3. Categoria: Cadastros
    cy.get(".menu-list span", { timeout: 15000 })
      .filter((i, el) => el.innerText.trim() === "Cadastros")
      .first()
      .click({ force: true });

    cy.wait(800);

    // 4. Subcategoria: Cadastro de Usuários
    cy.get(".menu-list span", { timeout: 15000 })
      .filter((i, el) => el.innerText.trim() === "Cadastro de Usuários")
      .first()
      .click({ force: true });

    cy.wait(800);

    // 5. Item: Usuário Interno
    cy.get(".menu-list span", { timeout: 15000 })
      .filter((i, el) => el.innerText.trim() === "Usuário Interno")
      .first()
      .click({ force: true });

    cy.wait(800);
  };

  // =============================================================
  // SUBROTINA 1: INCLUSÃO
  // =============================================================
  it("1. Navega via DOM até Inclusão, preenche e submete POST", () => {
    cy.log("[DAST] 1. Navegando via DOM para: INCLUSÃO...");
    abrirMenuUsuarioInterno();

    // Clica na subrotina terminal 'Inclusão'
    cy.get(".menu-list span", { timeout: 15000 })
      .filter((i, el) => el.innerText.trim() === "Inclusão")
      .first()
      .click({ force: true });

    cy.wait(2500);
    cy.screenshot("08_inclusao_janela_aberta");

    // Preenche CGM válido (CGM 6 = MUNICIPIO DE BAGE)
    cy.findInAllIframes("input[name='z01_numcgm'], input#z01_numcgm", 20000).then(($cgm) => {
      cy.wrap($cgm).clear().type("6{enter}", { force: true });
    });

    // Aguarda retorno RPC do nome do CGM para não sobrepor o login gerado automaticamente
    cy.wait(2000);

    // Preenche login único com timestamp para garantir unicidade
    const loginDast = `dast_${Date.now().toString().slice(-6)}`;
    cy.findInAllIframes("input[name='login'], input#login", 10000).then(($login) => {
      cy.wrap($login).clear().type(loginDast, { force: true });
    });

    cy.findInAllIframes("input[name='senha'], input#senha", 10000).then(($senha) => {
      cy.wrap($senha).clear().type("Dast123456@", { force: true });
    });

    cy.findInAllIframes("input[name='verificasenha'], input#verificasenha", 10000).then(($vsenha) => {
      cy.wrap($vsenha).clear().type("Dast123456@", { force: true });
    });

    cy.findInAllIframes("input[name='email'], input#email", 10000).then(($email) => {
      cy.wrap($email).clear().type("dast@dbseller.com.br", { force: true });
    });

    cy.screenshot("09_inclusao_preenchida");

    // Clica no botão 'Incluir' para disparar a requisição POST (con1_db_usuarios004.php)
    cy.findInAllIframes("input[name='incluir'], input[value*='Incluir']", 15000).then(($btn) => {
      cy.wrap($btn).first().click({ force: true });
    });

    cy.wait(3000);
    cy.screenshot("10_pos_submit_inclusao");
    cy.dismissAnyAlert();
  });

  // =============================================================
  // SUBROTINA 2: ALTERAÇÃO
  // =============================================================
  it("2. Navega via DOM até Alteração, busca registro, modifica e submete POST", () => {
    cy.log("[DAST] 2. Navegando via DOM para: ALTERAÇÃO...");
    abrirMenuUsuarioInterno();

    // Clica na subrotina terminal 'Alteração'
    cy.get(".menu-list span", { timeout: 15000 })
      .filter((i, el) => el.innerText.trim() === "Alteração")
      .first()
      .click({ force: true });

    cy.wait(3000);
    cy.screenshot("11_alteracao_janela_aberta");

    // No modal/iframe de pesquisa de usuário (func_db_usuariosalt.php), seleciona um usuário existente
    cy.findInAllIframes("a[onclick*='js_preenchepesquisa']", 25000).then(($link) => {
      cy.wrap($link.first()).click({ force: true });
      cy.wait(3000);

      // Aguarda o formulário carregar com os dados do usuário (onde o botão 'Alterar' fica habilitado)
      cy.findInAllIframes("input[name='alterar'], input#db_opcao", 20000).then(($btnAlt) => {
        // Se o usuário selecionado não tiver CGM vinculado, preenche CGM 6
        cy.findInAllIframes("input[name='z01_numcgm'], input#z01_numcgm", 10000).then(($cgmAlt) => {
          if (!$cgmAlt.val()) {
            cy.wrap($cgmAlt).clear().type("6{enter}", { force: true });
            cy.wait(1500);
          }
        });

        // Altera o e-mail do usuário
        cy.findInAllIframes("input[name='email'], input#email", 10000).then(($emailAlt) => {
          cy.wrap($emailAlt).clear({ force: true }).type("alterado_dast@dbseller.com.br", { force: true });
        });

        cy.screenshot("12_alteracao_preenchida");

        // Clica no botão 'Alterar' para submeter a alteração via POST (con1_db_usuarios005.php)
        cy.wrap($btnAlt).first().click({ force: true });
        cy.wait(3000);
        cy.dismissAnyAlert();
      });
    });

    cy.screenshot("13_pos_submit_alteracao");
  });
});
