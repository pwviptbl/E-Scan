/**
 * ============================================================
 * COMANDOS DE NAVEGAÇÃO MULTI-IFRAME E DAST PARA O E-CIDADE
 * ============================================================
 */

function deepIframeSearch(root, selector) {
  const found = root.find(selector);
  if (found.length > 0) return found;

  const frames = root.find("iframe");
  for (let i = 0; i < frames.length; i++) {
    const iframe = frames[i];
    const body = iframe.contentDocument?.body;
    if (body) {
      const result = deepIframeSearch(Cypress.$(body), selector);
      if (result && result.length > 0) return result;
    }
  }
  return null;
}

Cypress.Commands.add("findInAllIframes", (selector, timeout = 15000) => {
  const start = Date.now();

  function tryFind() {
    return cy.document().then((doc) => {
      const root = Cypress.$(doc.body);
      const result = deepIframeSearch(root, selector);

      if (result && result.length > 0) return cy.wrap(result);

      if (Date.now() - start > timeout) {
        throw new Error(`Elemento '${selector}' não encontrado em nenhum iframe dentro do timeout.`);
      }

      return cy.wait(400).then(tryFind);
    });
  }

  return tryFind();
});

Cypress.Commands.add("getIframeBody", (iframeSelector = "iframe#corpo") => {
  return cy
    .get(iframeSelector, { timeout: 30000 })
    .should("exist")
    .then(($iframe) => {
      const iframe = $iframe[0];
      return new Cypress.Promise((resolve) => {
        const tryResolve = () => {
          const body = iframe.contentDocument?.body;
          if (body && body.children.length > 0) {
            resolve(cy.wrap(body));
          }
        };
        tryResolve();
        iframe.addEventListener("load", tryResolve);
        setTimeout(tryResolve, 1500);
      });
    });
});

Cypress.Commands.add("waitForCorpoIframe", () => {
  return cy.get("iframe#corpo", { timeout: 30000 }).should("be.visible");
});

/**
 * Login flexível para o E-cidade
 * Suporta senha vazia e redirecionamento para o desktop
 */
Cypress.Commands.add("loginEcidade", (username = "dbseller", password = "") => {
  cy.visit("/login.php");

  cy.get("#usu_login", { timeout: 15000 })
    .should("be.visible")
    .clear()
    .type(username);

  if (password && password.trim() !== "") {
    cy.get("#usu_senha").clear().type(password);
  } else {
    cy.get("#usu_senha").clear();
  }

  // Clica no botão Entrar
  cy.get("#btnlogar").should("be.visible").click();

  // Aguarda carregamento do Desktop / Menu
  cy.location("pathname", { timeout: 30000 }).should("not.include", "login.php");
});

/**
 * Abre o menu principal do E-cidade
 * Trata variações de tema: .taskbar-menu-button, CARDÁPIO, etc.
 */
Cypress.Commands.add("openEcidadeMenu", () => {
  cy.get(".taskbar-menu-button, div[title='Menu Principal']", { timeout: 20000 })
    .should("be.visible")
    .click({ force: true });
});

/**
 * Garante que o menu do E-cidade está aberto (sem fechar caso já esteja ativo)
 */
Cypress.Commands.add("ensureEcidadeMenuOpen", () => {
  cy.get("#menu").then(($menu) => {
    if (!$menu.hasClass("active")) {
      cy.get(".taskbar-menu-button, div[title='Menu Principal']", { timeout: 20000 })
        .should("be.visible")
        .click({ force: true });
    }
  });
  cy.get("#menu", { timeout: 15000 }).should("have.class", "active");
});

/**
 * Preenchimento dinâmico inteligente de formulários em janelas do E-cidade
 */
Cypress.Commands.add("fuzzGenericForm", () => {
  cy.document().then((doc) => {
    // Procura em todas as janelas e iframes abertos
    function processFormInElement($root) {
      // 1. Trata CGM se existir no formulário
      const $cgm = $root.find("input[name='z01_numcgm'], input#z01_numcgm").filter(":visible");
      if ($cgm.length > 0 && !$cgm.prop("readonly") && !$cgm.prop("disabled") && !$cgm.val()) {
        $cgm.val("6");
        $cgm.trigger("change");
      }

      // 2. Preenche senhas se houver
      $root.find("input[type='password']:visible").each((_, el) => {
        const $pwd = Cypress.$(el);
        if (!$pwd.prop("readonly") && !$pwd.prop("disabled")) {
          $pwd.val("Dast123456@");
          $pwd.trigger("input");
        }
      });

      // 3. Preenche emails se houver
      $root.find("input[type='email'], input[name*='email']:visible").each((_, el) => {
        const $em = Cypress.$(el);
        if (!$em.prop("readonly") && !$em.prop("disabled")) {
          $em.val("dast@dbseller.com.br");
          $em.trigger("input");
        }
      });

      // 4. Preenche outros campos de texto vazios
      $root.find("input[type='text']:visible, textarea:visible").each((_, el) => {
        const $el = Cypress.$(el);
        const name = ($el.attr("name") || "").toLowerCase();
        if (!$el.prop("readonly") && !$el.prop("disabled") && !$el.val() && !name.includes("cgm")) {
          $el.val(name.includes("login") ? `dast_${Date.now().toString().slice(-5)}` : "1");
          $el.trigger("input");
        }
      });

      // 5. Interage com modais de busca (DBAncora / func_*.php)
      // No E-cidade, campos chave (CGM, Ruas, etc.) possuem links âncora que abrem janelas de pesquisa
      const $ancoras = $root.find("a.DBAncora:visible, a[onclick*='js_pesquisa']:visible");
      if ($ancoras.length > 0) {
        $ancoras.each((idx, a) => {
          if (idx < 2) { // Limita a 2 modais por tela para não onerar o tempo de execução
            try {
              a.click();
            } catch (e) {}
          }
        });
      }

      // 6. Clica no primeiro botão de submissão encontrado
      const submitBtn = $root.find(
        "input[type='submit'], input[name='incluir'], input[name='alterar'], input[value*='Incluir'], input[value*='Salvar'], input[value*='Pesquisar'], input[value*='Consultar']"
      ).filter(":visible").first();

      if (submitBtn.length > 0 && !submitBtn.prop("disabled")) {
        submitBtn.click();
      }
    }

    const $mainDoc = Cypress.$(doc);

    // Varre iframes principais e janelas modais de pesquisa (DBView / Window)
    $mainDoc.find("iframe").each((_, frame) => {
      try {
        const fBody = frame.contentDocument?.body;
        if (fBody) {
          const $fBody = Cypress.$(fBody);
          processFormInElement($fBody);

          // Sub-iframes internos (janelas de lookup db_iframe_* / func_*.php)
          $fBody.find("iframe").each((__, subFrame) => {
            try {
              const sfDoc = subFrame.contentDocument;
              const sfBody = sfDoc?.body;
              if (sfBody) {
                const $sfBody = Cypress.$(sfBody);
                // Se for um modal de pesquisa func_*.php, dispara busca interna para registrar tráfego POST/GET
                const $searchBtn = $sfBody.find("input[name='pesquisar'], input[value*='Pesquisar'], input#pesquisar2").filter(":visible").first();
                if ($searchBtn.length > 0) {
                  $sfBody.find("input[type='text']:visible").first().val("1");
                  $searchBtn.click();
                } else {
                  processFormInElement($sfBody);
                }
              }
            } catch (e) {}
          });
        }
      } catch (e) {}
    });
  });

  cy.wait(2000);
  cy.dismissAnyAlert();
});

/**
 * Fecha todas as janelas do desktop E-cidade
 */
Cypress.Commands.add("closeAllDesktopWindows", () => {
  cy.window().then((win) => {
    try {
      const alertBtn = Cypress.$(win.document).find("#alertify-ok, .alertify-button-ok, .alertify-button").filter(":visible");
      if (alertBtn.length > 0) {
        alertBtn.first().click();
      }
    } catch (e) {}

    try {
      Cypress.$(win.document).find("div[id$='_close'], .window_close, .ecidade_close").each((_, el) => {
        el.click();
      });
    } catch (e) {}

    try {
      if (win.Windows && Array.isArray(win.Windows.windows)) {
        win.Windows.windows.forEach((w) => {
          if (w && w.getId) win.Windows.close(w.getId());
        });
      }
    } catch (e) {}
  });
  cy.wait(400);
});

/**
 * Fecha popups/alertify se houver
 */
Cypress.Commands.add("dismissAnyAlert", () => {
  cy.document().then((doc) => {
    const okBtn = Cypress.$(doc).find("#alertify-ok, .alertify-button-ok, .alertify-button, button:contains('OK')").filter(":visible");
    if (okBtn.length > 0) {
      cy.wrap(okBtn.first()).click({ force: true });
    }
  });
});

