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
      // 1. Trata campos CGM genericos (*cgm / *numcgm)
      const $cgm = $root.find("input[name*='cgm'], input[id*='cgm']").filter(":visible");
      if ($cgm.length > 0) {
        $cgm.each((_, el) => {
          const $el = Cypress.$(el);
          const name = ($el.attr("name") || "").toLowerCase();
          if (!$el.prop("readonly") && !$el.prop("disabled") && !$el.val() && !name.includes("nome") && !name.includes("descr")) {
            $el.val("6");
            $el.trigger("change");
          }
        });
      }

      // 2. Preenche senhas se houver
      $root.find("input[type='password']:visible").each((_, el) => {
        const $pwd = Cypress.$(el);
        if (!$pwd.prop("readonly") && !$pwd.prop("disabled")) {
          $pwd.val("Dast123456@");
          $pwd.trigger("input");
        }
      });

      // 3. Preenche datas legadas (dia, mes, ano sao hidden no db_inputdata) e campos de data visiveis
      $root.find("input[name$='_dia']").each((_, el) => {
        el.value = "01";
      });
      $root.find("input[name$='_mes']").each((_, el) => {
        el.value = "01";
      });
      $root.find("input[name$='_ano']").each((_, el) => {
        el.value = "2026";
      });
      $root.find("input[name*='dt'], input[name*='data'], input[onblur*='js_validaDbData']").filter(":visible").each((_, el) => {
        const $el = Cypress.$(el);
        if (!$el.prop("readonly") && !$el.prop("disabled") && !$el.val()) {
          $el.val("01/01/2026");
          $el.trigger("input");
          $el.trigger("change");
        }
      });

      // 4. Preenche emails se houver
      $root.find("input[type='email'], input[name*='email']:visible").each((_, el) => {
        const $em = Cypress.$(el);
        if (!$em.prop("readonly") && !$em.prop("disabled")) {
          $em.val("dast@dbseller.com.br");
          $em.trigger("input");
        }
      });

      // 5. Preenche outros campos de texto vazios
      $root.find("input[type='text']:visible, textarea:visible").each((_, el) => {
        const $el = Cypress.$(el);
        const name = ($el.attr("name") || "").toLowerCase();
        if (!$el.prop("readonly") && !$el.prop("disabled") && !$el.val() && !name.includes("cgm") && !name.includes("dt") && !name.includes("data") && !name.endsWith("_dia") && !name.endsWith("_mes") && !name.endsWith("_ano")) {
          $el.val(name.includes("login") ? `dast_${Date.now().toString().slice(-5)}` : "1");
          $el.trigger("input");
        }
      });

      // 6. Clica no botao de acao principal (prioriza inclusao / persistencia)
      const primarySubmitBtn = $root.find(
        "input[name='incluir'], input[value*='Incluir'], input[name='salvar'], input[value*='Salvar'], input[type='submit'][value*='Incluir']"
      ).first();

      const secondarySubmitBtn = $root.find(
        "input[name='alterar'], input[value*='Alterar'], input[value*='Gravar'], input[type='submit']"
      ).first();

      const searchBtn = $root.find(
        "input[name='pesquisar'], input[value*='Pesquisar'], input#pesquisar2, input[value*='Consultar']"
      ).first();

      const btnToClick = primarySubmitBtn.length > 0 ? primarySubmitBtn : (secondarySubmitBtn.length > 0 ? secondarySubmitBtn : searchBtn);

      if (btnToClick && btnToClick.length > 0) {
        const btnName = btnToClick.attr("name") || "incluir";
        const btnVal = btnToClick.val() || "Incluir";
        cy.task("log", `[DAST Debug] -> Submetendo acao: name='${btnName}' val='${btnVal}'`);
        const formEl = btnToClick.closest("form")[0];
        if (formEl) {
          formEl.onsubmit = null;

          // Se o botao existir como submit, converte para hidden para ser serializado no submit()
          const existingBtn = formEl.elements[btnName];
          if (existingBtn) {
            existingBtn.type = "hidden";
            existingBtn.value = btnVal;
          } else {
            const hiddenInput = formEl.ownerDocument.createElement("input");
            hiddenInput.type = "hidden";
            hiddenInput.name = btnName;
            hiddenInput.value = btnVal;
            formEl.appendChild(hiddenInput);
          }

          try {
            HTMLFormElement.prototype.submit.call(formEl);
          } catch (e) {
            btnToClick[0].click();
          }
        } else {
          try {
            btnToClick[0].click();
          } catch (e) {
            btnToClick.trigger("click");
          }
        }
      }
    }

    function scanAndProcessIframes($container, depth = 0) {
      if (depth > 4) return;
      const $frames = $container.find("iframe");
      cy.task("log", `[DAST Debug] Depth ${depth}: encontrados ${$frames.length} iframes`);

      $frames.each((i, frame) => {
        try {
          const fDoc = frame.contentDocument;
          const fBody = fDoc?.body;
          const frameSrc = (frame.src || frame.getAttribute("src") || "").toLowerCase();
          const frameId = frame.id || frame.name || `frame_${i}`;
          cy.task("log", `[DAST Debug] -> Frame [${frameId}]: src='${frameSrc}' body=${Boolean(fBody)}`);

          if (fBody) {
            const $fBody = Cypress.$(fBody);

            if (frameSrc.includes("func_") || frameId.includes("db_iframe_")) {
              const $modalSearch = $fBody.find("input[name='pesquisar'], input[value*='Pesquisar'], input#pesquisar2").filter(":visible").first();
              cy.task("log", `[DAST Debug]    -> Modal de lookup detectado. Pesquisar: ${$modalSearch.length}`);
              if ($modalSearch.length > 0) {
                $fBody.find("input[type='text']:visible").first().val("1");
                $modalSearch.click();
              }
            } else {
              const inputsCount = $fBody.find("input, select, textarea").length;
              cy.task("log", `[DAST Debug]    -> Conteudo de rotina detectado. Inputs: ${inputsCount}`);
              processFormInElement($fBody);
            }

            scanAndProcessIframes($fBody, depth + 1);
          }
        } catch (e) {
          cy.task("log", `[DAST Debug] Frame erro de acesso: ${e.message}`);
        }
      });
    }

    const $mainDoc = Cypress.$(doc);
    scanAndProcessIframes($mainDoc, 0);
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

