describe("E-cidade DAST - Crawler Automático de Menus e Rotinas", () => {
  const areaTarget = Cypress.env("AREA") || "CONFIGURAÇÃO";
  const moduloTarget = Cypress.env("MODULO") || null;
  const categoriaTarget = Cypress.env("CATEGORIA") || null;
  const subcategoriaTarget = Cypress.env("SUBCATEGORIA") || null;
  const rotinaTarget = Cypress.env("ROTINA") || null;
  const maxRoutines = parseInt(Cypress.env("MAX_ROUTINES") || "0", 10);

  const normalize = (str) =>
    (str || "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .trim()
      .toLowerCase();

  function extractTerminalLeaves(node, pathIds = [], pathNames = []) {
    let leaves = [];
    const currentPathIds = [...pathIds, node.id];
    const currentPathNames = [...pathNames, node.nome];

    if (node.action && (!node.filhos || Object.keys(node.filhos).length === 0)) {
      leaves.push({
        id: node.id,
        nome: node.nome,
        action: node.action,
        breadcrumb: (moduloTarget ? `${moduloTarget} > ` : "") + currentPathNames.join(" > "),
        pathIds: currentPathIds,
        pathNames: currentPathNames
      });
    } else if (node.filhos) {
      const children = Object.values(node.filhos);
      children.sort((a, b) => (parseInt(a.menusequencia, 10) || 0) - (parseInt(b.menusequencia, 10) || 0));
      for (const child of children) {
        leaves = leaves.concat(extractTerminalLeaves(child, currentPathIds, currentPathNames));
      }
    }
    return leaves;
  }

  beforeEach(() => {
    cy.loginEcidade("dbseller", "");
    cy.url().should("include", "extension/desktop");
    cy.closeAllDesktopWindows();
  });

  const abrirNavegacaoBase = () => {
    cy.ensureEcidadeMenuOpen();

    // 1. Seleciona Área
    cy.get("#areas span", { timeout: 15000 })
      .filter((i, el) => normalize(el.innerText).includes(normalize(areaTarget)))
      .first()
      .click({ force: true });
    cy.wait(800);

    // 2. Seleciona Módulo se fornecido, senão primeiro módulo visível
    if (moduloTarget) {
      cy.get("#modulos span", { timeout: 15000 })
        .filter((i, el) => normalize(el.innerText).includes(normalize(moduloTarget)))
        .first()
        .click({ force: true });
    } else {
      cy.get("#modulos span:visible", { timeout: 15000 }).first().click({ force: true });
    }
    cy.wait(1200);
  };

  it(`Percorre dinamicamente as rotinas de: ${areaTarget} > ${moduloTarget || "*"} > ${categoriaTarget || "*"}`, () => {
    abrirNavegacaoBase();

    // Aguarda o container de itens do módulo ser carregado
    cy.get("#modulos").parent().nextAll(".menu-list-container").find(".menu-list span", { timeout: 15000 }).should("exist");

    cy.window().then((win) => {
      const $ = win.jQuery || win.$;
      const $catSpans = $("#modulos").parent().nextAll(".menu-list-container").find(".menu-list span");

      let relevantNodes = [];

      $catSpans.each((_, el) => {
        const data = $(el).data("menu.filhos");
        if (data) {
          if (categoriaTarget) {
            if (normalize(data.nome) === normalize(categoriaTarget)) {
              relevantNodes.push(data);
            }
          } else {
            relevantNodes.push(data);
          }
        }
      });

      if (relevantNodes.length === 0 && categoriaTarget) {
        // Fallback por includes caso haja variação sutil
        $catSpans.each((_, el) => {
          const data = $(el).data("menu.filhos");
          if (data && data.nome && normalize(data.nome).includes(normalize(categoriaTarget))) {
            relevantNodes.push(data);
          }
        });
      }

      cy.task("log", `[DAST] Categorias identificadas: ${relevantNodes.map(n => n.nome).join(", ")}`);

      // Extrai recursivamente todas as folhas terminais com action PHP
      let leaves = [];
      relevantNodes.forEach((node) => {
        leaves = leaves.concat(extractTerminalLeaves(node));
      });

      // Filtro por subcategoria se fornecido
      if (subcategoriaTarget) {
        const subNorm = normalize(subcategoriaTarget);
        leaves = leaves.filter((leaf) =>
          normalize(leaf.breadcrumb).includes(subNorm) ||
          leaf.pathNames.some((n) => normalize(n).includes(subNorm))
        );
      }

      // Filtro por rotina específica se fornecido
      if (rotinaTarget) {
        const rotNorm = normalize(rotinaTarget);
        leaves = leaves.filter((leaf) =>
          normalize(leaf.breadcrumb).includes(rotNorm) ||
          leaf.pathNames.some((n) => normalize(n).includes(rotNorm))
        );
      }

      const totalFound = leaves.length;
      if (maxRoutines > 0) {
        leaves = leaves.slice(0, maxRoutines);
      }

      cy.task("log", `[DAST] Encontradas ${totalFound} rotinas terminais. Executando: ${leaves.length}...`);

      // Exporta mapa completo das rotinas mapeadas para correlação no Scanner
      const routinesMap = {};
      leaves.forEach((l) => {
        routinesMap[l.action] = {
          breadcrumb: l.breadcrumb,
          nome: l.nome,
          action: l.action,
          id: l.id
        };
      });
      cy.writeFile("logs/routines_map.json", routinesMap);

      // Executa sequencialmente cada rotina terminal via navegação DOM
      leaves.forEach((leaf, idx) => {
        cy.task("log", `[DAST] [${idx + 1}/${leaves.length}] Executando: ${leaf.breadcrumb} (${leaf.action})`);

        // 1. Limpa janelas abertas
        cy.closeAllDesktopWindows();

        // 2. Abre o menu principal
        cy.ensureEcidadeMenuOpen();

        // 3. Move barra de menus para o início (esquerda)
        cy.get(".menu-action-home").click({ force: true });
        cy.wait(300);

        // 4. Navega pelo DOM clicando em cada nó até a folha terminal
        leaf.pathIds.forEach((stepId, stepIdx) => {
          cy.get(`#menu_id_${stepId}`, { timeout: 15000 })
            .scrollIntoView()
            .click({ force: true });

          if (stepIdx < leaf.pathIds.length - 1) {
            cy.wait(400);
          }
        });

        // 5. Aguarda renderização da janela aberta e seu iframe
        cy.wait(2500);

        // 6. Fuzzing inteligente dos formulários
        cy.fuzzGenericForm();

        // 7. Fecha todas as janelas após a execução
        cy.closeAllDesktopWindows();
      });
    });
  });
});
