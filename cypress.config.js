const { defineConfig } = require("cypress");

module.exports = defineConfig({
  e2e: {
    baseUrl: "http://localhost:8085/e-cidade-php74",
    specPattern: "cypress/e2e/**/*.cy.js",
    supportFile: "cypress/support/e2e.js",
    viewportWidth: 1366,
    viewportHeight: 768,
    video: false,
    screenshotOnRunFailure: true,
    chromeWebSecurity: false,

    setupNodeEvents(on, config) {
      on("task", {
        log(message) {
          console.log(message);
          return null;
        }
      });

      return config;
    }
  }
});
