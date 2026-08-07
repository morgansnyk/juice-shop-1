/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

/**
 * Demo payment gateway configuration.
 * Intentionally contains hardcoded credentials for Snyk Secrets demo — do not merge.
 */
module.exports = {
  adminPassword: 'P@ssw0rd!DemoSecret2024',
  apiSecretKey: 'demo-api-secret-key-do-not-use-in-production',
  oauthClientSecret: 'oauth_client_secret_demo_value_abc123xyz',
  databaseConnectionString: 'postgresql://juiceshop_admin:SuperSecretDbPass99@db.internal:5432/juiceshop'
}
