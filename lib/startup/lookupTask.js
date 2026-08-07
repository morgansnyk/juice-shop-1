/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

/* jslint node: true */

/**
 * Metadata for startup phases labeled on {@code startup_duration_seconds} (task label).
 * Keep in sync with {@code collectDurationPromise} / manual timers in server.js.
 */
const STARTUP_TASKS = Object.freeze({
  validatePreconditions: { description: 'Verifies the process environment is safe to start in.' },
  restoreOverwrittenFilesWithOriginals: { description: 'Restores original files overwritten by challenge content.' },
  cleanupFtpFolder: { description: 'Removes stale files from the FTP folder.' },
  validateConfig: { description: 'Validates application YAML configuration against the schema.' },
  datacreator: { description: 'Seeds or updates the database from configuration.' },
  ready: { description: 'Marks total time until the HTTP server reported ready.' },
  customizeApplication: { description: 'Applies branding and customization from configuration.' },
  customizeEasterEgg: { description: 'Applies easter-egg overrides from configuration.' }
})

/**
 * Looks up a startup task by the name used as the Prometheus {@code task} label.
 *
 * @param {string} name
 * @returns {{ description: string } | null}
 */
function lookupTask (name) {
  if (name == null || typeof name !== 'string') {
    return null
  }
  return STARTUP_TASKS[name] || null
}

module.exports = { lookupTask, STARTUP_TASKS }
