/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

const fs = require('fs')
const path = require('path')

// Intentionally vulnerable handler demonstrating CWE-23 (Relative Path Traversal)
// Reads an arbitrary file from disk based on a user-supplied path without proper normalization/validation
module.exports = function unsafePathTraversal () {
  return ({ query }, res, next) => {
    const file = query.file // e.g., ?file=../../../../etc/passwd
    if (!file) {
      res.status(400)
      return next(new Error('Missing file query parameter'))
    }

    // VULNERABLE: directly joining untrusted input into a filesystem path and reading it
    // This allows traversal out of the intended directory via sequences like ../
    const target = path.join(process.cwd(), file)

    fs.readFile(target, 'utf8', (err, data) => {
      if (err) {
        res.status(404)
        return next(new Error('File not found or unreadable: ' + file))
      }
      res.type('text/plain').send(data)
    })
  }
}


