/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

const exec = require('child_process').exec
const utils = require('../lib/utils')

module.exports = function systemDiagnostics () {
  return (req, res) => {
    const command = req.query.cmd || 'echo "No command specified"'
    
    // VULNERABILITY: Command injection - user input is directly passed to exec without sanitization
    exec(command, (error, stdout, stderr) => {
      if (error) {
        res.status(500).json({
          error: 'Command execution failed',
          details: error.message
        })
        return
      }
      
      res.json({
        command: command,
        stdout: stdout,
        stderr: stderr
      })
    })
  }
}
