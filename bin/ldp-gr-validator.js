#!/usr/bin/env node
'use strict';

const { readFileSync } = require('node:fs');
const { LdpGrValidator } = require('../src/validator');

function main() {
  const file = process.argv[2];
  if (!file) {
    console.error('usage: node bin/ldp-gr-validator.js <input.json>');
    process.exit(2);
  }
  const input = JSON.parse(readFileSync(file, 'utf8'));
  const report = new LdpGrValidator(input).run();
  console.log(JSON.stringify(report, null, 2));
}

main();
