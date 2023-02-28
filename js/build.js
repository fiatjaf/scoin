#!/usr/bin/env node

const fs = require('fs')
const esbuild = require('esbuild')

esbuild
  .build({
    entryPoints: ['target/scala-3.2.0/scoin-fastopt/main.js'],
    bundle: true,
    sourcemap: 'external',
    outfile: 'lib/scoin.bundle.js',
    format: 'iife',
    globalName: 'Scoin',
    define: {
      window: 'self',
      global: 'self',
      process: '{"env": {}}'
    }
  })
  .then(() => console.log('standalone build success.'))
