'use strict';

/**
 * GuardFi — Atlas connectivity diagnostic (temporary, safe to delete)
 *
 * Prints WHERE the connection fails: URI shape, DNS SRV, A/AAAA records, TCP
 * reachability, TLS handshake, and a driver connect attempt with IPv4 forced.
 * It never prints the password or the full connection string.
 */

require('dotenv').config({ quiet: true });

const dns = require('node:dns').promises;
const net = require('node:net');
const tls = require('node:tls');
const mongoose = require('mongoose');

const raw = process.env.MONGO_URI || '';

function mask(uri) {
  return uri.replace(/(mongodb(?:\+srv)?:\/\/)[^@]*@/, '$1***:***@');
}

function timeIt(fn) {
  const started = Date.now();
  return Promise.resolve()
    .then(fn)
    .then((value) => ({ ok: true, value, ms: Date.now() - started }))
    .catch((error) => ({ ok: false, error: `${error.code || error.name}: ${error.message}`, ms: Date.now() - started }));
}

function tcpProbe(host, port, family) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = net.connect({ host, port, family, timeout: 6000 });
    const done = (result) => {
      socket.destroy();
      resolve({ ...result, ms: Date.now() - started });
    };
    socket.once('connect', () => done({ ok: true, local: `${socket.localAddress}:${socket.localPort}` }));
    socket.once('timeout', () => done({ ok: false, error: 'timeout' }));
    socket.once('error', (error) => done({ ok: false, error: `${error.code || error.message}${error.address ? ` (${error.address})` : ''}` }));
  });
}

function tlsProbe(host, port) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = tls.connect({ host, port, servername: host, timeout: 8000, rejectUnauthorized: false }, () => {
      resolve({ ok: true, protocol: socket.getProtocol(), ms: Date.now() - started });
      socket.destroy();
    });
    socket.once('timeout', () => {
      resolve({ ok: false, error: 'timeout', ms: Date.now() - started });
      socket.destroy();
    });
    socket.once('error', (error) => {
      resolve({ ok: false, error: `${error.code || error.message}: ${error.message}`, ms: Date.now() - started });
      socket.destroy();
    });
  });
}

async function driverProbe(uri, options) {
  const started = Date.now();
  const connection = mongoose.createConnection();

  try {
    await connection.openUri(uri, { ...options, serverSelectionTimeoutMS: 8000, bufferCommands: false });
    return { ok: true, host: connection.host, name: connection.name, ms: Date.now() - started };
  } catch (error) {
    return { ok: false, error: `${error.name}: ${error.message.split('\n')[0]}`, ms: Date.now() - started };
  } finally {
    await connection.close().catch(() => {});
  }
}

async function main() {
  console.log('MONGO_URI =', mask(raw));

  if (!raw) {
    console.log('MONGO_URI is empty');
    return;
  }

  const isSrv = raw.startsWith('mongodb+srv://');
  let host;
  let dbPath;
  let paramKeys;
  let passwordProfile;

  try {
    const normalized = raw.replace(/^mongodb(\+srv)?:\/\//, 'http://');
    const parsed = new URL(normalized);
    host = parsed.hostname;
    dbPath = parsed.pathname || '(none)';
    paramKeys = [...parsed.searchParams.keys()];
    const password = decodeURIComponent(parsed.password || '');
    passwordProfile = {
      length: password.length,
      hasNonAlphanumeric: /[^A-Za-z0-9]/.test(password),
      hasPercentEncodedInUri: /%[0-9A-Fa-f]{2}/.test(parsed.password || ''),
      hasLiteralAtSign: (parsed.password || '').includes('@'),
    };
  } catch (error) {
    console.log('URI could not be parsed as a URL:', error.message);
    return;
  }

  console.log('scheme        =', isSrv ? 'mongodb+srv' : 'mongodb');
  console.log('host          =', host);
  console.log('database path =', dbPath);
  console.log('query keys    =', paramKeys.join(', ') || '(none)');
  console.log('password      =', passwordProfile);

  if (isSrv) {
    const srv = await timeIt(() => dns.resolveSrv(`_mongodb._tcp.${host}`));
    console.log('SRV lookup    =', JSON.stringify(srv));

    if (srv.ok) {
      const targets = srv.value.map((entry) => entry.name);
      for (const target of targets) {
        const a = await timeIt(() => dns.resolve4(target));
        const aaaa = await timeIt(() => dns.resolve6(target));
        console.log(`  ${target}`);
        console.log(`    A    = ${a.ok ? a.value.join(',') : a.error}`);
        console.log(`    AAAA = ${aaaa.ok ? aaaa.value.join(',') : aaaa.error}`);
        console.log(`    TCP v4 = ${JSON.stringify(await tcpProbe(target, 27017, 4))}`);
        if (aaaa.ok) console.log(`    TCP v6 = ${JSON.stringify(await tcpProbe(target, 27017, 6))}`);
        console.log(`    TLS  = ${JSON.stringify(await tlsProbe(target, 27017))}`);
      }
    }
  } else {
    console.log('TCP =', JSON.stringify(await tcpProbe(host, 27017, 0)));
    console.log('TLS =', JSON.stringify(await tlsProbe(host, 27017)));
  }

  console.log('driver default  =', JSON.stringify(await driverProbe(raw, {})));
  console.log('driver family 4 =', JSON.stringify(await driverProbe(raw, { family: 4 })));
  console.log('driver tls insecure =', JSON.stringify(await driverProbe(raw, { tlsAllowInvalidCertificates: true, family: 4 })));
}

main()
  .catch((error) => console.error('diagnostic crashed:', error))
  .finally(() => process.exit(0));
