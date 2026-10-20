'use strict';

/**
 * GuardFi — structured console logger (no external dependency).
 *
 * Reads LOG_LEVEL lazily on every call so it works no matter how early it is
 * imported (config/env.js loads dotenv after this module is required).
 */

const LEVELS = Object.freeze({ error: 0, warn: 1, info: 2, debug: 3 });

function activeLevel() {
  const fallback = process.env.NODE_ENV === 'production' ? 'info' : 'debug';
  const raw = String(process.env.LOG_LEVEL || fallback).trim().toLowerCase();
  const level = LEVELS[raw];
  return level === undefined ? LEVELS.info : level;
}

function describe(meta) {
  if (meta === undefined || meta === null) return '';
  if (meta instanceof Error) return `\n${meta.stack || meta.message}`;
  if (typeof meta === 'string') return ` ${meta}`;
  try {
    return ` ${JSON.stringify(meta)}`;
  } catch {
    return ' [unserializable metadata]';
  }
}

function emit(level, message, meta) {
  if (LEVELS[level] > activeLevel()) return;
  const line = `${new Date().toISOString()} [${level.toUpperCase().padEnd(5)}] ${message}${describe(meta)}`;
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}

module.exports = {
  error: (message, meta) => emit('error', message, meta),
  warn: (message, meta) => emit('warn', message, meta),
  info: (message, meta) => emit('info', message, meta),
  debug: (message, meta) => emit('debug', message, meta),
};
