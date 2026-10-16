import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { parseDotenvValue, readDotenv, writeDotenv, deleteDotenvKey, envPathFor } from '../src/dotenv.js';

describe('dotenv parsing (mirrors Go parseValue)', () => {
  it('handles quotes, comments, whitespace', () => {
    assert.equal(parseDotenvValue('"a b" # c'), 'a b');
    assert.equal(parseDotenvValue("'x'"), 'x');
    assert.equal(parseDotenvValue('plain # comment'), 'plain');
    assert.equal(parseDotenvValue('  spaced  '), 'spaced');
    assert.equal(parseDotenvValue(''), '');
  });
  it('reads files skipping comments/blank', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-dot-'));
    const file = path.join(dir, '.env');
    fs.writeFileSync(file, '# top\nA=1\n\nB="2 2" # keep?\nC = 3 # cmt\n');
    assert.deepEqual(readDotenv(file), { A: '1', B: '2 2', C: '3' });
    fs.rmSync(dir, { recursive: true, force: true });
  });
  it('missing file -> {}', () => {
    assert.deepEqual(readDotenv(path.join(os.tmpdir(), 'as-nope', '.env')), {});
  });
});

describe('dotenv merge-write (mirrors Go updateFile)', () => {
  let dir: string;
  let file: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-dotw-'));
    file = path.join(dir, '.env');
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('creates, merges preserving comments/order, quotes spaces', () => {
    writeDotenv(file, { A: '1' });
    fs.appendFileSync(file, '# note\nB=old\n');
    writeDotenv(file, { B: 'new value', C: 'x#y' });
    const raw = fs.readFileSync(file, 'utf8');
    assert.match(raw, /^A=1$/m);
    assert.match(raw, /^B="new value"$/m);
    assert.match(raw, /^C="x#y"$/m);
    assert.match(raw, /^# note$/m);
    assert.deepEqual(readDotenv(file), { A: '1', B: 'new value', C: 'x#y' });
  });
  it('is 0600 on POSIX', () => {
    if (process.platform === 'win32') return;
    writeDotenv(file, { A: '1' });
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  });
  it('deletes keys', () => {
    writeDotenv(file, { A: '1', B: '2' });
    deleteDotenvKey(file, 'A');
    assert.deepEqual(readDotenv(file), { B: '2' });
    deleteDotenvKey(file, 'ZZZ');
    deleteDotenvKey(path.join(dir, 'missing.env'), 'A');
  });
});

describe('envPathFor', () => {
  it('maps development -> .env, others -> .env.<env>', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-dotp-'));
    assert.equal(envPathFor(dir, 'development'), path.join(path.resolve(dir), '.env'));
    assert.equal(envPathFor(dir, 'production'), path.join(path.resolve(dir), '.env.production'));
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
