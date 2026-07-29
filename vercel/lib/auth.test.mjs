import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generate, verify, currentWindow } from './auth.js';

const TEST_SECRET = '0123456789abcdef0123456789abcdef';

describe('auth', () => {
  it('golden register', () => {
    const token = generate(TEST_SECRET, 'register', 1000000);
    assert.equal(token.length, 32);
    assert.equal(token, '6cb2fbc4a51a0132a2909d6110251362');
  });

  it('golden discover', () => {
    const token = generate(TEST_SECRET, 'discover', 1000000);
    assert.equal(token, '210a9b69b8ffce133e9d2d96c63262b0');
  });

  it('golden gate', () => {
    const token = generate(TEST_SECRET, 'gate', 1000000);
    assert.equal(token, '0a5b30e06bfa21db06f164a4c3535665');
  });

  it('verify exact window', () => {
    const token = generate(TEST_SECRET, 'gate', 5000);
    assert.ok(verify(TEST_SECRET, 'gate', token, 5000));
  });

  it('verify tolerance +1', () => {
    const token = generate(TEST_SECRET, 'gate', 4999);
    assert.ok(verify(TEST_SECRET, 'gate', token, 5000));
  });

  it('verify tolerance -1', () => {
    const token = generate(TEST_SECRET, 'gate', 5001);
    assert.ok(verify(TEST_SECRET, 'gate', token, 5000));
  });

  it('verify outside tolerance', () => {
    const token = generate(TEST_SECRET, 'gate', 4998);
    assert.ok(!verify(TEST_SECRET, 'gate', token, 5000));
  });

  it('purpose mismatch', () => {
    const token = generate(TEST_SECRET, 'register', 5000);
    assert.ok(!verify(TEST_SECRET, 'discover', token, 5000));
  });

  it('wrong secret', () => {
    const token = generate('wrong-secret-32-bytes-long!!!!!', 'gate', 5000);
    assert.ok(!verify(TEST_SECRET, 'gate', token, 5000));
  });

  it('rejects short token', () => {
    assert.ok(!verify(TEST_SECRET, 'gate', 'too-short', 5000));
  });

  it('currentWindow returns positive', () => {
    assert.ok(currentWindow() > 0);
  });
});
