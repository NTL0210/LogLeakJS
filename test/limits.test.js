import assert from 'node:assert/strict';
import test from 'node:test';
import { createLogLeakDetector } from '../src/index.js';
import { analyze } from '../test-support/helpers.js';

test('maxRecords truncates input and marks the analysis incomplete', () => {
  const result = analyze(['one', 'two', 'three'], { limits: { maxRecords: 2 } });

  assert.equal(result.summary.recordsAnalyzed, 2);
  assert.equal(result.coverage, 'incomplete');
  assert.equal(result.summary.incompleteReasons.includes('max-records-exceeded'), true);
  assert.equal(
    result.diagnostics.some((diagnostic) => diagnostic.code === 'max-records-exceeded'),
    true,
  );
});

test('an oversized record is rejected and never silently passes', () => {
  const result = analyze('a'.repeat(200), {
    limits: { maxRecordBytes: 128, maxTotalBytes: 1024 },
  });

  assert.equal(result.status, 'incomplete');
  assert.equal(result.summary.recordsAnalyzed, 0);
  assert.equal(result.summary.incompleteReasons.includes('max-record-bytes-exceeded'), true);
});

test('the total byte budget stops analysis and marks it incomplete', () => {
  const result = analyze(['a'.repeat(600), 'b'.repeat(600)], {
    limits: { maxRecordBytes: 1024, maxTotalBytes: 1024 },
  });

  assert.equal(result.status, 'incomplete');
  assert.equal(result.summary.recordsAnalyzed, 1);
  assert.equal(result.summary.incompleteReasons.includes('max-total-bytes-exceeded'), true);
});

test('maxDepth stops traversal and marks the analysis incomplete', () => {
  const record = { a: { b: { c: { d: 'deep' } } } };
  const result = analyze(record, { limits: { maxDepth: 2 } });

  assert.equal(result.coverage, 'incomplete');
  assert.equal(result.summary.incompleteReasons.includes('max-depth-exceeded'), true);
});

test('maxNodesPerRecord stops traversal and marks the analysis incomplete', () => {
  const record = Object.fromEntries(
    Array.from({ length: 50 }, (_, index) => [`key${index}`, 'value']),
  );
  const result = analyze(record, { limits: { maxNodesPerRecord: 10 } });

  assert.equal(result.coverage, 'incomplete');
  assert.equal(result.summary.incompleteReasons.includes('max-nodes-exceeded'), true);
});

test('maxFindings truncates findings and reports the truncation', () => {
  const result = analyze(['aaaaaaaa', 'bbbbbbbb'], {
    knownSecrets: ['aaaaaaaa', 'bbbbbbbb'],
    limits: { maxFindings: 1 },
  });

  assert.equal(result.status, 'leaks');
  assert.equal(result.findings.length, 1);
  assert.equal(result.summary.incompleteReasons.includes('max-findings-exceeded'), true);
});

test('maxDiagnostics drops extra diagnostics and marks the analysis incomplete', () => {
  const record = {};
  for (let index = 0; index < 30; index += 1) {
    Object.defineProperty(record, `getter${index}`, {
      enumerable: true,
      get() {
        return 'synthetic';
      },
    });
  }

  const result = analyze(record, { limits: { maxDiagnostics: 1 } });
  assert.equal(result.coverage, 'incomplete');
  assert.equal(result.diagnostics.length, 1);
  assert.equal(result.summary.diagnosticsDropped, 29);
  assert.equal(result.summary.incompleteReasons.includes('max-diagnostics-exceeded'), true);
});

test('the time limit is enforced without a silent pass', () => {
  const originalNow = Date.now;
  const base = originalNow();
  let calls = 0;
  Date.now = () => {
    calls += 1;
    return calls === 1 ? base : base + 10_000;
  };

  try {
    const result = analyze(['one', 'two'], { limits: { timeLimitMs: 1 } });
    assert.equal(result.status, 'incomplete');
    assert.equal(result.summary.recordsAnalyzed, 0);
    assert.equal(result.summary.incompleteReasons.includes('time-limit-exceeded'), true);
  } finally {
    Date.now = originalNow;
  }
});

test('limit values are visible in the result summary and frozen', () => {
  const detector = createLogLeakDetector({
    limits: { maxRecords: 7, maxDepth: 3 },
  });
  const result = detector.analyze([]);
  assert.equal(result.summary.limits.maxRecords, 7);
  assert.equal(result.summary.limits.maxDepth, 3);
  assert.equal(Object.isFrozen(result.summary.limits), true);
});

test('exceeding any bound never produces status "pass"', () => {
  const cases = [
    analyze(['one', 'two'], { limits: { maxRecords: 1 } }),
    analyze('a'.repeat(130), { limits: { maxRecordBytes: 128, maxTotalBytes: 1024 } }),
    analyze({ a: { b: { c: 1 } } }, { limits: { maxDepth: 1 } }),
  ];

  for (const result of cases) {
    assert.notEqual(result.status, 'pass');
    assert.equal(result.coverage, 'incomplete');
    assert.equal(result.failOnIncomplete, true);
  }
});
