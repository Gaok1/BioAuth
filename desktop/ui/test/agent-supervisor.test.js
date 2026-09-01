'use strict';

// Guards around starting the daemon. Nothing here spawns a process: the cases
// worth pinning are the ones where the supervisor must *not* act.

const { test } = require('node:test');
const assert = require('node:assert');

const { AgentSupervisor } = require('../src/agent-supervisor');

const quiet = () => new AgentSupervisor({ onLog: () => {} });

test('does not start an agent when one is already serving', () => {
  // A systemd unit, or a user running it in a terminal, owns the agent. Two of
  // them would race over the endpoint file and the pairing store.
  const supervisor = quiet();
  supervisor.ensureRunning(true);
  assert.equal(supervisor.child, null);
});

test('starts nothing once stopped', () => {
  const supervisor = quiet();
  supervisor.stop();
  supervisor.ensureRunning(false);
  assert.equal(supervisor.child, null);
});

test('gives up after a bounded number of attempts', () => {
  const supervisor = quiet();
  supervisor.attempts = 99;
  supervisor.ensureRunning(false);
  assert.equal(supervisor.child, null, 'the attempt budget must be respected');
});

test('markHealthy restores the attempt budget', () => {
  const supervisor = quiet();
  supervisor.attempts = 99;
  supervisor.markHealthy();
  assert.equal(supervisor.attempts, 0);
});

test('a healthy agent cancels a restart that is no longer owed', async () => {
  // An agent this process started exits, and `exit` queues a restart three
  // seconds out that fires with `alreadyRunning: false`. If something else took
  // over in the meantime -- which is often *why* ours exited -- that queued
  // start is a rival to it, and the endpoint file and the pairing store have
  // one owner between them.
  const supervisor = quiet();
  let fired = false;
  supervisor.timer = setTimeout(() => {
    fired = true;
  }, 5);

  supervisor.markHealthy();

  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(fired, false, 'the queued restart must not run');
  assert.equal(supervisor.timer, null);
  supervisor.stop();
});
