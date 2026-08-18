/**
 * Goya SDK — Complete FES example
 *
 * Run against a local node:
 *   npx tsx src/example.ts
 *
 * Run against production:
 *   npx tsx src/example.ts https://goya-node.fly.dev
 */

import { GoyaClient, generateKeypair } from './index.js';

const nodeUrl = process.argv[2] || 'http://localhost:8080';
const client = new GoyaClient(nodeUrl);

console.log(`\n── Goya SDK Example ──\n`);
console.log(`Node: ${nodeUrl}\n`);

// 1. Generate keypairs
const alice = await generateKeypair();
const bob = await generateKeypair();
console.log(`Alice: ${alice.did}`);
console.log(`Bob:   ${bob.did}\n`);

// 2. Register identities
await client.registerIdentity(alice);
await client.registerIdentity(bob);
console.log('Identities registered.\n');

// 3. Deploy NDA from template
const contract = await client.deploy({
  template: 'nda',
  parties: {
    discloser: alice.did,
    recipient: bob.did,
  },
  payload: { scope: 'SDK integration test' },
});
console.log(`Contract: ${contract.id}`);
console.log(`State:    ${contract.state}`);
console.log(`Hash:     ${contract.content_hash.slice(0, 16)}...\n`);

// 4. Alice signs (FES)
const afterAlice = await client.signWithKeypair(
  contract.id,
  alice,
  contract.content_hash,
);
console.log(`Alice signed → ${afterAlice.state}`);

// 5. Bob signs (FES)
const afterBob = await client.signWithKeypair(
  contract.id,
  bob,
  contract.content_hash,
);
console.log(`Bob signed   → ${afterBob.state}\n`);

// 6. Retrieve final state
const final = await client.getContract(contract.id);
console.log(`Final state: ${final.state}`);
for (const p of final.parties) {
  const algo = p.envelope?.signature_algorithm ?? '—';
  console.log(`  ${p.role.padEnd(12)} ${p.did}  signed=${p.signed}  algo=${algo}`);
}

console.log(`\n✓ Done. NDA signed by both parties with Ed25519.\n`);
