// Run web/verify.js on one certificate under node, as a browser runs it (the
// same file, unmodified, with a `window` shim), and print its checks and
// summary rows as JSON.   node tests/gap_history_node.mjs FILE
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const WEB = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'web');
const sandbox = { window: {}, TextEncoder, TextDecoder, crypto, atob, btoa, console, Blob, Response, DecompressionStream };
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(WEB, 'verify.js'), 'utf8'), sandbox, { filename: 'verify.js' });
const result = await sandbox.window.CoriqoVerify.verifyJson(JSON.parse(fs.readFileSync(process.argv[2], 'utf8')));
process.stdout.write(JSON.stringify({ checks: result.checks, summary: result.summary }));
