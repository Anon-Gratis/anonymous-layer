import { expect } from 'chai';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const NODE_CLI = join(import.meta.dirname || new URL('.', import.meta.url).pathname, 'anon-node.mjs');
const CHAT_CLI = join(import.meta.dirname || new URL('.', import.meta.url).pathname, 'anon-chat.mjs');

const runCmd = (script, args, { cwd } = {}) => new Promise((resolve) => {

    const child = spawn(process.execPath, [script, ...args], { cwd });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('exit', (code) => resolve({ code, stdout, stderr }));

});

const spawnChat = (args, { cwd } = {}) => {

    const child = spawn(process.execPath, [CHAT_CLI, ...args], {
        cwd,
        stdio: ['pipe', 'pipe', 'pipe'],
    });
    const lines = [];
    child.stdout.on('data', (d) => { lines.push(d.toString()); });
    child.stderr.on('data', (d) => { lines.push(d.toString()); });
    const exited = new Promise((resolve) => child.on('exit', (code) => resolve(code)));
    return {
        child,
        exited,
        log: () => lines.join(''),
        write: (s) => child.stdin.write(s),
    };

};

const waitFor = async (predicate, { intervalMs = 30, timeoutMs = 5000 } = {}) => {

    const start = Date.now();
    while (Date.now() - start < timeoutMs) {

        if (predicate()) return true;
        await new Promise((r) => setTimeout(r, intervalMs));

    }
    return false;

};

describe('bin/anon-chat', function () {

    this.timeout(15000);

    let dir;
    let aFp, bFp;

    beforeEach(async () => {

        dir = await mkdtemp(join(tmpdir(), 'anon-chat-'));

        // Initialise two anon-node configs with distinct ports.
        await runCmd(NODE_CLI, ['init', './a.json', '--port', '19401'], { cwd: dir });
        await runCmd(NODE_CLI, ['init', './b.json', '--port', '19402'], { cwd: dir });

        // Speed up the gossip tick so the handshake completes quickly.
        for (const name of ['./a.json', './b.json']) {

            const cfg = JSON.parse(await readFile(join(dir, name), 'utf8'));
            cfg.tickIntervalMs = 200;
            await writeFile(join(dir, name), JSON.stringify(cfg, null, 2));

        }

        // Exchange seed records so each side knows the other.
        const aShare = await runCmd(NODE_CLI, ['share', './a.json'], { cwd: dir });
        const bShare = await runCmd(NODE_CLI, ['share', './b.json'], { cwd: dir });
        await runCmd(NODE_CLI, ['add-seed', './b.json', aShare.stdout.trim()], { cwd: dir });
        await runCmd(NODE_CLI, ['add-seed', './a.json', bShare.stdout.trim()], { cwd: dir });

        const aInfo = await runCmd(NODE_CLI, ['info', './a.json'], { cwd: dir });
        const bInfo = await runCmd(NODE_CLI, ['info', './b.json'], { cwd: dir });
        aFp = aInfo.stdout.match(/fingerprint:\s+([0-9a-f]{64})/)[1];
        bFp = bInfo.stdout.match(/fingerprint:\s+([0-9a-f]{64})/)[1];

    });

    afterEach(async () => {

        await rm(dir, { recursive: true, force: true });

    });

    it('refuses to start when peer fingerprint is not in seed list', async () => {

        const unknownFp = '0'.repeat(64);
        const result = await runCmd(CHAT_CLI, ['./a.json', unknownFp], { cwd: dir });
        expect(result.code).to.equal(1);
        expect(result.stderr).to.match(/not in seed list/);

    });

    it('refuses to start on a malformed peer fingerprint', async () => {

        const result = await runCmd(CHAT_CLI, ['./a.json', 'not-a-fingerprint'], { cwd: dir });
        expect(result.code).to.equal(1);
        expect(result.stderr).to.match(/64 hex characters/);

    });

    it('two chat clients exchange messages end-to-end', async () => {

        const a = spawnChat(['./a.json', bFp], { cwd: dir });
        const b = spawnChat(['./b.json', aFp], { cwd: dir });
        try {

            // Wait for both sides to print "* connected to ...".
            const aReady = await waitFor(() => /\* connected to/.test(a.log()), { timeoutMs: 5000 });
            const bReady = await waitFor(() => /\* connected to/.test(b.log()), { timeoutMs: 5000 });
            expect(aReady, `A never connected:\n${a.log()}`).to.equal(true);
            expect(bReady, `B never connected:\n${b.log()}`).to.equal(true);

            // A says hi.
            a.write('hello from A\n');
            const bSaw = await waitFor(() => /hello from A/.test(b.log()), { timeoutMs: 3000 });
            expect(bSaw, `B never received A's message:\n${b.log()}`).to.equal(true);

            // B replies.
            b.write('ack from B\n');
            const aSaw = await waitFor(() => /ack from B/.test(a.log()), { timeoutMs: 3000 });
            expect(aSaw, `A never received B's reply:\n${a.log()}`).to.equal(true);

        } finally {

            a.child.stdin.end();
            b.child.stdin.end();
            await Promise.all([a.exited, b.exited]);

        }

    });

});
