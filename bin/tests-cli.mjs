import { expect } from 'chai';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CLI = join(import.meta.dirname || new URL('.', import.meta.url).pathname, 'anon-node.mjs');

const runCmd = (args, { cwd } = {}) => new Promise((resolve) => {

    const child = spawn(process.execPath, [CLI, ...args], { cwd });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('exit', (code) => resolve({ code, stdout, stderr }));

});

const spawnDaemon = (args, { cwd } = {}) => {

    const child = spawn(process.execPath, [CLI, ...args], { cwd });
    const lines = [];
    child.stderr.on('data', (d) => { lines.push(d.toString()); });
    child.stdout.on('data', (d) => { lines.push(d.toString()); });
    const exited = new Promise((resolve) => child.on('exit', (code) => resolve(code)));
    return { child, exited, log: () => lines.join('') };

};

const waitFor = async (predicate, { intervalMs = 30, timeoutMs = 3000 } = {}) => {

    const start = Date.now();
    while (Date.now() - start < timeoutMs) {

        if (predicate()) return true;
        await new Promise((r) => setTimeout(r, intervalMs));

    }
    return false;

};

describe('bin/anon-node CLI', function () {

    this.timeout(10000);

    let dir;

    beforeEach(async () => {

        dir = await mkdtemp(join(tmpdir(), 'anon-cli-'));

    });

    afterEach(async () => {

        await rm(dir, { recursive: true, force: true });

    });

    it('init creates identity, config, empty seed list', async () => {

        const { code, stdout } = await runCmd(['init', './node.json'], { cwd: dir });
        expect(code).to.equal(0);
        expect(stdout).to.contain('fingerprint:');
        const cfg = JSON.parse(await readFile(join(dir, 'node.json'), 'utf8'));
        expect(cfg.identity.path).to.equal('./node.identity.key');
        expect(cfg.listen.port).to.equal(8443);
        const id = await readFile(join(dir, 'node.identity.key'));
        expect(id.length).to.equal(64);
        const seeds = await readFile(join(dir, 'node.seeds.bin'));
        expect(seeds.length).to.equal(0);

    });

    it('init refuses to overwrite existing config', async () => {

        await runCmd(['init', './node.json'], { cwd: dir });
        const { code, stderr } = await runCmd(['init', './node.json'], { cwd: dir });
        expect(code).to.equal(1);
        expect(stderr).to.match(/refusing to overwrite/);

    });

    it('info prints fingerprint and listen address', async () => {

        await runCmd(['init', './node.json'], { cwd: dir });
        const { code, stdout } = await runCmd(['info', './node.json'], { cwd: dir });
        expect(code).to.equal(0);
        expect(stdout).to.match(/fingerprint:\s+[0-9a-f]{64}/);
        expect(stdout).to.match(/listen:\s+127\.0\.0\.1:8443/);
        expect(stdout).to.match(/seed list:.*0 records/);

    });

    it('run starts, listens, and exits cleanly on SIGINT', async () => {

        await runCmd(['init', './node.json'], { cwd: dir });
        // Use a non-default port to avoid conflicts on developer
        // machines that may already have something on 8443.
        const cfgPath = join(dir, 'node.json');
        const cfg = JSON.parse(await readFile(cfgPath, 'utf8'));
        cfg.listen.port = 0; // let the OS pick
        await readFile(cfgPath); // ensure read
        // Rewrite config with port 0.
        const { writeFile } = await import('node:fs/promises');
        await writeFile(cfgPath, JSON.stringify(cfg, null, 2));

        const daemon = spawnDaemon(['run', './node.json'], { cwd: dir });
        const listening = await waitFor(() => /INFO\s+listening/.test(daemon.log()));
        expect(listening, `did not see 'listening' log line:\n${daemon.log()}`).to.equal(true);

        daemon.child.kill('SIGINT');
        const code = await daemon.exited;
        expect(code, `non-zero exit; log:\n${daemon.log()}`).to.equal(0);
        expect(daemon.log()).to.match(/shutdown complete/);

    });

    it('run with malformed seed list refuses to start', async () => {

        await runCmd(['init', './node.json'], { cwd: dir });
        // Write some garbage into the actual seeds file the config
        // references — init derives the path from the config name.
        const { writeFile } = await import('node:fs/promises');
        await writeFile(join(dir, 'node.seeds.bin'), Buffer.from([1, 2, 3]));

        const daemon = spawnDaemon(['run', './node.json'], { cwd: dir });
        const code = await daemon.exited;
        expect(code).to.equal(2);
        expect(daemon.log()).to.match(/seed list malformed/);

    });

    it('init --port overrides the default listen port', async () => {

        const { code } = await runCmd(['init', './node.json', '--port', '19001'], { cwd: dir });
        expect(code).to.equal(0);
        const { stdout } = await runCmd(['info', './node.json'], { cwd: dir });
        expect(stdout).to.match(/listen:\s+127\.0\.0\.1:19001/);

    });

    it('share + add-seed round-trip between two configs', async () => {

        await runCmd(['init', './a.json', '--port', '19101'], { cwd: dir });
        await runCmd(['init', './b.json', '--port', '19102'], { cwd: dir });

        const aShare = await runCmd(['share', './a.json'], { cwd: dir });
        expect(aShare.code).to.equal(0);
        const aHex = aShare.stdout.trim();
        expect(aHex).to.match(/^[0-9a-f]+$/);

        const add = await runCmd(['add-seed', './b.json', aHex], { cwd: dir });
        expect(add.code).to.equal(0);
        expect(add.stdout).to.match(/added:\s+[0-9a-f]{64}/);
        expect(add.stdout).to.match(/total seeds:\s+1/);

        // Refuses duplicates.
        const dup = await runCmd(['add-seed', './b.json', aHex], { cwd: dir });
        expect(dup.code).to.equal(1);
        expect(dup.stderr).to.match(/already exists/);

    });

    it('add-seed rejects malformed hex', async () => {

        await runCmd(['init', './node.json'], { cwd: dir });
        const result = await runCmd(['add-seed', './node.json', 'not-hex'], { cwd: dir });
        expect(result.code).to.equal(1);

    });

    it('two nodes complete a real handshake over WebSocket', async function () {

        // The handshake requires one tick interval to complete (the
        // tick sends each side's KEY_CERTIFICATE). Default tickIntervalMs
        // is 5000; we override to 200 ms for tests so the case runs
        // quickly. Operationally, 5s is appropriate (low gossip volume).
        this.timeout(10000);

        await runCmd(['init', './a.json', '--port', '19201'], { cwd: dir });
        await runCmd(['init', './b.json', '--port', '19202'], { cwd: dir });

        // Tighten tickIntervalMs for test speed.
        const { readFile, writeFile } = await import('node:fs/promises');
        for (const name of ['./a.json', './b.json']) {

            const cfg = JSON.parse(await readFile(join(dir, name), 'utf8'));
            cfg.tickIntervalMs = 200;
            await writeFile(join(dir, name), JSON.stringify(cfg, null, 2));

        }

        const aHex = (await runCmd(['share', './a.json'], { cwd: dir })).stdout.trim();
        const bHex = (await runCmd(['share', './b.json'], { cwd: dir })).stdout.trim();
        await runCmd(['add-seed', './b.json', aHex], { cwd: dir });
        await runCmd(['add-seed', './a.json', bHex], { cwd: dir });

        const a = spawnDaemon(['run', './a.json'], { cwd: dir });
        const b = spawnDaemon(['run', './b.json'], { cwd: dir });
        try {

            const aConnected = await waitFor(
                () => /peer connected/.test(a.log()),
                { timeoutMs: 5000 },
            );
            const bConnected = await waitFor(
                () => /peer connected/.test(b.log()),
                { timeoutMs: 5000 },
            );
            expect(aConnected, `A never saw a peer:\n${a.log()}`).to.equal(true);
            expect(bConnected, `B never saw a peer:\n${b.log()}`).to.equal(true);

        } finally {

            a.child.kill('SIGINT');
            b.child.kill('SIGINT');
            await Promise.all([a.exited, b.exited]);

        }

    });

});
