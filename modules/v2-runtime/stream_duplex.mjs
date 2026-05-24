// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.

// Adapter: wrap a v2-runtime stream (`{ send, end, onData, onEnd }`)
// as a Node Duplex stream. Used by anon-layer tunnel factories AND by
// any tool that wants to feed an anon-layer stream into a TCP-shaped
// API (anon-site fetchOnce, an HTTP library, etc.).

import { Duplex } from 'node:stream';

export class StreamDuplex extends Duplex {

    constructor(stream) {

        super({ allowHalfOpen: true });
        this._anonStream = stream;
        this._queue = [];
        this._ended = false;

        stream.onData((bytes) => {

            this._queue.push(Buffer.from(bytes));
            this._flush();

        });
        stream.onEnd(() => {

            this._ended = true;
            this._flush();

        });

    }

    _read() { this._flush(); }

    _flush() {

        while (this._queue.length > 0) {

            const chunk = this._queue.shift();
            if (!this.push(chunk)) return;

        }
        if (this._ended) {

            this.push(null);
            this._ended = false;

        }

    }

    _write(chunk, encoding, callback) {

        try {

            this._anonStream.send(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
            callback();

        } catch (err) {

            callback(err);

        }

    }

    _final(callback) {

        try { this._anonStream.end(); } catch { /* ignore */ }
        callback();

    }

}

export const wrapAsDuplex = (stream) => new StreamDuplex(stream);
