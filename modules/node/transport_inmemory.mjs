// In-memory transport pair for deterministic testing of the dispatcher
// and node assembly without spinning up real WebSocket servers.
//
// Each side exposes the small Transport interface the dispatcher uses:
//
//   send(bytes)           transmit a frame
//   onMessage(handler)    register receive callback (handler(bytes))
//   onClose(handler)      register close callback
//   close()               disconnect, fires onClose on the peer
//
// Delivery is synchronous: a send() on one side invokes the peer's
// onMessage handler before returning. This is intentional — it makes
// dispatcher tests fully deterministic without timers or microtasks.
// The receiver gets a copy of the bytes, so the sender can mutate or
// zeroize its source buffer after send() returns.

export const createTransportPair = () => {

    const sides = [makeSide(), makeSide()];
    sides[0]._peer = sides[1];
    sides[1]._peer = sides[0];
    return sides;

};

const makeSide = () => {

    const state = {
        _peer: null,
        _onMessage: null,
        _onClose: null,
        _closed: false,
    };

    state.send = (bytes) => {

        if (state._closed) return;
        if (state._peer._closed) return;
        if (state._peer._onMessage) {

            state._peer._onMessage(new Uint8Array(bytes));

        }

    };

    state.onMessage = (handler) => { state._onMessage = handler; };
    state.onClose = (handler) => { state._onClose = handler; };

    state.close = () => {

        if (state._closed) return;
        state._closed = true;
        if (state._onClose) state._onClose();
        if (state._peer && !state._peer._closed) {

            state._peer._closed = true;
            if (state._peer._onClose) state._peer._onClose();

        }

    };

    return state;

};
