import CoordinationPacketsFormatter from '../packets/coordination/format/index.mjs';
import CoordinationPacketsParser from '../packets/coordination/parse/index.mjs';
import ElGamalCryptography from '../cryptography/elgamal/index.mjs';
import RandomGenerator from '../random/index.mjs';
import TwofishCryptography from '../cryptography/twofish/index.mjs';

import { EventEmitter } from 'events';
import { WebSocketServer, WebSocket } from 'ws';

import {
    LENGTH_COORDINATION_HEADER,
    LENGTH_COORDINATION_KEY,
    LENGTH_KEY_SYMMETRIC,

    LIMIT_UINT32_MAX,

    MODULUS_PEER_IDENTIFICATION,

    OFFSET_COORDINATION_HEADER,
    OFFSET_COORDINATION_TYPE,
    OFFSET_FORWARD_IPV6_WEBSOCKET_PORT,
    OFFSET_FORWARD_IPV6_WEBSOCKET_HOST,
    OFFSET_KEY_DECRYPTION,
    OFFSET_LENGTH_REAL,

    TYPE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET,
    TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET,
} from '../constants/index.mjs';

import {
    EXTRACT_HOST_IPV6,
    EXTRACT_SUBARRAY,
    EXTRACT_UINT16,
    POLYNOMIAL_MODULUS_BUFFER,
} from '../utilities/index.mjs'

const DEFAULT_INTERVAL_ANNOUNCE_PEER = 750; // milliseconds
const DEFAULT_MAXIMUM_WEBSOCKET_CONNECTIONS = 8; // units
const DEFAULT_MAXIMUM_LENGTH_PACKET = 8192; // octets, also known as "bytes"

const OFFSET_KEY_SENDER = LENGTH_COORDINATION_HEADER;
const OFFSET_DATA_START = LENGTH_COORDINATION_HEADER + LENGTH_COORDINATION_KEY;

const VALID_EVENTS = new Set([
    'listening',
    'error',
]);

////////////////////////////////////////////////////////////////////////
// SENDERS                                                            //
////////////////////////////////////////////////////////////////////////

const SEND_ANNOUNCE_PEER = (socket, peerData) => {};

////////////////////////////////////////////////////////////////////////
// HANDLERS FOR EACH MESSAGE TYPE                                     //
////////////////////////////////////////////////////////////////////////

const HANDLE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET = (packet, addPeer) => {

    const text = CoordinationPacketsParser.parse(packet);
    const subarrayPublicKey = EXTRACT_SUBARRAY(
        packet,
        OFFSET_DATA_START,
        LENGTH_COORDINATION_KEY,
    );

    const publicKey = new Uint8Array(subarrayPublicKey);
    const { destination } = text;
    const { host, port } = destination;
    const family = 'IPv6';
    const peerData = { publicKey, family, port, host, self: false };
    addPeer(peerData);

};

const HANDLE_COORDINATION_FORWARD_IPV6_WEBSOCKET = (packet) => {

    const remoteHost = EXTRACT_HOST_IPV6(packet, OFFSET_FORWARD_IPV6_WEBSOCKET_HOST);
    const remotePort = EXTRACT_UINT16(packet, OFFSET_FORWARD_IPV6_WEBSOCKET_PORT);

    const forwardPacket = (remoteHost, remotePort, packet) => {

        const target = `ws://[${ remoteHost }]:${ remotePort }/`;

        const webSocket = new WebSocket(target, {
            perMessageDeflate: false
        });

        webSocket.on('error', (error) => {

            console.log(error);

        });

        webSocket.on('open', () => {

            webSocket.send(packet);

            setTimeout(() => {

                webSocket.close();

            }, 1000);

        });

    };

    const nextPacket = packet.subarray(OFFSET_DATA_START);
    forwardPacket(remoteHost, remotePort, nextPacket);

};

////////////////////////////////////////////////////////////////////////
// CREATORS FOR EACH ROUTER TYPE                                      //
////////////////////////////////////////////////////////////////////////

const CREATE_COORDINATION_SERVER_WEBSOCKET = (options, onPacket) => {

    const { coordination } = options;
    const { host, port } = coordination;

    const server = new WebSocketServer({ host, port });

    server.on('connection', (socket) => {

        socket.on('message', onPacket);

    });

    return server;

};

export const createServer = (options) => {

    RandomGenerator.seed(performance.now() | 0);

    let serverCoordination = null;
    let peerData = null;

    const peers = new Map();
    const sockets = new Map();

    const eventEmitter = new EventEmitter();

    const exponent = new Uint8Array(options.exponent);
    const publicKey = new Uint8Array(LENGTH_COORDINATION_KEY);
    ElGamalCryptography.calculateKey2048(exponent, publicKey);

    const addPeer = (peerData) => {

        const { publicKey } = peerData;
        const shortKey = POLYNOMIAL_MODULUS_BUFFER(
            publicKey,
            0,
            LENGTH_COORDINATION_KEY,
            MODULUS_PEER_IDENTIFICATION,
        );

        if (peers.has(shortKey)) {

            return;

        }

        peerData.countAnnounce = 0;

        peers.set(shortKey, peerData);

        if (!peerData.self && !sockets.has(shortKey)) {

            const { host: remoteHost, port: remotePort } = peerData;

            const target = `ws://[${ remoteHost }]:${ remotePort }/`;

            const webSocket = new WebSocket(target, {
                perMessageDeflate: false
            });

            webSocket.on('error', (error) => {

                // console.log(error);

            });

            webSocket.on('close', () => {

                peers.delete(shortKey);
                sockets.delete(shortKey);

            });

            sockets.set(shortKey, webSocket);

        }

    };

    const continuousAnnouncePeer = () => {

        let lowestCount = LIMIT_UINT32_MAX;
        let lowestShortKey = LIMIT_UINT32_MAX;
        let lowestPeerData = null;
        for (const [shortKey, peerData] of peers) {

            const { countAnnounce } = peerData;
            if (countAnnounce < lowestCount) {

                lowestCount = countAnnounce;
                lowestShortKey = shortKey;
                lowestPeerData = peerData;

            }

        }

        if (!lowestPeerData) {

            return;

        }

        lowestPeerData.countAnnounce = (lowestPeerData.countAnnounce + 1) | 0;

        const symmetricKey = new Uint8Array(LENGTH_KEY_SYMMETRIC);
        RandomGenerator.fill(symmetricKey);

        const lengthFullPacket
            = LENGTH_COORDINATION_HEADER
            + LENGTH_COORDINATION_KEY   // senderKey
            + LENGTH_COORDINATION_KEY   // publicKey
            ;

        const bufferFullPacket = new Uint8Array(lengthFullPacket);
        const templateFullPacket = new Uint8Array(lengthFullPacket);

        const bufferHeader = EXTRACT_SUBARRAY(
            bufferFullPacket,
            0,
            LENGTH_COORDINATION_HEADER,
        );

        const templateHeader = EXTRACT_SUBARRAY(
            templateFullPacket,
            0,
            LENGTH_COORDINATION_HEADER,
        );

        const textPacket = {
            type: TYPE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET,
            key: symmetricKey,
            lengthReal: 0x0100,
            lengthNext: 0x0000,
            destination: Object.freeze({
                host: lowestPeerData.host,
                port: lowestPeerData.port,
            }),
        };

        CoordinationPacketsFormatter.format(textPacket, templateFullPacket);

        templateFullPacket.set(lowestPeerData.publicKey, OFFSET_DATA_START);

        const packetCipher = templateFullPacket.subarray(OFFSET_DATA_START);
        TwofishCryptography.encrypt128Chain(
            symmetricKey,
            lowestPeerData.publicKey,
            packetCipher,
        );

        for (const [shortKey, socket] of sockets.entries()) {

            if (shortKey === lowestShortKey) {

                continue;

            }

            if (socket.readyState !== WebSocket.OPEN) {

                continue;

            }

            bufferFullPacket.set(templateFullPacket);

            const peerData = peers.get(shortKey);
            const { publicKey } = peerData;

            const bufferExponentSender = new Uint8Array(LENGTH_COORDINATION_KEY);
            RandomGenerator.fill(bufferExponentSender);

            const bufferKeySender = new Uint8Array(LENGTH_COORDINATION_KEY);
            ElGamalCryptography.calculateKey2048(
                bufferExponentSender,
                bufferKeySender,
            );

            ElGamalCryptography.encrypt2048(
                publicKey,
                bufferExponentSender,
                templateHeader,
                bufferHeader,
                bufferKeySender,
            );

            bufferFullPacket.set(bufferKeySender, OFFSET_KEY_SENDER);

            socket.send(bufferFullPacket);

        }

    };

    const intervalAnnounce = setInterval(
        continuousAnnouncePeer,
        DEFAULT_INTERVAL_ANNOUNCE_PEER,
    );

    const onPacket = (packet) => {

        const keySender = EXTRACT_SUBARRAY(packet, OFFSET_KEY_SENDER, LENGTH_COORDINATION_KEY);
        const textPlainA = new Uint8Array(LENGTH_COORDINATION_KEY);
        const textCipherA = packet.subarray(0, LENGTH_COORDINATION_HEADER);
        ElGamalCryptography.decrypt2048(
            exponent,
            keySender,
            textCipherA,
            textPlainA,
        );

        packet.set(textPlainA, OFFSET_COORDINATION_HEADER);

        const key = EXTRACT_SUBARRAY(packet, OFFSET_KEY_DECRYPTION, LENGTH_KEY_SYMMETRIC);
        const textCipherB = packet.subarray(OFFSET_DATA_START);
        const textPlainB = new Uint8Array(textCipherB.length);
        TwofishCryptography.decrypt128Chain(key, textCipherB, textPlainB);

        packet.set(textPlainB, OFFSET_DATA_START);

        const type = packet[OFFSET_COORDINATION_TYPE];
        switch (type) {

            case TYPE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET: {

                return HANDLE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET(packet, addPeer);

            }

            case TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET: {

                return HANDLE_COORDINATION_FORWARD_IPV6_WEBSOCKET(packet);

            }

        }

    };

    const { coordination } = options;
    const { type: coordinationType } = coordination;

    switch (coordinationType) {

        case 'websocket': {

            serverCoordination = CREATE_COORDINATION_SERVER_WEBSOCKET(options, onPacket);
            break;

        }

    }

    serverCoordination.on('listening', () => {

        const { port, address: host, family } = serverCoordination.address();

        peerData = { publicKey, family, port, host, self: true };
        addPeer(peerData);

        eventEmitter.emit('listening');

    });

    serverCoordination.on('error', (error) => {

        eventEmitter.emit('error', error);

    });

    const address = () => {

        return serverCoordination.address();

    };

    const close = () => {

        for (const socket of sockets.values()) {

            socket.close();

        }

        serverCoordination.close();

        clearInterval(intervalAnnounce);

    };

    const getPeerData = () => {

        return peerData;

    };

    const on = (eventName, listener) => {

        if (!VALID_EVENTS.has(eventName)) {

            return;

        }

        eventEmitter.on(eventName, listener);

    };

    const router = Object.freeze({
        addPeer,
        address,
        close,
        on,
        getPeerData,
        peers,
    });

    return router;

};

const AnonymityRouter = Object.freeze({
    createServer,
});

export default AnonymityRouter;
