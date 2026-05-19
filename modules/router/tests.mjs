import {
    LENGTH_COORDINATION_KEY,
} from '../constants/index.mjs';

import RandomGenerator from '../random/index.mjs';
import AnonymityRouter from './index.mjs';

import { expect } from 'chai';

const TIMEOUT_TEST = 15000; // milliseconds
const TIMEOUT_NETWORK = 12000; // milliseconds

const PORT_ANLA_DEFAULT = 11412; // 'A' = 1, 'N' = 14, 'L' = 12

const PORT_ANY = 0;

const REMOTE_HOST = '::1';
const REMOTE_PORT = PORT_ANLA_DEFAULT;

describe('AnonymityRouter', () => {

    ////////////////////////////////////////////////////////////////////
    // The routers should strive towards a "everyone-sees-everyone"   //
    // kind of situation, as this prevents some few nodes growing in  //
    // excessive relevance and ruining the decentralization of the    //
    // network. However, this is not a behavior that is required of   //
    // all implementations (and the protocol accommodates for this).  //
    // Some routers may be more silent and only advertise themselves  //
    // for a select few. The following test dot not reflect all       //
    // possible implementations of this protocol.                     //
    ////////////////////////////////////////////////////////////////////

    it('should eventually become a complete, fully-connected graph', (done) => {

        // four routers are created and initially linked like this:
        // 1 -> 2 -> 3 -> 4 -> 1
        // This is not a complete, fully-connected graph. However,
        // as the nodes advertise themselves to each other, it should
        // become a "everyone-sees-everyone" graph, a complete graph.

        const LENGTH_REMOTE_SERVERS = 4;
        const MASK_MODULUS_FOUR = 0b11;

        const testData = Object.seal({
            serversListening: 0,
            completeGraph: false,
            testComplete: false,
        });

        const announceError = (error) => {

            if (!testData.testComplete) {

                done(error);
                testData.testComplete = true;

            }

        };

        RandomGenerator.seed(performance.now() | 0);
        const exponent = new Uint8Array(LENGTH_COORDINATION_KEY);

        const optionsRemoteServer = {
            exponent: exponent,
            coordination: {
                type: 'websocket',
                host: REMOTE_HOST,
                port: PORT_ANY,
            },
            transport: {
                type: 'websocket',
                host: REMOTE_HOST,
                port: PORT_ANY,
            },
        };

        const remoteServers = new Array(LENGTH_REMOTE_SERVERS);

        const linkServers = () => {

            let indexA = 0;
            while (indexA < LENGTH_REMOTE_SERVERS) {

                const indexB = (indexA + 1) & MASK_MODULUS_FOUR;

                const remoteServerA = remoteServers[indexA];
                const remoteServerB = remoteServers[indexB];

                const peerData = { ...remoteServerA.getPeerData(), self: false };
                remoteServerB.addPeer(peerData);

                indexA = (indexA + 1) | 0;

            }

        };

        let index = 0;
        while (index < LENGTH_REMOTE_SERVERS) {

            RandomGenerator.fill(exponent);

            const remoteServer = AnonymityRouter.createServer(optionsRemoteServer);
            remoteServers[index] = remoteServer;

            remoteServer.on('listening', () => {

                testData.serversListening = (testData.serversListening + 1) | 0;
                if (testData.serversListening === 4) {

                    linkServers();

                }

            });

            remoteServer.on('error', announceError);

            index = (index + 1) | 0;

        }

        let cleanupCallback;

        const checkCompleteGraph = () => {

            let index = 0;
            while (index < LENGTH_REMOTE_SERVERS) {

                const { peers } = remoteServers[index];
                if (peers.size < 4) {

                    testData.completeGraph = false;
                    return;

                }

                index = (index + 1) | 0;

            }

            testData.completeGraph = true;
            testData.testComplete = true;
            done();

            if (typeof cleanupCallback === 'function') {

                cleanupCallback();

            }

        };

        const intervalCheck = setInterval(checkCompleteGraph, 1000);

        const shutdownServers = () => {

            clearInterval(intervalCheck);

            let index = 0;
            while (index < LENGTH_REMOTE_SERVERS) {

                remoteServers[index].close();

                index = (index + 1) | 0;

            }

            if (testData.testComplete) {

                return;

            }

            const error = new Error('timeout without complete graph!');
            announceError(error);
            return;

        };

        setTimeout(shutdownServers, TIMEOUT_NETWORK);
        cleanupCallback = shutdownServers;

    }).timeout(TIMEOUT_TEST);

});

