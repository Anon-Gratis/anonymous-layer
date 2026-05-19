////////////////////////////////////////////////////////////////////////
// FLAGS                                                              //
////////////////////////////////////////////////////////////////////////

export const FLAG_CLIENT_IPV4_WEBSOCKET                         = 1 <<  0;
export const FLAG_CLIENT_IPV4_UDP                               = 1 <<  1;
export const FLAG_CLIENT_IPV6_WEBSOCKET                         = 1 <<  2;
export const FLAG_CLIENT_IPV6_UDP                               = 1 <<  3;
export const FLAG_SERVER_IPV4_WEBSOCKET                         = 1 <<  4;
export const FLAG_SERVER_IPV4_UDP                               = 1 <<  5;
export const FLAG_SERVER_IPV6_WEBSOCKET                         = 1 <<  6;
export const FLAG_SERVER_IPV6_UDP                               = 1 <<  7;

////////////////////////////////////////////////////////////////////////
// LENGHTS - all measured in bit octets, also known as "bytes"        //
////////////////////////////////////////////////////////////////////////

export const LENGTH_COORDINATION_HEADER                         = 256;
export const LENGTH_COORDINATION_KEY                            = 256;
export const LENGTH_HOST_IPV6                                   = 16;
export const LENGTH_KEY_DECRYPTION                              = 16;
export const LENGTH_KEY_ENCRYPTION                              = 16;
export const LENGTH_KEY_SYMMETRIC                               = 16;
export const LENGTH_SESSION_TOKEN                               = 8;
export const LENGTH_SHARED_REMAINDER                            = 8;
export const LENGTH_SHARED_SECRET                               = 16;

////////////////////////////////////////////////////////////////////////
// LIMITS                                                             //
////////////////////////////////////////////////////////////////////////

export const LIMIT_UINT32_MAX
    = (~0) >>> 0;

////////////////////////////////////////////////////////////////////////
// MODULUS                                                            //
////////////////////////////////////////////////////////////////////////

// polynomial modulus for packet checksum
// expression: x^17 + x^3 + 1
// binary: 0b10000000000001001
export const MODULUS_PACKET_CHECKSUM
    = 0b10000000000001001;

// expression: x^23 + x^5 + 1
// binary: 0b100000000000000000100001
export const MODULUS_PEER_IDENTIFICATION
    = 0b100000000000000000100001;

// expression: x⁶64 + x^38 + x^18 + x^10 + 1
// binary: 0b10000000000000000000000000100000000000000000001000000010000000001
export const MODULUS_SHARED_SECRET = Object.freeze([
    0b00000001,
    0b00000000,
    0b00000000,
    0b00000000,
    0b01000000,
    0b00000000,
    0b00000100,
    0b00000100,
    0b00000001,
]);

////////////////////////////////////////////////////////////////////////
// OFFSETS                                                            //
////////////////////////////////////////////////////////////////////////

// offsets that are common for coordination packets of any type
// offset #0 is where the checksum is stored
// offset #2 is where the octets that are the dividend begin
// offset #236 is where the real length (header not included) is stored
// offset #238 is where the next length (header not included) is stored
// offset #240 is where the decryption key is stored

export const OFFSET_CHECKSUM                                    = 0;
export const OFFSET_POLYNOMIAL                                  = 2;
export const OFFSET_COORDINATION_TYPE                           = 2;
export const OFFSET_REPLY_TYPE                                  = 3;
export const OFFSET_SHIFT_TIME_IDLE                             = 4;
export const OFFSET_SHIFT_TIME_TOTAL                            = 5;
export const OFFSET_SHIFT_DATA_AVERAGE                          = 6;
export const OFFSET_SHIFT_DATA_TOTAL                            = 7;
export const OFFSET_FLAGS_32BITS                                = 8;
export const OFFSET_SESSION_TOKEN                               = 224;
export const OFFSET_LENGTH_REAL                                 = 236;
export const OFFSET_LENGTH_NEXT                                 = 238;
export const OFFSET_KEY_DECRYPTION                              = 240;

export const OFFSET_SHARED_SECRET_DECRYPTION                    = 48;
export const OFFSET_SHARED_SECRET_ENCRYPTION                    = 64;
export const OFFSET_REMAINDER_DECRYPTION                        = 80;
export const OFFSET_REMAINDER_ENCRYPTION                        = 88;
export const OFFSET_KEY_COLOR_CHANGE                            = 96;

export const OFFSET_COORDINATION_HEADER                         = 0;
export const OFFSET_COORDINAITION_KEY_SENDER                    = 256;

// offsets for addresses

export const OFFSET_ADDRESS_REPLY_IPV4_PORT                     = 14;
export const OFFSET_ADDRESS_REPLY_IPV4_HOST                     = 16;
export const OFFSET_ADDRESS_REPLY_IPV6_PORT                     = 14;
export const OFFSET_ADDRESS_REPLY_IPV6_HOST                     = 32;

export const OFFSET_ADDRESS_TARGET_IPV4_PORT                    = 12;
export const OFFSET_ADDRESS_TARGET_IPV4_HOST                    = 16;
export const OFFSET_ADDRESS_TARGET_IPV6_PORT                    = 12;
export const OFFSET_ADDRESS_TARGET_IPV6_HOST                    = 16;

export const OFFSET_ADDRESS_TYPE                                = 3;

////////////////////////////////////////////////////////////////////////
// TYPES                                                              //
////////////////////////////////////////////////////////////////////////

// all defined types for coordination packets
export const TYPE_COORDINATION_FORWARD                          = 0;
export const TYPE_COORDINATION_ANNOUNCE_PEER                    = 1;
export const TYPE_COORDINATION_REDIRECT_STATIC                  = 2;

export const TYPE_COORDINATION_FASTER_LINK_PLEAD                = 16;
export const TYPE_COORDINATION_FASTER_LINK_GRANT                = 17;
export const TYPE_COORDINATION_FASTER_LINK_TRADE                = 18;
export const TYPE_COORDINATION_FASTER_LINK_CHECK                = 19;

export const TYPE_ADDRESS_IPV4_WEBSOCKET                        = 0;
export const TYPE_ADDRESS_IPV4_UDP                              = 1;
export const TYPE_ADDRESS_IPV6_WEBSOCKET                        = 2;
export const TYPE_ADDRESS_IPV6_UDP                              = 3;
