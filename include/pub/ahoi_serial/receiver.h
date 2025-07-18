#ifndef AHOI_SERIAL_RECEIVER_H
#define AHOI_SERIAL_RECEIVER_H

#include <stddef.h>

#include "core.h"

#define RECV_BUF_SIZE 512

typedef enum {
    PACKET_RECV_OK,
    PACKET_RECV_KO
} packet_rcv_status;

typedef enum {
    PACKET_DECODE_OK,
    PACKET_DECODE_KO
} packet_decode_status;

packet_rcv_status receive_ahoi_packet(int fd, void (*cb)(const ahoi_packet_t*));

packet_decode_status decode_ahoi_packet(const uint8_t *data, size_t len, ahoi_packet_t* ahoi_packet);

#endif // AHOI_SERIAL_RECEIVER_H
