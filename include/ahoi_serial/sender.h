#ifndef AHOI_SERIAL_SENDER_H
#define AHOI_SERIAL_SENDER_H

#include "core.h"

typedef enum {
    PACKET_SEND_OK,
    PACKET_SEND_KO
} packet_send_status;

packet_send_status send_ahoi_packet(int fd, const ahoi_packet_t* ahoi_packet);

#endif // AHOI_SERIAL_SENDER_H
