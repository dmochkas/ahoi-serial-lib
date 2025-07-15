#include "sender.h"

#include <stdio.h>
#include <unistd.h>

#include "common_defs.h"
#include "core.h"

packet_send_status send_ahoi_packet(int fd, const ahoi_packet_t* ahoi_packet) {
    const uint8_t* abstract_packet = (const uint8_t*) ahoi_packet;
    uint8_t escaped_packet[512];
    int packet_len = 0;

    // Framing: DLE-STX
    escaped_packet[packet_len++] = 0x10;
    escaped_packet[packet_len++] = 0x02;

    // Escape
    for (int i = 0; i < HEADER_SIZE + ahoi_packet->pl_size; i++) {
        if (abstract_packet[i] == 0x10) {
            escaped_packet[packet_len++] = 0x10;
        }
        escaped_packet[packet_len++] = abstract_packet[i];
    }

    // Framing: DLE-ETX
    escaped_packet[packet_len++] = 0x10;
    escaped_packet[packet_len++] = 0x03;

    const ssize_t bytes_written = write(fd, escaped_packet, packet_len);

    if (bytes_written < 0) {
        fprintf(stderr, "Error writing to serial port");
        return PACKET_SEND_KO;
    }

    if (bytes_written != packet_len) {
        fprintf(stderr, "Warning: Partial write (%zd of %d bytes)\n", bytes_written, packet_len);
        return PACKET_SEND_KO;
    }

    // printf("Sent escaped_packet (%d bytes): ", packet_len);
    // for (int i = 0; i < packet_len; i++) printf("%02X ", escaped_packet[i]);
    // printf("\n");

    increment_seq_number();
    return PACKET_SEND_OK;
}