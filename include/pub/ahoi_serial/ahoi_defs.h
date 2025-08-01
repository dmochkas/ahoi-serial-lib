#ifndef AHOI_SERIAL_COMMON_DEFS_H
#define AHOI_SERIAL_COMMON_DEFS_H

#define AHOI_ACK_TYPE 0x7F
#define AHOI_ID_CMD 0x84
#define AHOI_SNIFF_MODE_CMD 0xA1

#define is_data_packet(pkt) ((pkt)->type < 0x7F)
#define is_ack(pkt) ((pkt)->type == 0x7F)
#define is_command_packet(pkt) ((pkt)->type >= 0x80 && pkt->type <= 0xFD)
#define is_serial_ack(pkt) ((pkt)->type >= 0xFF)
#define is_serial_nack(pkt) ((pkt)->type >= 0xFE)

#define KEY_SIZE 16
#define NONCE_SIZE 16
#define TAG_SIZE 16
#define HEADER_SIZE 6
#define MAX_PAYLOAD_SIZE 256
#define MAX_SECURE_PAYLOAD_SIZE (256 - TAG_SIZE)
#define MAX_PACKET_SIZE (HEADER_SIZE + MAX_PAYLOAD_SIZE)

#endif