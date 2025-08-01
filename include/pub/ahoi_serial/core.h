#ifndef AHOI_SERIAL_CORE_H
#define AHOI_SERIAL_CORE_H

#include <stdint.h>
#include <stddef.h>

#define SECONDS_IN_HOUR 3600

// Solo R flag is not used
typedef enum {
    A_FLAG = 0x01,
    AR_FLAG = 0x03,
    E_FLAG = 0x04,
    AE_FLAGS = 0x05,
    ARE_FLAGS = 0x07,
} ahoi_packet_flags;

typedef struct {
    uint8_t src;
    uint8_t dst;
    uint8_t type;
    uint8_t flags;
    uint8_t seq;
    uint8_t pl_size;
    uint8_t* payload;
} ahoi_packet_t;

typedef enum {
    PACKET_DECODE_OK,
    PACKET_DECODE_KO
} packet_decode_status;

void store_key(const uint8_t* new_key);

uint8_t get_seq_number();

void increment_seq_number();

void print_packet(const ahoi_packet_t *ahoi_packet);

packet_decode_status decode_ahoi_packet(const uint8_t *data, size_t len, ahoi_packet_t* ahoi_packet);

#endif // AHOI_SERIAL_CORE_H
