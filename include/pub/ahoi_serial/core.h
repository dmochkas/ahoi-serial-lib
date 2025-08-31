#ifndef AHOI_SERIAL_CORE_H
#define AHOI_SERIAL_CORE_H

#include <stdint.h>
#include <stddef.h>

#define SECONDS_IN_HOUR 3600

// A and R flags are incompatible
typedef enum {
    A_FLAG = 0x01,
    R_FLAG = 0x02,
    E_FLAG = 0x04,
    AE_FLAGS = 0x05,
    RE_FLAGS = 0x06,
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

typedef struct {
    uint8_t power;
    uint8_t rssi;
    uint8_t biterrors;
    uint8_t agcMean;
    uint8_t agcMin;
    uint8_t agcMax;
} ahoi_footer_t;

typedef enum {
    PACKET_DECODE_OK,
    PACKET_DECODE_KO
} packet_decode_status;

#if SECURE_MODE == 1
void store_key(const uint8_t* new_key);
#endif

uint8_t get_seq_number();

void increment_seq_number();

void print_packet(const ahoi_packet_t *ahoi_packet);

packet_decode_status decode_ahoi_packet(const uint8_t *data, const size_t len, ahoi_packet_t* ahoi_packet, ahoi_footer_t* ahoi_footer);

#endif // AHOI_SERIAL_CORE_H
