#ifndef AHOI_SERIAL_CORE_H
#define AHOI_SERIAL_CORE_H

#include <stdint.h>

#define SECONDS_IN_HOUR 3600

extern uint8_t seq_number;

// A and R flags are incompatible
typedef enum {
    A_FLAG = 0x04,
    R_FLAG = 0x02,
    E_FLAG = 0x01,
    AE_FLAGS = 0x05,
    RE_FLAGS = 0x03,
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
    PACKET_GEN_OK,
    PACKET_GEN_KO
} packet_gen_status;

void store_key(const uint8_t* new_key);

void increment_seq_number();

int open_serial_port(const uint8_t *port, int baudrate);

void print_packet(const ahoi_packet_t *ahoi_packet);

#endif // AHOI_SERIAL_CORE_H
