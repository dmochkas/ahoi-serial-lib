#ifndef AHOI_SERIAL_CORE_H
#define AHOI_SERIAL_CORE_H

#include <stdint.h>

#define SECONDS_IN_HOUR 3600

#define AHOI_ACK_TYPE 0x7F

extern uint8_t seq_number;

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

void store_key(const uint8_t* new_key);

void increment_seq_number();

int open_serial_port(const uint8_t *port, int baudrate);

void print_packet(const ahoi_packet_t *ahoi_packet);

#endif // AHOI_SERIAL_CORE_H
