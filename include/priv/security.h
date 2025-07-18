#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>
#include <stddef.h>

#include "core.h"

typedef enum {
    NONCE_GEN_OK,
    NONCE_GEN_KO
} nonce_gen_status;

typedef enum {
    SECURE_OK,
    SECURE_KO
} secure_status;

typedef enum {
    VERIFY_OK,
    VERIFY_KO
} verify_status;

void sec_store_key(const uint8_t* new_key);

nonce_gen_status generate_nonce(uint8_t seq, uint8_t* buf, size_t nonce_size);

// Adds tag, applies encryption to payload
secure_status secure_ahoi_packet(ahoi_packet_t* ahoi_packet);

verify_status verify_packet(ahoi_packet_t* ahoi_packet);

#endif // SECURITY_H
