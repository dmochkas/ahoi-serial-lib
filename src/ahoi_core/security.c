#include "security.h"

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <netinet/ip.h>

#include "ascon.h"
#include "ahoi_defs.h"
#include <zlog.h>
extern zlog_category_t *zc;

static uint8_t key[KEY_SIZE] = {0};
static uint8_t ascon_buf[MAX_SECURE_PAYLOAD_SIZE] = {0};
static uint8_t nonce_buf[NONCE_SIZE] = {0};


void sec_store_key(const uint8_t *new_key) {
    memcpy(key, new_key, KEY_SIZE);
}

nonce_gen_status generate_nonce(const uint8_t seq, uint8_t *buf, const size_t nonce_size) {
    if (nonce_size < sizeof(time_t) + sizeof(uint8_t)) {
        return NONCE_GEN_KO;
    }

    memset(buf, 0, nonce_size);

    const time_t now = time(NULL);
    const time_t hour_timestamp = htonl(now / SECONDS_IN_HOUR);

    memcpy(buf, &hour_timestamp, sizeof(hour_timestamp));
    memcpy(buf + sizeof(hour_timestamp), &seq, sizeof(seq));

    return NONCE_GEN_OK;
}

secure_status secure_ahoi_packet(ahoi_packet_t *ahoi_packet) {
    static uint8_t tag_buf[TAG_SIZE] = {0};
    const uint8_t *header = (uint8_t *) ahoi_packet;
    const size_t pl_size = ahoi_packet->pl_size;

    // NULL check
    if (!ahoi_packet || !ahoi_packet->payload) {
        zlog_error(zc, "Invalid packet or payload!\n");
        return SECURE_KO;
    }

    if (pl_size + TAG_SIZE > MAX_SECURE_PAYLOAD_SIZE) {
        zlog_error(zc, "There is not space in the buffer");
        return SECURE_KO;
    }

    if (generate_nonce(ahoi_packet->seq, nonce_buf, NONCE_SIZE) != NONCE_GEN_OK) {
        zlog_error(zc, "Nonce generation failed!\n");
        return SECURE_KO;
    }

    ahoi_packet->pl_size = pl_size + TAG_SIZE;

    const int enc_result = ascon_aead_encrypt(
        tag_buf, ascon_buf,
        ahoi_packet->payload, pl_size,
        header, HEADER_SIZE,
        nonce_buf, key
    );

    if (enc_result != 0) {
        zlog_error(zc, "Packet encryption failed!\n");
        return SECURE_KO;
    }

    memcpy(ahoi_packet->payload, ascon_buf, pl_size);
    memcpy(ahoi_packet->payload + pl_size, tag_buf, TAG_SIZE);

    return SECURE_OK;
}

verify_status verify_packet(ahoi_packet_t *ahoi_packet) {
    const size_t ciphertext_len = (ahoi_packet->pl_size) - TAG_SIZE;
    const uint8_t *tag = ahoi_packet->payload + ciphertext_len;

    if (generate_nonce(ahoi_packet->seq, nonce_buf, NONCE_SIZE) != NONCE_GEN_OK) {
        zlog_error(zc, "Nonce generation failed!\n");
        return VERIFY_KO;
    }
    if (ciphertext_len > MAX_SECURE_PAYLOAD_SIZE) {
        zlog_error(zc, "There is not space in the buffer");
        return VERIFY_KO;
    }

    const int dec_result = ascon_aead_decrypt(
        ascon_buf,
        tag, ahoi_packet->payload, ciphertext_len,
        (const uint8_t *) ahoi_packet, HEADER_SIZE,
        nonce_buf, key
    );

    if (dec_result != 0) {
        zlog_error(zc, "Decryption failed.\n");
        return VERIFY_KO;
    }

    memcpy(ahoi_packet->payload, ascon_buf, ciphertext_len);
    ahoi_packet->pl_size = ciphertext_len;
    return VERIFY_OK;
}
