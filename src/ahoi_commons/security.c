#include "security.h"
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <netinet/ip.h>

#include "ascon.h"
#include "common_defs.h"

static uint8_t key[KEY_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
static uint8_t ascon_buf[MAX_SECURE_PAYLOAD_SIZE] = {0};
static uint8_t nonce_buf[NONCE_SIZE] = {0};


void sec_store_key(const uint8_t* new_key) {
    memcpy(key, new_key, KEY_SIZE);
}

nonce_gen_status generate_nonce(const uint8_t seq, uint8_t* buf, const size_t nonce_size) {
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

secure_status secure_ahoi_packet(ahoi_packet_t* ahoi_packet) {
    static uint8_t tag_buf[TAG_SIZE] = {0};
    const uint8_t* header = (uint8_t*) ahoi_packet;
    const size_t pl_size = ahoi_packet->pl_size;


    if (!ahoi_packet || !ahoi_packet->payload) {
    fprintf(stderr, "Invalid packet or payload!\n"); // This part is to protect the Ascon function to payload NULL
    return SECURE_KO;
    }

    if (pl_size + TAG_SIZE > MAX_SECURE_PAYLOAD_SIZE) {
        fprintf(stderr, "There is not space in the buffer");
        return SECURE_KO;
    }

    memset(ascon_buf, 0, MAX_SECURE_PAYLOAD_SIZE); //start with zero

    if (generate_nonce(seq_number, nonce_buf, NONCE_SIZE) != NONCE_GEN_OK) {
        fprintf(stderr, "Nonce generation failed!\n");
        return SECURE_KO;
    }

    const int enc_result = ascon_aead_encrypt(
        tag_buf, ascon_buf,
        ahoi_packet->payload, pl_size,
        header, HEADER_SIZE,
        nonce_buf, key
    );

    if (enc_result != 0) {
        fprintf(stderr, "Packet encryption failed!\n");
        return SECURE_KO;
    }

    printf("\nKey: ");
    for (int i = 0; i < KEY_SIZE; i++) printf("%02X ", key[i]);
    
    printf("\n");
    printf("HEADER_SIZE = %d\n", HEADER_SIZE);
    printf("Nonce: ");
    for (int i = 0; i < NONCE_SIZE; i++) printf("%02X ", nonce_buf[i]);
    
    printf("\nHeader ptr: %p\n", (void*)header);    
    printf("Generated tag:\n");
    for (int i = 0; i < TAG_SIZE; i++) {
    printf("%02X ", tag_buf[i]);
    }
    printf("\n");
    printf("Plaintext payload (%zu bytes):\n",pl_size);
    for (int i = 0; i < pl_size ; i++) {
    printf("%02X ", ahoi_packet->payload[i]);
    }
    printf("\n");

    

    printf("ascon_buf after encryption:\n");
    for (int i = 0; i < pl_size + TAG_SIZE; i++) printf("%02X ", ascon_buf[i]);

    memcpy(ahoi_packet->payload, ascon_buf, pl_size);// Without this the encrypted result never reaches the packet.
    memcpy(ahoi_packet->payload + pl_size, tag_buf, TAG_SIZE); 
    ahoi_packet->pl_size = pl_size + TAG_SIZE;

    printf("ahoi_packet->payload after memcpy:\n");
    for (int i = 0; i < pl_size + TAG_SIZE; i++) printf("%02X ", ahoi_packet->payload[i]);
    printf("\n");

    printf("Header content during encryption:\n");
    for (int i = 0; i < HEADER_SIZE; i++) {
    printf("%02X ", header[i]);
    }
    printf("\n");

    return SECURE_OK;
}

verify_status verify_packet(ahoi_packet_t* ahoi_packet) {
    const size_t ciphertext_len = (ahoi_packet->pl_size) - TAG_SIZE;
    const uint8_t *tag = ahoi_packet->payload + ciphertext_len;

    if (generate_nonce(seq_number, nonce_buf, NONCE_SIZE) != NONCE_GEN_OK) {
        fprintf(stderr, "Nonce generation failed!\n");
        return VERIFY_KO;
    }
    if (ciphertext_len > MAX_SECURE_PAYLOAD_SIZE) {
        fprintf(stderr, "There is not space in the buffer");
        return SECURE_KO;
    }

    printf("\nKey: ");
    for (int i = 0; i < KEY_SIZE; i++) printf("%02X ", key[i]);
    printf("HEADER_SIZE = %d\n", HEADER_SIZE);
    printf("Nonce: ");
    for (int i = 0; i < NONCE_SIZE; i++) printf("%02X ", nonce_buf[i]);
    
    printf("\nHeader ptr: %p\n", (void*)ahoi_packet);
    printf("Tag used for decryption:\n");
    for (int i = 0; i < TAG_SIZE; i++) {
    printf("%02X ", tag[i]);
    }
    printf("\n");
    printf("ascon_buf before decryption:\n");
    for (int i = 0; i < ahoi_packet->pl_size; i++) printf("%02X ", ascon_buf[i]);
    printf("\n");
    printf("Payload before decryption:\n");
    for (int i = 0; i < ahoi_packet->pl_size; i++) {
    printf("%02X ", ahoi_packet->payload[i]);
    }
    printf("\n");
    printf("Header content during decryption:\n");
    for (int i = 0; i < HEADER_SIZE; i++) {
    printf("%02X ", ((uint8_t*)ahoi_packet)[i]);
    }
    printf("\n");

    const int dec_result = ascon_aead_decrypt(
        ascon_buf,
        tag, ahoi_packet->payload, ciphertext_len,
        (const uint8_t*) ahoi_packet, HEADER_SIZE,
        nonce_buf, key
    );

    if (dec_result != 0) {
        fprintf(stderr,"Decryption failed.\n");
        return VERIFY_KO;
    }

    memcpy(ahoi_packet->payload, ascon_buf, ciphertext_len);
    ahoi_packet->pl_size = ciphertext_len;
    return VERIFY_OK;
}