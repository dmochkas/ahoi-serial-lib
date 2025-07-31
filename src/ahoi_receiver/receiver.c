#include "receiver.h"

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>

#include "common_defs.h"
#include "security.h"

packet_rcv_status receive_ahoi_packet(const int fd, void (*cb)(const ahoi_packet_t*), void (*ack_cb)(const ahoi_packet_t*), int timeout_ms) {
    static uint8_t recv_buf[RECV_BUF_SIZE] = {0};
    static uint8_t payload_buf[MAX_PAYLOAD_SIZE] = {0};
    static ahoi_packet_t staging_packet = {
        .payload = payload_buf
    };

    int buf_pos = 0;
    int in_packet = 0;
    struct pollfd pfd;
    int retval;
    int packet_received = 0;

    pfd.fd = fd;
    pfd.events = POLLIN;

    while (!packet_received) {
        retval = poll(&pfd, 1, timeout_ms);
        if (retval == -1) {
            fprintf(stderr,"Poll error\n");
            return PACKET_RCV_KO;
        }
        if (retval == 0) {
            return PACKET_RCV_TIMEOUT;
        }
        if (!(pfd.revents & POLLIN)) {
            continue;
        }
        uint8_t byte;
        if (read(fd, &byte, 1) != 1) continue;

        if (!in_packet && byte == 0x10) {
            if (read(fd, &byte, 1) == 1 && byte == 0x02) {
                in_packet = 1;
                buf_pos = 0;
            }
        } else if (in_packet) {
            if (byte == 0x10) {
                if (read(fd, &byte, 1) == 1) {
                    if (byte == 0x03) {

                        if (buf_pos == 0 || buf_pos > RECV_BUF_SIZE) {
                            fprintf(stderr, "Invalid packet size\n");
                            in_packet = 0;
                            return PACKET_RCV_KO;
                        }

                        packet_decode_status status = decode_ahoi_packet(recv_buf, buf_pos, &staging_packet);
                        if (status != PACKET_DECODE_OK) {
                            fprintf(stderr, "Packet decoding failed\n");
                            in_packet = 0;
                            return PACKET_RCV_KO;
                        }

                        if (staging_packet.type == AHOI_ACK_TYPE && ack_cb != NULL) {
                            ack_cb(&staging_packet);
                        } else if (cb != NULL) {
                            cb(&staging_packet);
                        }
                        in_packet = 0;
                        packet_received = 1;
                    } else if (byte == 0x10) {

                        if (buf_pos >= RECV_BUF_SIZE) {
                            fprintf(stderr, "Buffer overflow\n");
                            in_packet = 0;
                            return PACKET_RCV_KO;
                        }
                        recv_buf[buf_pos++] = 0x10;
                    }
                }
            } else {
                if (buf_pos >= RECV_BUF_SIZE) {
                    fprintf(stderr, "Buffer overflow\n");
                    in_packet = 0;
                    return PACKET_RCV_KO;
                }
                recv_buf[buf_pos++] = byte;
            }
        }
    }
    return PACKET_RCV_OK;
}

packet_decode_status decode_ahoi_packet(const uint8_t *data, const size_t len, ahoi_packet_t* ahoi_packet) {
    if (len < HEADER_SIZE) {
        fprintf(stderr,"Packet too short\n");
        return PACKET_DECODE_KO;
    }

    memcpy(ahoi_packet, data, HEADER_SIZE);
    memcpy(ahoi_packet->payload, data + HEADER_SIZE, ahoi_packet->pl_size);
    const uint8_t ciphertext_len = ahoi_packet->pl_size - TAG_SIZE;

    if (HEADER_SIZE + ahoi_packet->pl_size > len) {
        fprintf(stderr,"Invalid lengths: total=%d, cipher=%d, tag=%d, received=%ld\n",
              ahoi_packet->pl_size, ciphertext_len, TAG_SIZE, len);
        return PACKET_DECODE_KO;
    }

    // printf("=== DEBUG ===\n");
    // printf("Nonce: ");
    // for(int i=0; i<NONCE_SIZE; i++) printf("%02X", nonce_buf[i]);
    // printf("\nAD Header: ");
    // for(int i=0; i<HEADER_SIZE; i++) printf("%02X", header[i]);
    // printf("\nCiphertext (%d): ", ciphertext_len);
    // for(int i=0; i<ciphertext_len; i++) printf("%02X", ciphertext[i]);
    // printf("\nTag: ");
    // for(int i=0; i<TAG_SIZE; i++) printf("%02X", tag[i]);
    // printf("\n=============\n");

    if (verify_packet(ahoi_packet) != VERIFY_OK) {
        fprintf(stderr,"Error validating packet\n");
        return PACKET_DECODE_KO;
    }

    seq_number = ahoi_packet->seq;
    return PACKET_DECODE_OK;
}