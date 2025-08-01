#include "com.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <fcntl.h>
#include <termios.h>

#include "ahoi_defs.h"
#include "security.h"

#define AHOI_SERIAL_ACK_TIMEOUT_MS 100

static uint8_t send_buf[2 * MAX_PACKET_SIZE + 4];
static uint8_t payload_buf[MAX_PAYLOAD_SIZE] = {0};
static ahoi_packet_t ahoi_packet_internal = {
    .payload = payload_buf
};

/* Private functions */

size_t ahoi_serialize(const ahoi_packet_t* p, uint8_t* buf) {
    size_t packet_len = 0;

    // Framing: DLE-STX
    buf[packet_len++] = 0x10;
    buf[packet_len++] = 0x02;

    // Escape header
    const uint8_t* header = (const uint8_t*) p;
    for (int i = 0; i < HEADER_SIZE; i++) {
        if (header[i] == 0x10) {
            buf[packet_len++] = 0x10;
        }
        buf[packet_len++] = header[i];
    }

    // Escape payload
    for (int i = 0; i < p->pl_size; i++) {
        if (p->payload[i] == 0x10) {
            buf[packet_len++] = 0x10;
        }
        buf[packet_len++] = p->payload[i];
    }

    // Framing: DLE-ETX
    buf[packet_len++] = 0x10;
    buf[packet_len++] = 0x03;

    return packet_len;
}

/* Public functions */

int open_serial_port(const uint8_t *port, int baudrate) {
    int fd = open(port, O_RDWR | O_NOCTTY | O_NDELAY);
    if (fd == -1) {
        perror("Error opening serial port");
        return -1;
    }

    struct termios options;
    tcgetattr(fd, &options);

    cfsetispeed(&options, baudrate);
    cfsetospeed(&options, baudrate);
    options.c_cflag &= ~PARENB;
    options.c_cflag &= ~CSTOPB;
    options.c_cflag &= ~CSIZE;
    options.c_cflag |= CS8;
    options.c_cflag |= (CLOCAL | CREAD);
    options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    options.c_iflag &= ~(IXON | IXOFF | IXANY);
    options.c_oflag &= ~OPOST;

    tcsetattr(fd, TCSANOW, &options);
    return fd;
}

packet_send_status send_ahoi_cmd(int fd, const ahoi_packet_t* ahoi_packet, uint8_t* rsp_buf, const size_t buf_len, size_t* rsp_len) {
    if (!ahoi_packet || !ahoi_packet->payload) {
        fprintf(stderr, "Invalid packet or payload!\n");
        return PACKET_SEND_KO;
    }

    if (!is_command_packet(ahoi_packet)) {
        fprintf(stderr, "Expecting ahoi command packet\n");
        return PACKET_SEND_KO;
    }

    const size_t len = ahoi_serialize(ahoi_packet, send_buf);

    const ssize_t bytes_written = write(fd, send_buf, len);
    if (bytes_written < 0) {
        fprintf(stderr, "Error writing to serial port\n");
        return PACKET_SEND_KO;
    }
    if (bytes_written != len) {
        fprintf(stderr, "Warning: Partial write (%zd of %lu bytes)\n", bytes_written, len);
        return PACKET_SEND_KO;
    }

    if (receive_ahoi_packet_sync(fd, &ahoi_packet_internal, AHOI_SERIAL_ACK_TIMEOUT_MS) != PACKET_RCV_OK) {
        fprintf(stderr, "Error receiving send ack\n");
        return PACKET_SEND_KO;
    }

    if (is_serial_nack(&ahoi_packet_internal)) {
        fprintf(stderr, "Ahoi cmd is malformed\n");
        return PACKET_SEND_KO;
    }

    if (rsp_buf != NULL) {
        if (buf_len < ahoi_packet_internal.pl_size) {
            fprintf(stderr, "Response buffer is too small\n");
            return PACKET_SEND_KO;
        }
        memcpy(rsp_buf, ahoi_packet_internal.payload, ahoi_packet_internal.pl_size);
        *rsp_len = ahoi_packet_internal.pl_size;
    }
    return PACKET_SEND_OK;
}

packet_send_status send_ahoi_data(int fd, ahoi_packet_t* ahoi_packet) {
    if (!ahoi_packet || !ahoi_packet->payload) {
        fprintf(stderr, "Invalid packet or payload!\n");
        return PACKET_SEND_KO;
    }

    if (!is_data_packet(ahoi_packet)) {
        fprintf(stderr, "Expecting ahoi data packet\n");
        return PACKET_SEND_KO;
    }

    ahoi_packet->seq = get_seq_number();
    secure_ahoi_packet(ahoi_packet);

    // TODO: make a macro
    const size_t len = ahoi_serialize(ahoi_packet, send_buf);

    const ssize_t bytes_written = write(fd, send_buf, len);
    if (bytes_written < 0) {
        fprintf(stderr, "Error writing to serial port\n")   ;
        return PACKET_SEND_KO;
    }
    if (bytes_written != len) {
        fprintf(stderr, "Warning: Partial write (%zd of %lu bytes)\n", bytes_written, len);
        return PACKET_SEND_KO;
    }

    if (receive_ahoi_packet_sync(fd, &ahoi_packet_internal, AHOI_SERIAL_ACK_TIMEOUT_MS) != PACKET_RCV_OK) {
        fprintf(stderr, "Error receiving send ack\n");
        return PACKET_SEND_KO;
    }

    if (!is_serial_ack(&ahoi_packet_internal)) {
        fprintf(stderr, "Unexpected response from modem\n");
        return PACKET_SEND_KO;
    }

    increment_seq_number();
    return PACKET_SEND_OK;
}

packet_rcv_status receive_ahoi_packet_sync(const int fd, ahoi_packet_t* p, int timeout_ms) {
    static uint8_t recv_buf[RECV_BUF_SIZE] = {0};

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

                        const packet_decode_status status = decode_ahoi_packet(recv_buf, buf_pos, p);
                        if (status != PACKET_DECODE_OK) {
                            fprintf(stderr, "Packet decoding failed\n");
                            in_packet = 0;
                            return PACKET_RCV_KO;
                        }
                        in_packet = 0;
                        packet_received = 1;
                    } else if (byte == 0x10) {
                        recv_buf[buf_pos++] = 0x10;
                    } else {
                        // TODO: what if malformed packet
                    }
                }
            } else {
                recv_buf[buf_pos++] = byte;
            }
        }
    }
    return PACKET_RCV_OK;
}