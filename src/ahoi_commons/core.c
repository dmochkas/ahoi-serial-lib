#include "core.h"

#include <stdio.h>
#include <fcntl.h>
#include <termios.h>

#include "security.h"

uint8_t seq_number = 0;

void store_key(const uint8_t* new_key) {
    sec_store_key(new_key);
}

void increment_seq_number() {
    seq_number = (seq_number +1) % 256;
}

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

void print_packet(const ahoi_packet_t *ahoi_packet) {
    if (ahoi_packet == NULL) {
        printf("ahoi_packet is NULL\n");
        return;
    }

    printf("Ahoi Packet:\n");
    printf("  Source:      %u\n", ahoi_packet->src);
    printf("  Destination: %u\n", ahoi_packet->dst);
    printf("  Type:        %u\n", ahoi_packet->type);
    printf("  Flags:       %u\n", ahoi_packet->flags);
    printf("  Sequence:    %u\n", ahoi_packet->seq);
    printf("  PL Size:     %u\n", ahoi_packet->pl_size);

    if (ahoi_packet->pl_size > 0 && ahoi_packet->payload != NULL) {
        printf("  Payload:     ");
        for (int i = 0; i < ahoi_packet->pl_size; i++) {
            printf("%02x ", ahoi_packet->payload[i]);
        }
        printf("\n");
    }
}