#ifndef AHOI_LIB_CMD_H
#define AHOI_LIB_CMD_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    COMMAND_SET_OK,
    COMMAND_SET_KO
} command_set_status;

command_set_status ahoi_set_command(int fd, uint8_t type, const uint8_t* payload, size_t pl_len);

void set_ahoi_id(int fd, uint8_t id);

void set_ahoi_sniff_mode(int fd, uint8_t mode);

#endif //AHOI_LIB_CMD_H
