#include "cmd.h"

#include <stdio.h>

#include "ahoi_defs.h"
#include "com.h"
#include <zlog.h>
extern zlog_category_t *zc;

command_set_status ahoi_set_command(int fd, const uint8_t type, const uint8_t* payload, const size_t pl_len) {
    ahoi_packet_t cmd = {0};
    cmd.type = type;
    cmd.pl_size = pl_len;
    cmd.payload = payload;

    return send_ahoi_cmd(fd, &cmd, NULL, 0, NULL);
}

void set_ahoi_id(int fd, const uint8_t id) {
    if (ahoi_set_command(fd, AHOI_ID_CMD, &id, 1) != COMMAND_SET_OK) {
        zlog_warn(zc,"Warning: Id was not set\n");
    }
}

void set_ahoi_sniff_mode(int fd, const uint8_t mode) {
    if (ahoi_set_command(fd, AHOI_SNIFF_MODE_CMD, &mode, 1) != COMMAND_SET_OK) {
        zlog_warn(zc, "Warning: Sniff mode was not set\n");
    }
}