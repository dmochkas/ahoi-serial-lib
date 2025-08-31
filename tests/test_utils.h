#pragma once

#include <stddef.h>
#include <stdint.h>

#include "core.h"

size_t ahoi_serialize(const ahoi_packet_t* p, uint8_t* buf);

size_t ahoi_serialize_rx(ahoi_packet_t* p, ahoi_footer_t* f, uint8_t* buf);

void ahoi_packets_assert_equal(ahoi_packet_t* p1, ahoi_packet_t* p2);

void fill_serial_ack(int fd);

void fill_serial_nack(int fd);

void fill_cmd_resp(int fd, const ahoi_packet_t* set_cmd);

void fill_ack_resp(int fd, const ahoi_packet_t* data);

void fill_rack_resp(int fd, const ahoi_packet_t* data);