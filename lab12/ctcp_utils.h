/******************************************************************************
 * ctcp_utils.h
 * ------------
 * Contains definitions for helper functions that you might find useful.
 * Implementations can be found in ctcp_utils.c.
 *
 *****************************************************************************/

#ifndef CTCP_UTILS_H
#define CTCP_UTILS_H

#include "ctcp_sys.h"

/**
 * Computes a checksum over the given data and returns the result in
 * NETWORK-byte order.
 *
 * _data: Data to compute checksum over.
 * len: Length of data.
 *
 * returns: The checksum in network-byte order.
 */
uint16_t cksum(const void *_data, uint16_t len);

/**
 * Gets the current time in milliseconds.
 */
long current_time();

/**
 * Prints out the headers of a cTCP segment. Expects the segment to come in
 * network-byte order. All fields are converted and printed out in host order,
 * except for the checksum.
 *
 * segment: The cTCP segment, in network-byte order.
 */
void print_hdr_ctcp(ctcp_segment_t *segment);

#endif /* CTCP_UTILS_H */
