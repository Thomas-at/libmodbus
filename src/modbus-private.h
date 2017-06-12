/*
 * Copyright © 2010-2012 Stéphane Raimbault <stephane.raimbault@gmail.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#ifndef MODBUS_PRIVATE_H
#define MODBUS_PRIVATE_H

#ifndef _MSC_VER
# include <stdint.h>
# include <sys/time.h>
#else
# include "stdint.h"
# include <time.h>
typedef int ssize_t;
#endif
#include <sys/types.h>
#include <config.h>

#include "modbus.h"

MODBUS_BEGIN_DECLS

/* It's not really the minimal length (the real one is report slave ID
 * in RTU (4 bytes)) but it's a convenient size to use in RTU or TCP
 * communications to read many values or write a single one.
 * Maximum between :
 * - HEADER_LENGTH_TCP (7) + function (1) + address (2) + number (2)
 * - HEADER_LENGTH_RTU (1) + function (1) + address (2) + number (2) + CRC (2)
 */
#define _MIN_REQ_LENGTH 12

#define _REPORT_SLAVE_ID 180

#define _MODBUS_EXCEPTION_RSP_LENGTH 5

/* Timeouts in microsecond (0.5 s) */
#define _RESPONSE_TIMEOUT    500000
#define _BYTE_TIMEOUT        500000

/* state machine for asynchronous operation */
typedef enum {
	ASYNC_STATE_DISCONNECTED=0,
	ASYNC_STATE_CONNECTING,
	ASYNC_STATE_CONNECTED,
	ASYNC_STATE_LISTENING,
	ASYNC_STATE_SENDING_REQUEST,
	ASYNC_STATE_RECEIVING_INDICATION,
	ASYNC_STATE_SENDING_RESPONSE,
	ASYNC_STATE_RECEIVING_CONFIRMATION
} modbus_async_state_t;

typedef enum {
	ASYNC_READ,
	ASYNC_WRITE
} modbus_async_rw_t;

typedef enum {
    _MODBUS_BACKEND_TYPE_RTU=0,
    _MODBUS_BACKEND_TYPE_TCP
} modbus_backend_type_t;

/*
 *  ---------- Request     Indication ----------
 *  | Client | ---------------------->| Server |
 *  ---------- Confirmation  Response ----------
 */
typedef enum {
    /* Request message on the server side */
    MSG_INDICATION,
    /* Request message on the client side */
    MSG_CONFIRMATION
} msg_type_t;

/* This structure reduces the number of params in functions and so
 * optimizes the speed of execution (~ 37%). */
typedef struct _sft {
    int slave;
    int function;
    int t_id;
} sft_t;

/* Max between RTU and TCP max adu length (so TCP) */
#define MAX_MESSAGE_LENGTH 260

/* 3 steps are used to parse the query */
typedef enum {
    _STEP_FUNCTION,
    _STEP_META,
    _STEP_DATA
} _step_t;

typedef struct _modbus_backend {
    unsigned int backend_type;
    unsigned int header_length;
    unsigned int checksum_length;
    unsigned int max_adu_length;
    int (*set_slave) (modbus_t *ctx, int slave);
    int (*build_request_basis) (modbus_t *ctx, int function, int addr,
                                int nb, uint8_t *req);
    int (*build_response_basis) (sft_t *sft, uint8_t *rsp);
    int (*prepare_response_tid) (const uint8_t *req, int *req_length);
    int (*send_msg_pre) (uint8_t *req, int req_length);
    ssize_t (*send) (modbus_t *ctx, const uint8_t *req, int req_length);
    int (*receive) (modbus_t *ctx, uint8_t *req);
    ssize_t (*recv) (modbus_t *ctx, uint8_t *rsp, int rsp_length);
    int (*check_integrity) (modbus_t *ctx, uint8_t *msg,
                            const int msg_length);
    int (*pre_check_confirmation) (modbus_t *ctx, const uint8_t *req,
                                   const uint8_t *rsp, int rsp_length);
    int (*connect) (modbus_t *ctx);
    void (*close) (modbus_t *ctx);
    int (*flush) (modbus_t *ctx);
    int (*select) (modbus_t *ctx, fd_set *rset, struct timeval *tv, int msg_length);
    void (*free) (modbus_t *ctx);
    int (*connect_async) (modbus_t *ctx);
    ssize_t (*send_async) (modbus_t *ctx, const uint8_t *req, int req_length);
    int (*start_receive_msg_async) (modbus_t *ctx);
    int (*stop_receive_msg_async) (modbus_t *ctx);
    int (*listen_async) (modbus_t *ctx, int nb_connection);
    int (*selected) (modbus_t *ctx, int fd, int flag);
    void (*select_timeout) (modbus_t *ctx, int fd);
} modbus_backend_t;

struct _modbus {
    /* Slave address */
    int slave;
    /* Socket or file descriptor */
    int s;
    int debug;
    int error_recovery;
    struct timeval response_timeout;
    struct timeval byte_timeout;
    const modbus_backend_t *backend;
    void *backend_data;
    /* data for async operation */
    /* request length */
    int req_length;
    /* request data */
    uint8_t req[MAX_MESSAGE_LENGTH];
    /* response data */
    uint8_t rsp[MAX_MESSAGE_LENGTH];
    /* length of data remaining to be sent after select() write ready */
    int send_length;
    /* pointer to data to be sent */
    const uint8_t *send_ptr;
    /* length counter for reception, used per step */
    int length_to_read;
    /* total length of data received */
    int msg_length;
    /* message type to receive */
    msg_type_t msg_type;
    /* step of reception */
    _step_t step;
    /* pointer to data to be received */
    uint8_t *recv_ptr;
    /* pointer to decoded data */
    uint16_t *dest;
    /* listen() socket for server connections */
    int listen_s;
    /* state */
    modbus_async_state_t async_state;
    modbus_async_rw_t async_rw;
    /* pointers to callback functions */
    connected_cb_t connected_cb;
    read_cb_t read_cb;
    write_cb_t write_cb;
    indication_cb_t indication_cb;
    indication_complete_cb_t indication_complete_cb;
    add_watch_cb_t add_watch_cb;
    remove_watch_cb_t remove_watch_cb;
};

void _modbus_init_common(modbus_t *ctx);
void _error_print(modbus_t *ctx, const char *context);
int _modbus_receive_msg(modbus_t *ctx, uint8_t *msg, msg_type_t msg_type);

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dest, const char *src, size_t dest_size);
#endif

MODBUS_END_DECLS

#endif  /* MODBUS_PRIVATE_H */
