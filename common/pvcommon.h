/*  Copyright 2014 Derek Chadwick

    This file is part of the pivotal Computer Forensics Timeline Tools.

    Pivotal is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Pivotal is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Pivotal.  If not, see <http://www.gnu.org/licenses/>.
*/


/*
   pvcommon.h

   Title : Pivotal Computer Forensics Utilities
   Author: Derek Chadwick
   Date  : 06/07/2014

   Purpose: Pivotal global definitions.

*/


/*
   Constant Definitions
*/

#ifndef PIVOTAL_COMMON_H
#define PIVOTAL_COMMON_H


#define DEBUG 1

#define SERVER_PORT_STRING "59888"

#define PV_PATH_MAX_LENGTH 4096 /* Redefine max path length since limits.h does weird things! FLTK defines this = 2048 */
#define PV_MAX_INPUT_STR 4096
#define PV_IP_ADDR_MAX 128
#define MAX_EVENT_DESC_SIZE 256
#define MAX_EVENT_ID_SIZE 8

#define PV_FILE_OUT  0x01
#define PV_GUI_OUT   0x02
#define PV_INDEX_IN  0x04
#define PV_CACHE_IN  0x08
#define PV_FILTER_ON 0x10

#define PV_FILE_ACCESS_TIME   0x01
#define PV_FILE_CREATION_TIME 0x02
#define PV_FILE_MODIFY_TIME   0x04

#define DATABASE_FILE_EXT ".txt"
#define EVENT_FILE_EXT ".fle"
#define PV_SEARCH_FILTER_LIST "pv-file-filter-list.txt"

#ifdef LINUX_BUILD
#define PATH_SEPARATOR "/"
#define CURRENT_DIR "./"
#define CONFIG_FILE "./pivotal-linux.conf"
#define LOG_FILE "./pivotal-linux.log"
#define DATABASE_FILE "./pivotal-event-linux"
#define BINARY_FILE "./pivotal"
#define MESSAGE_LOG_FILE "/var/log/messages"
#define SECURITY_LOG_FILE "/var/log/security"
#define EVENT_FILE "pivotal-events"
#define EVENT_LOG_PATH "./"
#else
#define PATH_SEPARATOR "\\"
#define CURRENT_DIR ".\\"
#define CONFIG_FILE ".\\pivotal.conf"
#define LOG_FILE ".\\pivotal.log"
#define DATABASE_FILE "pivotal-events"
#define EVENT_FILE "pivotal-events"

#endif /* LINUX_BUILD */

/*
   ENUMs
*/

enum op_modes { PV_DB_MODE = 1, PV_DB_MODE_X, PV_GUI_MODE, PV_GUI_MODE_X, PV_GUI_AND_DB_MODE, PV_GUI_AND_DB_MODE_X };
enum error_codes { SUCCESS, FILE_ERROR, INTEGRITY_ERROR, MALLOC_ERROR, SYSTEM_ERROR, UNKNOWN_ANOMALY };
enum log_modes { LOG_ERROR, LOG_WARNING, LOG_INFO };

/*
DATA STRUCTURES
*/

struct pv_project_header
{
   char *name;
   char *investigator;
   char *summary;
   char *start_date;
   char *end_date;
   char *description;
   int event_count;
};

typedef struct pv_project_header pv_project_header_t;


/* pvutil.c */

int fatal(char *str);
void *xcalloc (size_t size);
void *xmalloc (size_t size);
void *xrealloc (void *ptr, size_t size);
int xfree(char *buf, int len);
int print_help();
char* xitoa(int value, char* result, int len, int base);
int get_time_string(char *tstr, int slen);
int validate_ipv4_address(char *ipv4_addr);
int validate_ipv6_address(char *ipv6_addr);
char *ltrim(char *s);
char *rtrim(char *s);
char *trim(char *s);

/* pvsocket.c */

int init_socket(char *gui_ip_address);
int send_event(char *event_string);
char *get_response();
int close_socket();


/**
 * Unified2 Extra Data Header
 *
 */
typedef struct Unified2ExtraDataHdr_ {
    uint32_t event_type;
    uint32_t event_length;
} Unified2ExtraDataHdr;

/**
 * Unified2 Extra Data (currently used only for XFF)
 *
 */
typedef struct Unified2ExtraData_ {
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t type; /* EventInfo */
    uint32_t data_type; /*EventDataType */
    uint32_t blob_length; /* Length of the data + sizeof(blob_length) + sizeof(data_type)*/
} Unified2ExtraData;

/**
 * Unified2 file header struct
 *
 * Used for storing file header options.
 */
typedef struct Unified2AlertFileHeader_ {
    uint32_t type;      /**< unified2 type header */
    uint32_t length;    /**< unified2 struct size length */
} Unified2AlertFileHeader;

/**
 * Unified2 Ipv4 struct
 *
 * Used for storing ipv4 type values.
 */
typedef struct AlertIPv4Unified2_ {
    uint32_t sensor_id;             /**< sendor id */
    uint32_t event_id;              /**< event id */
    uint32_t event_second;          /**< event second */
    uint32_t event_microsecond;     /**< event microsecond */
    uint32_t signature_id;          /**< signature id */
    uint32_t generator_id;          /**< generator id */
    uint32_t signature_revision;    /**< signature revision */
    uint32_t classification_id;     /**< classification id */
    uint32_t priority_id;           /**< priority id */
    uint32_t src_ip;                /**< source ip */
    uint32_t dst_ip;                /**< destination ip */
    uint16_t sp;                    /**< source port */
    uint16_t dp;                    /**< destination port */
    uint8_t  protocol;              /**< protocol */
    uint8_t  packet_action;         /**< packet action */
} AlertIPv4Unified2;

/**
 * Unified2 Ipv6 type struct
 *
 * Used for storing ipv6 type values.
 */
typedef struct AlertIPv6Unified2_ {
    uint32_t sensor_id;             /**< sendor id */
    uint32_t event_id;              /**< event id */
    uint32_t event_second;          /**< event second */
    uint32_t event_microsecond;     /**< event microsecond */
    uint32_t signature_id;          /**< signature id */
    uint32_t generator_id;          /**< generator id */
    uint32_t signature_revision;    /**< signature revision */
    uint32_t classification_id;     /**< classification id */
    uint32_t priority_id;           /**< priority id */
    struct in6_addr src_ip;         /**< source ip */
    struct in6_addr dst_ip;         /**< destination ip */
    uint16_t sp;                    /**< source port */
    uint16_t dp;                    /**< destination port */
    uint8_t  protocol;              /**< protocol */
    uint8_t  packet_action;         /**< packet action */
} AlertIPv6Unified2;

/**
 * Unified2 packet type struct
 *
 * Used for storing packet type values.
 */
typedef struct AlertUnified2Packet_ {
    uint32_t sensor_id;             /**< sensor id */
    uint32_t event_id;              /**< event id */
    uint32_t event_second;          /**< event second */
    uint32_t packet_second;         /**< packet second */
    uint32_t packet_microsecond;    /**< packet microsecond */
    uint32_t linktype;              /**< link type */
    uint32_t packet_length;         /**< packet length */
    uint8_t packet_data[4];         /**< packet data */
} Unified2Packet;

#endif

