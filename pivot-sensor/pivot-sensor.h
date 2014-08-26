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
   pivot_sensor.h

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

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

/* pivot-sensor.c */

int parse_command_line_args(int argc, char *argv[], char *capture_device, char *pv_event_filename, char *server_ip_address, char *filter_file);
int show_sensor_help();

/* pvsniffer.c */

pcap_t* open_pcap_socket(char* device, const char* bpfstr);
void capture_loop(int packets, pcap_handler func);
void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr);
void terminate_capture(int signal_number);
int start_capture(char *interface, const char *bpf_string);

/* */


#endif