/*  Copyright 2014 Derek Chadwick

    This file is part of the Pivotal Network Security Tools.

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
   pivot_server.h

   Title : Pivotal Server Main Header File
   Author: Derek Chadwick
   Date  : 06/07/2014

   Purpose: Pivotal Server global definitions.

*/


/*
   Constant Definitions
*/

#ifndef PIVOTAL_SERVER_H
#define PIVOTAL_SERVER_H


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
#include <ifaddrs.h>
#include <pcap.h>


/* pivot-server.c */

int parse_command_line_args(int argc, char *argv[], char *event_filename);
int show_server_help();

/* pvconnection.c */

void *sensor_connection_handler(void *socket_desc);


#endif
