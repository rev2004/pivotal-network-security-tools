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
   pivot-sensor.c

   Title : Pivotal NST Sensor
   Author: Derek Chadwick
   Date  : 06/07/2014

   Purpose: Pivotal Sensor Main Function. Processes command line options
            and executes packet sniffer mode or unified2 log follower
            mode.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pvcommon.h"

static uint32_t sensor_id = 0;

int main(int argc, char *argv[])
{
   char pv_out_file[PV_PATH_MAX];
   char server_ip_address[PV_IP_ADDR_MAX];
   char filter_file[PV_PATH_MAX];
   int mode;
   int res = open_log_file(argv[0]);

   if (res < 0)
   {
      printf("pivot-sensor.c main() <ERROR> Could not open log file.\n");
      exit(FILE_ERROR);
   }
   print_log_entry("pivot-sensor.c main() <INFO> Starting Pivotal Sensor 1.0\n");

   mode = parse_command_line_args(argc, argv, pv_out_file, server_ip_address, filter_file);
   if (mode > 0)
   {

      if (mode & PV_SNIFF_INPUT)
      {
      }
      else if (mode & PV_UNIFIED2_INPUT)
      {
      }
      else
      {
         print_log_entry("pivot-sensor.c main() <ERROR> Invalid command line options!\n");
         show_help();
      }
   }
   else
   {
      print_log_entry("pivot-sensor.c main() <ERROR> Invalid command line options!\n");
      show_help();
   }

   close_log_file();

   exit(0);
}

/*
   Function: parse_command_line_args
   Purpose : Validates command line arguments.
   Input   : argc, argv, log file and db file handles.
   Return  : mode of operation and database file handle if required.
*/
int parse_command_line_args(int argc, char *argv[], char *pv_event_filename, char *in_file, char *server_ip_address, char *filter_file)
{
   int retval = 0;
   int input_file_specified = 0;
   char timestr[100];
   int tlen;

   tlen = get_time_string(timestr, 99);

   memset(pv_event_filename, 0, PV_PATH_MAX);
   memset(in_file, 0, PV_PATH_MAX);
   memset(filter_file, 0, PV_PATH_MAX);
   strncpy(pv_event_filename, EVENT_FILE, strlen(EVENT_FILE)); /* the default event filename */

   if (tlen > 0)
   {
      strncat(pv_event_filename, timestr, tlen);
   }
   else
   {
      print_log_entry("parse_command_line_args() <WARNING> Invalid time string.\n");
   }
   strncat(pv_event_filename, EVENT_FILE_EXT, 4);

   if (argc < 2)
   {
	  print_log_entry("parse_command_line_args(): invalid arguments < 2\n");
      return(-1);
   }
   else
   {
      int i;
      for (i = 1; i < argc; i++)
      {
         if (strncmp(argv[i], "-w", 2) == 0)
         {
            retval = retval | PV_FILE_OUT; /* Create FineLine event file */
         }
         else if (strncmp(argv[i], "-s", 2) == 0)
         {
            retval = retval | PV_SERVER_OUT; /* Send event records to Pivotal server */
         }
         else if (strncmp(argv[i], "-b", 2) == 0)
         {
            retval = retval | PV_FILE_OUT | PV_SERVER_OUT; /* Create FineLine event file and send events to server */
         }
         else if (strncmp(argv[i], "-o", 2) == 0)
         {
            /* FineLine event file name to use for output of event records */
            if ((i+1) < argc)
            {
               printf("parse_command_line_args() <INFO> FineLine event file: %s\n", argv[i+1]);
               strncpy(pv_event_filename, argv[i+1], strlen(argv[i+1]));
            }
            else
            {
               print_log_entry("parse_command_line_args() <ERROR> Missing event file name.\n");
               return(-1);
            }
         }
         else if (strncmp(argv[i], "-i", 2) == 0)
         {

         }
		   else if (strncmp(argv[i], "-a", 2) == 0)
		   {
			   if ((i+1) < argc)
			   {
			      printf("parse_command_line_args() <INFO> Server IP address: %s\n", argv[i+1]);
               strncpy(server_ip_address, argv[i+1], strlen(argv[i+1]));
			      if (validate_ipv4_address(gui_ip_address) < 0)
			      {
				      print_log_entry("parse_command_line_args() <ERROR> Invalid IPv4 address.\n");
                  return(-1);
			      }
			   }
			   else
			   {
			      print_log_entry("parse_command_line_args() <ERROR> Missing IPv4 address.\n");
               return(-1);
			   }
		   }
         else if (strncmp(argv[i], "-f", 2) == 0)
         {
            /* Filter file name  */
            if ((i+1) < argc)
            {
               printf("parse_command_line_args() <INFO> Filter file: %s\n", argv[i+1]);
               strncpy(filter_file, argv[i+1], strlen(argv[i+1]));
			      retval = retval | PV_FILTER_ON;
            }
            else
            {
               print_log_entry("parse_command_line_args() <ERROR> Missing filter file name.\n");
               return(-1);
            }
         }
      }
   }

   print_log_entry("parse_command_line_args() <INFO> Finished processing command line arguments.\n");

   return(retval);
}


