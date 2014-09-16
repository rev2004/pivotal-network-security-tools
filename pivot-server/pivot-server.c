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
   pivot-server.c

   Title : Pivotal NST Server
   Author: Derek Chadwick
   Date  : 06/07/2014

   Purpose: Pivotal Server Main Function. Processes command line options
            and opens a socket to listen for events from the sensors or
            data requests from the GUI. For each connection from a sensor
            a posix thread is spawned to process event packets sent by
            the sensor.

            Functions:
            1. Receives event data from the sensor(s).
            2. Maintains a hashmap of src <-> dst ip connections.
            3. Does whois lookups of each remote ip address.
            4. Maintains a hashmap of remote ip <-> domain owner data.
            5. Maintains traffic statistics for each remote ip.
            6. Receives data requests from the GUI and returns traffic statistics.
            7. Receives intrusions alerts from the venom pot.
            8. Logs events and alerts.

   Status : EXPERIMENTAL - not for use in production networks.

*/


#include "pvcommon.h"
#include "pivot-server.h"

char source_file[20] = "pivot-server.c";

int main(int argc, char *argv[])
{
   char event_file[PV_MAX_INPUT_STR];
   int mode;
   int res = open_log_file(argv[0]);

   if (res < 0)
   {
      printf("pivot-server.c main() <ERROR> Could not open log file.\n");
      exit(FILE_ERROR);
   }
   print_log_entry("pivot-server.c main() <INFO> Starting Pivotal Sensor 1.0\n");

   mode = parse_command_line_args(argc, argv, event_file);
   if (mode > 0)
   {
      init_server_socket(PV_SERVER_PORT, sensor_connection_handler);
   }
   else
   {
      print_log_entry("pivot-server.c main() <ERROR> Invalid command line options!\n");
      show_server_help();
   }

   close_log_file();

   exit(0);
}

/*
   Function: parse_command_line_args
   Purpose : Validates command line arguments.
   Input   : argc, argv.
   Return  : returns -1 on error, mode of operation on success.
*/
int parse_command_line_args(int argc, char *argv[], char *event_filename)
{
   int retval = 0;
   char timestr[100];
   int tlen;

   tlen = get_time_string(timestr, 100);

   if (tlen > 0) /* Build the default event filename, pivotal-events-YYYYMMDD-HHMMSS.fle */
   {
      strncpy(event_filename, EVENT_FILE, strlen(EVENT_FILE));
      strncat(event_filename, timestr, tlen);
   }
   else
   {
      print_log_entry("parse_command_line_args() <WARNING> Invalid time string.\n");
   }
   strncat(event_filename, EVENT_FILE_EXT, 4);

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
         if (strncmp(argv[i], "-c", 2) == 0)
         {
            retval = retval | PV_CAPTURE_INPUT; /* Capture packets on a network interface */
         }
         if (strncmp(argv[i], "-t", 2) == 0)
         {
            retval = retval | PV_UNIFIED2_INPUT; /* Tail Unified2 log files */
         }
         else if (strncmp(argv[i], "-w", 2) == 0)
         {
            retval = retval | PV_FILE_OUT; /* Create FineLine event file */
         }
         else if (strncmp(argv[i], "-g", 2) == 0)
         {
            retval = retval | PV_GUI_OUT; /* Send event records to Pivotal server */
         }
         else if (strncmp(argv[i], "-b", 2) == 0)
         {
            retval = retval | PV_FILE_OUT | PV_SERVER_OUT; /* Create FineLine event file and send events to server */
         }
         else if (strncmp(argv[i], "-o", 2) == 0)
         {
            /* Optional FineLine event file name to use for output of event records */
            if ((i+1) < argc)
            {
               printf("parse_command_line_args() <INFO> FineLine event file: %s\n", argv[i+1]);
               strncpy(event_filename, argv[i+1], strlen(argv[i+1]));
            }
            else
            {
               print_log_entry("parse_command_line_args() <ERROR> Missing event file name.\n");
               return(-1);
            }
         }
         else if (strncmp(argv[i], "-i", 2) == 0)
         {
            /* Network interface for packet capture */
            if ((i+1) < argc)
            {
               printf("parse_command_line_args() <INFO> Interface: %s\n", argv[i+1]);
            }
            else
            {
               print_log_entry("parse_command_line_args() <ERROR> Missing network interface.\n");
               return(-1);
            }
         }
		   else if (strncmp(argv[i], "-a", 2) == 0)
		   {
			   if ((i+1) < argc)
			   {
			      /* IP address of the Pivotal NST Server. */
			      printf("parse_command_line_args() <INFO> Server IP address: %s\n", argv[i+1]);
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

/* TODO: help */
int show_server_help()
{
   printf("\nPivotal NST Server 1.0\n\n");
   printf("Command: pivotal-server <options>\n\n");
   printf("Capture packets from an interface                 : -c\n");
   printf("Tail a Unified2 event log                         : -t\n");
   printf("Output to a fineline event file                   : -w\n");
   printf("Send events to server                             : -s\n");
   printf("Specify fineline output filename                  : -o FILENAME\n");
   printf("Specify network interface                         : -i INTERFACE\n");
   printf("Specify a server IP address                       : -a 192.168.1.10\n");
   printf("Specify filter file                               : -f FILENAME\n");
   printf("\n");
   printf("Input and output files are optional. For sending events to the server\n");
   printf("-a <IPaddress> is mandatory. Minimal command line is:\n\n");
   printf("sudo pivotal-server -w -i wlan0\n\n");
   printf("This will capture packets on the wlan0 interface and output events into\n");
   printf("a default fineline event file: fineline-events-YYYYMMDD-HHMMSS.fle\n");
   printf("An optional BPF filter list can be included, the default filter\n");
   printf("file is pv-filter-list.txt\n");

   return(0);
}

