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

   Purpose: Implements functions for handling packets sent by sensors.
            For each connection from a sensor a posix thread is spawned to process
            event packets sent by the sensor. The connection handler logs all
            messages received from the sensor and updates the statistics hashmap
            for traffic to remote IP addresses.


   Status : EXPERIMENTAL - not for use in production networks.

*/


#include "pvcommon.h"
#include "pivot-server.h"

char pvconnection_source_file[20] = "pvconnection.c";

/*
   Function: sensor_connection_handler
   Purpose : Called by the posix thread, opens sensor log file then
             loops on the socket recv command, logs messages received
             from the sensor and updates the IP statistics hash map.
   Input   : Socket descriptor.
   Return  : returns NULL.
*/
void *sensor_connection_handler(void *socket_desc)
{
   int sock = *(int*)socket_desc;
   int read_size, tlen;
   char timestr[100];
   char sensor_id[100];
   char sensor_message[PV_MAX_INPUT_STR];
   char event_filename[PV_MAX_INPUT_STR];
   FILE *sensor_log;

   print_log_entry("sensor_connection_handler() <INFO> Connection handler starting.\n");

   /* !!!CLEAR THE BUFFERS!!! */
   memset(sensor_message, 0, PV_MAX_INPUT_STR);
   memset(event_filename, 0, PV_MAX_INPUT_STR);
   memset(sensor_id, 0, 100);
   memset(timestr, 0, 100);

   /*
      Read the first message from the sensor, extract the sensor ID from the message
      and open the log file. A separate log file is maintained for each sensor.
      The file format is plain text Fineline Event format ->

      https://code.google.com/p/fineline-computer-forensics-timeline-tools/

      The log file name format is: SID0000-YYYYMMDD-HHMMSS.fle

   */

   if ((read_size = recv(sock, sensor_message, PV_MAX_INPUT_STR, 0)) > 0)
   {

      get_sensor_id(sensor_message, sensor_id);
      strncpy(event_filename, sensor_id, strlen(sensor_id));
      tlen = get_time_string(timestr, 100);

      if (tlen > 0) /* Build the default event log filename, SENSOR0000-YYYYMMDD-HHMMSS.fle */
      {
         strncat(event_filename, timestr, tlen);
      }
      else
      {
         strncat(event_filename, "-YYYYMMDD-HHMMSS", 16);
         print_log_entry("sensor_connection_handler() <WARNING> Invalid time string.\n");
      }
      strncat(event_filename, EVENT_FILE_EXT, 4);

      sensor_log = open_sensor_log_file(event_filename);
      if (sensor_log == NULL)
      {
         print_log_entry("sensor_connection_handler() <ERROR> Could not open sensor log file.\n");
         return(NULL);
      }
      /* TODO: update statistics hashmap */
      write_project_header(sensor_log, "Pivotal Sensor Log");
      write_sensor_log_record(sensor_log, sensor_message);
   }
   else
   {
      print_log_entry("sensor_connection_handler() <ERROR> Sensor receive failed.\n");
      return(NULL);
   }

   /*
      Start the receive loop, only exit receive on error or sensor disconnect.
   */

   while((read_size = recv(sock, sensor_message, PV_MAX_INPUT_STR, 0)) > 0 )
   {
      /* TODO: update connections statistics map */
      write_sensor_log_record(sensor_log, sensor_message);
      memset(sensor_message, 0, PV_MAX_INPUT_STR);
   }

   if(read_size == 0)
   {
      print_log_entry("sensor_connection_handler() <INFO> Sensor disconnected.\n");
   }
   else if(read_size == -1)
   {
      print_log_entry("sensor_connection_handler() <ERROR> Sensor receive failed.\n");
   }

   close_sensor_log_file(sensor_log);
   free(socket_desc);

   return(NULL);
}

void get_sensor_id(char *msg, char *sid)
{
   char *ptr;

   ptr = strstr(msg, "SENSOR");

   /*
      Each message from a sensor contains an ID field with the following format:
      <id>SENSORXXXX</id>
      Were XXXX is a user specified 4 digit number. Each sensor id should be
      unique to assist in forensic backtracking and prevent confusion of the
      message sources and log files.
   */

   if (ptr != NULL)
   {
      strncpy(sid, ptr, 10);
   }
   else
   {
      strncpy(sid, "SENSORXXXX", 10); /* Unknown sensor ID. */
   }

   return;
}
