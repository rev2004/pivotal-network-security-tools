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
            event packets sent by the sensor.


   Status : EXPERIMENTAL - not for use in production networks.

*/


#include "pvcommon.h"
#include "pivot-server.h"

char pvconnection_source_file[20] = "pvconnection.c ";

void *sensor_connection_handler(void *socket_desc)
{
   int sock = *(int*)socket_desc;
   int read_size;
   char client_message[PV_MAX_INPUT_STR];

   strcpy(client_message, "Greetings! I am your connection handler\n");
   write(sock , client_message , strlen(client_message));

   memset(client_message, 0, PV_MAX_INPUT_STR);

   while((read_size = recv(sock , client_message , PV_MAX_INPUT_STR , 0)) > 0 )
   {
      write(sock , client_message , strlen(client_message));
      memset(client_message, 0, PV_MAX_INPUT_STR);
   }

   if(read_size == 0)
   {
      puts("Client disconnected");
      fflush(stdout);
   }
   else if(read_size == -1)
   {
      perror("recv failed");
   }

   free(socket_desc);

   return(0);
}

