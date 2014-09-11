
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
   pvsocket.c

   Title : Pivotal NST.
   Author: Derek Chadwick
   Date  : 06/07/2014

   Purpose: Wrapper functions for network client and server sockets for TCP and UDP
            communications.

   TODO: Implement udp socket functions.

*/


#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "pvcommon.h"


/*
   Function: init_client_socket
   Purpose : initialises a Linux/BSD socket.
   Input   : string containing the GUI IP address.
   Return  : A valid socket = success, -1 = fail.
*/
int init_client_socket(char *server_ip_address)
{
   int sockfd;
   struct sockaddr_in serv_addr;

   if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
   {
      print_log_entry("init_socket() <ERROR> Could not create socket.\n");
      return(-1);
   }

   memset(&serv_addr, '0', sizeof(serv_addr));

   serv_addr.sin_family = AF_INET;
   serv_addr.sin_port = htons(PV_SERVER_PORT);

   if(inet_pton(AF_INET, server_ip_address, &serv_addr.sin_addr)<=0)
   {
      print_log_entry("init_socket() <ERROR> inet_pton error occurred.\n");
      return(-1);
   }

   if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
   {
      printf("init_socket() <ERROR> Connect Failed.\n");
      return(-1);
   }
   return(sockfd);
}

/*
   Function: init_server_socket
   Purpose : initialises a server TCP socket and spawns a thread to handle
             each new connection.
   Input   : TCP port number, handler function.
   Return  : 0 = success, -1 = fail.
*/
int init_server_socket(int port_number, void *(* connector)(void *))
{
   int sockfd, new_sock, sock_size, *new_sock_p;
   struct sockaddr_in server_addr, client_addr;
   pthread_t server_thread;
   char message[PV_MAX_INPUT_STR];

   if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
   {
      print_log_entry("init_server_socket() <ERROR> Could not create socket.\n");
      return(-1);
   }

   sock_size = sizeof(struct sockaddr_in);
   memset(&server_addr, '0', sock_size);
   memset(&client_addr, '0', sock_size);

   server_addr.sin_family = AF_INET;
   server_addr.sin_addr.s_addr = INADDR_ANY;
   server_addr.sin_port = htons(PV_SERVER_PORT);

   if(bind(sockfd, (struct sockaddr *)&server_addr, sock_size) < 0)
   {
      print_log_entry("init_server_socket() <ERROR> Could not bind socket.\n");
      return 1;
   }

   listen(sockfd , 3);

   print_log_entry("init_server_socket() <INFO> Waiting for incoming connections...\n");

   while((new_sock = accept(sockfd, (struct sockaddr *)&client_addr, (socklen_t*)&sock_size)))
   {
      print_log_entry("init_server_socket() <INFO> Connection accepted.\n");

      /* DEBUG */
      strcpy(message, "Hello Client , I have received your connection. And now I will assign a handler for you.");
      write(new_sock, message, strlen(message));

      new_sock_p = malloc(1);
      *new_sock_p = new_sock;

      if(pthread_create(&server_thread, NULL, connector, (void*)new_sock_p) < 0)
      {
         print_log_entry("init_server_socket() <ERROR> Could not create thread.\n");
         return(-1);
      }

      memset(&client_addr, '0', sock_size);
   }

   if (new_sock < 0)
   {
      perror("accept failed");
      return(-1);
   }

   return(0);
}

int send_event(int sockfd, char *event_string)
{
   int k;
   k = send(sockfd, event_string, strlen(event_string), 0);
   if (k == -1)
   {
      print_log_entry("send_event() <ERROR> Cannot write to server!\n");
   }

   return(k);
}

/* TODO: protocol not fully specified yet */
char *get_response(int sockfd, char *in_buffer)
{
   return(NULL);
}

int close_socket(int sockfd)
{
   close(sockfd);
   return(0);
}

/* DEBUG */
void *connection_handler(void *socket_desc)
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

