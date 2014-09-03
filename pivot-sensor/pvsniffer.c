
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
   pvsniffer.c

   Title : Pivotal NST Sensor
   Author: Derek Chadwick
   Date  : 06/07/2014

   Purpose: Pivotal Sensor packet sniffer. Uses libpcap to process IP packets
            on the user specified network interface. If no interface is specified
            the default is used (eth0). A filter file can be specified as a
            commmand line option. The filter file is plain text with lines
            consisting of BSD Packet Filter (BPF) rules. See Wireshark User Guide
            or TCPDUMP man page for more info on BPF rules.

            For each packet processed, the source and destination ip is stored
            in a hashmap and the packet count and data size is accumulated for
            traffic between the src and dst. These records are then sent to the
            Pivotal Server every 60 seconds.

   Note   : The default filter is (ip and not src localhost). The negative condition
            is required since we will be sending event packets to the Pivot Server,
            so we do not want to enter into the recursive spiral of self-analysis.

   Status : EXPERIMENTAL - not for use in production networks.

*/



#include "pvcommon.h"
#include "pivot-sensor.h"

pcap_t* pcap_device;
int link_header_length;
int options;

pcap_t* open_pcap_socket(char* device, const char* bpfstr)
{
   char error_buffer[PCAP_ERRBUF_SIZE];
   pcap_t* pdev;
   uint32_t  src_ip, netmask;
   struct bpf_program  bpfp;

/* DEPRECATED: default to eth0 if interface not specified by user.
   if ((strncmp(device, "NONE", 4) == 0) || (strlen(device) == 0))
   {
      if ((device = pcap_lookupdev(error_buffer)) == NULL)
      {
         sprint_log_entry("open_pcap_socket()", error_buffer);
         return NULL;
      }
   }
*/

   if ((pdev = pcap_open_live(device, BUFSIZ, 1, 0, error_buffer)) == NULL)
   {
      sprint_log_entry("open_pcap_socket()", error_buffer);
      return NULL;
   }

   /* Get network device source IP address and netmask. */
   if (pcap_lookupnet(device, &src_ip, &netmask, error_buffer) < 0)
   {
      sprint_log_entry("open_pcap_socket()", error_buffer);
      return NULL;
   }

   /* Convert the packet filter epxression into a packet filter binary. */
   if (pcap_compile(pdev, &bpfp, (char*)bpfstr, 0, netmask))
   {
      sprint_log_entry("open_pcap_socket()", pcap_geterr(pcap_device));
      return NULL;
   }

   /* Assign the packet filter to the given libpcap socket. */
   if (pcap_setfilter(pdev, &bpfp) < 0)
   {
      sprint_log_entry("open_pcap_socket()", pcap_geterr(pdev));
      return NULL;
   }

   return pdev;
}

void capture_loop(int packets, pcap_handler func)
{
   int link_type;

    /* Determine the datalink layer type. */
   if ((link_type = pcap_datalink(pcap_device)) < 0)
   {
      sprint_log_entry("capture_loop()", pcap_geterr(pcap_device));
      return;
   }

    /* Set the datalink layer header size. */
   switch (link_type)
   {
   case DLT_NULL:
      link_header_length = 4;
      break;

   case DLT_EN10MB:
      link_header_length = 14;
      break;

   case DLT_SLIP:
   case DLT_PPP:
      link_header_length = 24;
      break;

   default:
      iprint_log_entry("capture_loop() <ERROR> Unsupported datalink", link_type);
      return;
   }

    /* Start capturing packets. */
   if (pcap_loop(pcap_device, packets, func, 0) < 0)
   {
      sprint_log_entry("pcap_loop() <ERROR>", pcap_geterr(pcap_device));
   }
}

void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr)
{
   struct ip* iphdr;
   struct icmphdr* icmphdr;
   struct tcphdr* tcphdr;
   struct udphdr* udphdr;
   char ip_header_info[256], srcip[256], dstip[256];
   unsigned short id, seq;

   /* Skip the datalink layer header and get the IP header fields. */
   packetptr += link_header_length;
   iphdr = (struct ip*)packetptr;
   strcpy(srcip, inet_ntoa(iphdr->ip_src));
   strcpy(dstip, inet_ntoa(iphdr->ip_dst));
   sprintf(ip_header_info, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl, 4*iphdr->ip_hl, ntohs(iphdr->ip_len));

   /* Advance to the transport layer header then parse and display the fields based on the type of hearder: tcp, udp or icmp. */
   packetptr += 4*iphdr->ip_hl;
   switch (iphdr->ip_p)
   {
   case IPPROTO_TCP:
        tcphdr = (struct tcphdr*)packetptr;
        printf("TCP  %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->source), dstip, ntohs(tcphdr->dest));
        printf("%s\n", ip_header_info);
        printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
               (tcphdr->urg ? 'U' : '*'),
               (tcphdr->ack ? 'A' : '*'),
               (tcphdr->psh ? 'P' : '*'),
               (tcphdr->rst ? 'R' : '*'),
               (tcphdr->syn ? 'S' : '*'),
               (tcphdr->fin ? 'F' : '*'),
               ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),
               ntohs(tcphdr->window), 4*tcphdr->doff);
        break;

   case IPPROTO_UDP:
      udphdr = (struct udphdr*)packetptr;
      printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->source), dstip, ntohs(udphdr->dest));
      printf("%s\n", ip_header_info);
      break;

   case IPPROTO_ICMP:
      icmphdr = (struct icmphdr*)packetptr;
      printf("ICMP %s -> %s\n", srcip, dstip);
      printf("%s\n", ip_header_info);
      memcpy(&id, (u_char*)icmphdr+4, 2);
      memcpy(&seq, (u_char*)icmphdr+6, 2);
      printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->type, icmphdr->code, ntohs(id), ntohs(seq));
      break;

      default:
         printf("Src: %s Dst: %s Hdr: %s\n", srcip, dstip, ip_header_info);
   }
   printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
}

/*
   Function: process_packet
   Purpose : Called by libpcap to process each packet.
             Parses the ip packet header, tcp/udp headers and
             creates a fineline event record, then sends the
             record to the Pivotal Server or writes it to an
             event file.
   Input   : user data pointer is either a socket or file pointer.
*/
void process_packet(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr)
{
   struct ip* iphdr;
   struct icmphdr* icmphdr;
   struct tcphdr* tcphdr;
   struct udphdr* udphdr;
   char ip_header_info[256], srcip[256], dstip[256], event_data[512], temp_data[256], key_value[512];
   unsigned short id, seq;
   pv_ip_record_t *ip_record;

   /* CLEAR THE BUFFERS */
   memset(event_data, 0, 512);
   memset(key_value, 0, 512);
   memset(temp_data, 0, 256);

   /* Skip the datalink layer header and get the IP header fields. */
   packetptr += link_header_length;
   iphdr = (struct ip*)packetptr;
   strcpy(srcip, inet_ntoa(iphdr->ip_src));
   strcpy(dstip, inet_ntoa(iphdr->ip_dst));
   sprintf(ip_header_info, "ID:%d TOS:0x%x TTL:%d IpLen:%d DgLen:%d ",ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl, 4*iphdr->ip_hl, ntohs(iphdr->ip_len));

   /* Advance to the transport layer header then parse and display the fields based on the type of hearder: tcp, udp or icmp. */
   packetptr += 4*iphdr->ip_hl;
   switch (iphdr->ip_p)
   {
   case IPPROTO_TCP:
      tcphdr = (struct tcphdr*)packetptr;
      sprintf(event_data, "TCP  %s:%d -> %s:%d ", srcip, ntohs(tcphdr->source), dstip, ntohs(tcphdr->dest));
      strncpy(key_value, event_data, strlen(event_data));
      sprintf(temp_data, "%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d ",
               (tcphdr->urg ? 'U' : '*'),
               (tcphdr->ack ? 'A' : '*'),
               (tcphdr->psh ? 'P' : '*'),
               (tcphdr->rst ? 'R' : '*'),
               (tcphdr->syn ? 'S' : '*'),
               (tcphdr->fin ? 'F' : '*'),
               ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),
               ntohs(tcphdr->window), 4*tcphdr->doff);
      strncat(event_data, ip_header_info, strlen(ip_header_info));
      strncat(event_data, temp_data, strlen(temp_data));
      break;

   case IPPROTO_UDP:
      udphdr = (struct udphdr*)packetptr;
      sprintf(event_data, "UDP  %s:%d -> %s:%d ", srcip, ntohs(udphdr->source), dstip, ntohs(udphdr->dest));
      strncpy(key_value, event_data, strlen(event_data));
      strncat(event_data, ip_header_info, strlen(ip_header_info));
      break;

   case IPPROTO_ICMP:
      icmphdr = (struct icmphdr*)packetptr;
      sprintf(event_data, "ICMP %s -> %s ", srcip, dstip);
      strncpy(key_value, event_data, strlen(event_data));
      memcpy(&id, (u_char*)icmphdr+4, 2);
      memcpy(&seq, (u_char*)icmphdr+6, 2);
      sprintf(temp_data, "Type:%d Code:%d ID:%d Seq:%d ", icmphdr->type, icmphdr->code, ntohs(id), ntohs(seq));
      strncat(event_data, ip_header_info, strlen(ip_header_info));
      strncat(event_data, temp_data, strlen(temp_data));
      break;

      default:
         sprintf(event_data, "Src: %s Dst: %s Hdr: %s", srcip, dstip, ip_header_info);
         strncpy(key_value, event_data, strlen(event_data));

   }

   /* Update the hashmap stats */
   if ((ip_record = find_ip(key_value)) != NULL)
   {
      ip_record->packet_count++;
      ip_record->data_size += ntohs(iphdr->ip_len);
   }
   else
   {
      ip_record = xcalloc(sizeof(pv_ip_record_t));
      strncpy(ip_record->key_value, key_value, strlen((key_value)));
      ip_record->data_size = ntohs(iphdr->ip_len);
      ip_record->packet_count = 1;
      add_ip(ip_record);
   }

   /* Now write a Fineline event record. */
   if (options & PV_FILE_OUT)
   {
      write_fineline_event_record(event_data);
   }

   /* Now send event record to the server. */
   if (options & PV_SERVER_OUT)
   {
      send_event(event_data);
   }

   printf("%s\n", event_data);
   printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");

   return;
}


void terminate_capture(int signal_number)
{
   struct pcap_stat stats;

   if (pcap_stats(pcap_device, &stats) >= 0)
   {
      printf("%d packets received\n", stats.ps_recv);
      printf("%d packets dropped\n\n", stats.ps_drop);
   }
   pcap_close(pcap_device);

   if (options & PV_FILE_OUT)
   {
      dump_statistics();
      close_fineline_event_file();
   }

   if (options & PV_SERVER_OUT)
      close_socket();

   print_ip_map();

   exit(0);
}

/*
   Function: start_capture
   Purpose : Opens the pcap socket, sets interrupt signals then calls
             capture_loop() to start packet processing. Also opens the
             event file if logging, opens the tcp socket if sending
             events to the Pivotal Server.
   Input   : Interface and filter strings, event file name, server ip address.
   Output  : Returns -1 on error.
*/
int start_capture(char *interface, const char *bpf_string, char *event_file, char *server_address, int mode)
{
   int packets = 0;
   options = mode;

   if (options & PV_FILE_OUT)
   {
      if (open_fineline_event_file(event_file) == NULL)
      {
         print_log_entry("start_capture() <ERROR> Could not open event file.\n");
         return(-1);
      }
      write_fineline_project_header("Pivot Sensor Packet Capture Log");
   }

   if (options & PV_SERVER_OUT)
   {
      if (init_socket(server_address) == -1)
      {
         print_log_entry("start_capture() <ERROR> Could not init socket.\n");
         return(-1);
      }
   }

   if ((pcap_device = open_pcap_socket(interface, bpf_string)) != NULL)
   {
      signal(SIGINT, terminate_capture);
      signal(SIGTERM, terminate_capture);
      signal(SIGQUIT, terminate_capture);
      /* capture_loop(packets, (pcap_handler)parse_packet); */
      capture_loop(packets, (pcap_handler)process_packet);
      terminate_capture(0);
   }

   return(-1);
}
