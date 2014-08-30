
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
   pvipmap.c

   Title : Pivotal NST Sensor IP Address Map
   Author: Derek Chadwick
   Date  : 06/07/2014

   Purpose: A wrapper for uthash, used to store IP addresses extracted from
            packet captures.

*/

#include "pvcommon.h"
#include "pivot-sensor.h"

pv_ip_record_t *ip_map = NULL; /* the hash map head record */

void add_ip(pv_ip_record_t *flip)
{
    pv_ip_record_t *s;

    HASH_FIND_STR(ip_map, flip->ip_address , s);  /* id already in the hash? */
    if (s == NULL)
    {
      HASH_ADD_STR(ip_map, ip_address, flip);  /* id: name of key field */
    }

}

pv_ip_record_t *find_ip(char *lookup_string)
{
    pv_ip_record_t *s;

    HASH_FIND_STR(ip_map, lookup_string, s);  /* s: output pointer */
    return s;
}

pv_ip_record_t *get_first_ip_record()
{
   return(ip_map);
}

pv_ip_record_t *get_last_ip_record()
{
   pv_ip_record_t *s = get_first_ip_record();
   if (s != NULL)
      return((pv_ip_record_t *)s->hh.prev);
   return(NULL);
}

void delete_ip(pv_ip_record_t *ip_record)
{
    HASH_DEL(ip_map, ip_record);  /* event: pointer to deletee */
    free(ip_record);
}

void delete_all_ips()
{
  pv_ip_record_t *current_ip, *tmp;

  HASH_ITER(hh, ip_map, current_ip, tmp)
  {
    HASH_DEL(ip_map,current_ip);  /* delete it (ip_map advances to next) */
    free(current_ip);              /* free it */
  }
}

void write_ip_map(FILE *outfile)
{
    pv_ip_record_t *s;

    for(s=ip_map; s != NULL; s=(pv_ip_record_t *)(s->hh.next))
    {
        fputs(s->ip_address, outfile);
    }
}

void send_ip_map()
{
    pv_ip_record_t *s;

    for(s=ip_map; s != NULL; s=(pv_ip_record_t *)(s->hh.next))    {
        send_event(s->ip_address);
    }
}

void print_ip_map()
{
    pv_ip_record_t *s;

    for(s=ip_map; s != NULL; s=(pv_ip_record_t *)(s->hh.next))
    {
        printf("URL: %s\n", s->ip_address);
    }
}

