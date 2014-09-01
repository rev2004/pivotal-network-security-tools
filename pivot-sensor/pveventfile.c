
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
   pveventfile.c

   Title : Pivotal NST Sensor Event File
   Author: Derek Chadwick
   Date  : 06/07/2014

   Purpose: Pivotal Sensor event file open/write/close functions.

*/



#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "pvcommon.h"
#include "pivot-sensor.h"

FILE *evt_file;

/*
   Function: open_event_file()

   Purpose : event file in the current working directory.
   Input   : event file name.
   Output  : Returns event file pointer or NULL on fail.
*/
FILE *open_fineline_event_file(char *evt_file_name)
{
    evt_file = fopen(evt_file_name, "a");
    if (evt_file == NULL)
    {
       printf("open_fineline_event_file() <ERROR>: could not open event file: %s\n", evt_file_name);
       return(NULL);
    }
    printf("open_event_file() <INFO> open_fineline_event_file(): %s\n", evt_file_name);

   return(evt_file);
}


/*
   Function: write_fineline_event_record()

   Purpose : Creates an event string and writes to the fineline event file.
           :
   Input   : Event data string.
   Output  : Timestamped event record.
*/
int write_fineline_event_record(char *estr)
{
   time_t curtime;
   struct tm *loctime;
   char event_string[PV_MAX_INPUT_STR];
   char *time_str;

   /* Get the current time. */
   curtime = time (NULL);
   loctime = localtime (&curtime);

   time_str = asctime(loctime);

   strcpy(event_string, "<event><id>PVSENSOR</id><evidencenumber>NONE</evidencenumber><time>");
   strcat(event_string, time_str);
   strcat(event_string, "</time><type>1</type><summary>Pivot Sensor Packet Event</summary><data>");
   strncat(event_string, estr, strlen(estr));
   strcat(event_string, "</data><hiddenevent>0</hiddenevent><hiddentext>0</hiddentext><marked>0</marked><pinned>0</pinned><ypos>0</ypos></event>\n");

   fputs (event_string, evt_file);

   printf("%s", event_string);

   return(0);
}

/*
   Function: write_fineline_project_header()

   Purpose : Creates an event file header string and writes to the event file.
           :
   Input   : Project description string.
   Output  : Timestamped log header entry.
*/
int write_fineline_project_header(char *pstr)
{
   time_t curtime;
   struct tm *loctime;
   int slen = strlen(pstr) + PV_MAX_INPUT_STR;
   char *hdr = (char *) xcalloc(slen);
   char *time_str;

   /* Get the current time. */
   curtime = time (NULL);
   loctime = localtime (&curtime);
   time_str = asctime(loctime);

   strcpy(hdr, "<project><name>FineLine Project ");
   strncat(hdr, time_str, strlen(time_str) - 1);
   strcat(hdr, "</name><investigator>NONE</investigator><summary>NONE</summary><startdate>NONE</startdate><enddate>NONE</enddate><description>");
   strncat(hdr, pstr, slen);
   strcat(hdr, "</description></project>\n");
   fputs (hdr, evt_file);

   print_log_entry("write_fineline_project_header() <INFO> Wrote Project Header.\n");

   xfree(hdr, slen);

   return(0);
}

int close_fineline_event_file()
{
   if (fclose(evt_file) < 0)
   {
      print_log_entry("close_fineline_event_file() <ERROR> Close event file error.\n");
      return(-1);
   }
   return(0);
}


