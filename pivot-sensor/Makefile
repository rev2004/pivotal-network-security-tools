# Pivotal Network Security Tools
# Derek Chadwick 06/07/2014
# Builds Linux version of Pivotal Sensor.

# Compiler flags

CC=gcc
CFLAGS=-c -Wall -ansi -DLINUX_BUILD -D_GNU_SOURCE

# Linker flags

LDFLAGS=
LIBS=-lpcap
LIBDIRS=-L../../libs

# Sources

SOURCES=pivot-sensor.c \
pvsniffer.c \
pvfilter.c  \
../common/pvlog.c \
../common/pvutil.c \
../common/pvsocket.c

# Objects

OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=pivot-sensor

# Includes

INCPREFIX=
INCLUDES=-I../common

# Target Rules

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@

strip:
	strip pivot-sensor

clean:
	rm *.o pivot-sensor ../common/*.o


