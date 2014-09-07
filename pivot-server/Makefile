# Pivotal Network Security Tools
# Derek Chadwick 06/07/2014
# Builds Linux version of Pivotal Server.

# Compiler flags

CC=gcc
CFLAGS=-c -Wall -ansi -D_GNU_SOURCE

# Linker flags

LDFLAGS=-static
LIBS=
LIBDIRS=-L../../libs

# Sources

SOURCES=pivot-server.c \
../common/pvlog.c \
../common/pvutil.c \
../common/pveventfile.c \
../common/pvsocket.c \
../common/pvipmap.c

# Objects

OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=pivot-server

# Includes

INCPREFIX=
INCLUDES=-I../common

# Target Rules

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -DLINUX_BUILD $< -o $@

strip:
	strip pivot-server

clean:
	rm *.o pivot-server ../common/*.o


