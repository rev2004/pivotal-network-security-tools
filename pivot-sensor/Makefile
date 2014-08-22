# Pivotal Network Security Tools
# Derek Chadwick 06/07/2014
# Builds Linux version of Pivotal Sensor.

# Compiler flags

CC=gcc
CFLAGS=-c -Wall -ansi

# Linker flags

LDFLAGS=-static
LIBS=-lpcap
LIBDIRS=-L../../libs

# Sources

SOURCES=fineline.c \
fllog.c \
flutil.c \
fleventparser.c \
fleventfile.c \
fleventhashmap.c \
flevt.c \
flevtx.c \
flfiltermap.c \
flwineventhashmap.c \
flsocket.c

# Objects

OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=pivotal-sensor

# Includes

INCPREFIX=../../libs/libevtx-20131211
INCLUDES=-I$(INCPREFIX)/include \
-I$(INCPREFIX)/common \
-I$(INCPREFIX)/libfdatetime \
-I$(INCPREFIX)/libcerror \
-I$(INCPREFIX)/libcstring \
-I../common

# Target Rules

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -DLINUX_BUILD $< -o $@

strip:
	strip pivotal-sensor

clean:
	rm *.o pivotal-sensor


