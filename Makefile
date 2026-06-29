CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
TARGET   = grad
SRC      = grad.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

install: $(TARGET)
	install -Dm755 $(TARGET) /usr/local/bin/$(TARGET)

clean:
	rm -f $(TARGET)
