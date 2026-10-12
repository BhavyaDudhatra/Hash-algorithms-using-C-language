CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
TARGET = hasher
SRC = main.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

# Linux needs -pthread for the cracker threads; harmless elsewhere
linux:
	$(CC) $(CFLAGS) -pthread -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET) $(TARGET).exe

# Quick smoke test: hash "hello" with SHA-256, expect 2cf24dba...
test: $(TARGET)
	printf '1\nhello\n4\n3\n' | ./$(TARGET) | grep -q '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824' && echo HASH_OK

.PHONY: all linux clean test
