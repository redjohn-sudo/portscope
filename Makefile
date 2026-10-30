# portscope - a TCP port scanner that speaks MCP, in C.
CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Ivendor -Isrc
BIN      = portscope
OBJ      = src/main.o src/net.o vendor/cJSON.o

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BIN) $(OBJ)

.PHONY: clean
