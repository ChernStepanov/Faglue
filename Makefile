CC      := gcc
CFLAGS  := -Wall -Wextra -Werror -std=c11 -O2
LDFLAGS := -lm
TARGET  := faglue
SRCS    := src/main.c

.PHONY: all debug asan clean

all: $(TARGET)

$(TARGET): $(SRCS) src/structs.h src/validator.h
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

debug: CFLAGS := -Wall -Wextra -g -O0
debug: $(TARGET)

asan: CFLAGS := -Wall -Wextra -g -O1 -fsanitize=address,undefined
asan: LDFLAGS += -fsanitize=address,undefined
asan: $(TARGET)

clean:
	rm -f $(TARGET)
