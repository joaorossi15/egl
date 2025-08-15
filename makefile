TARGET := egl

CC      := gcc
CFLAGS  := -Wall -Wextra -std=c11 \
           -Iinclude \
           -Isrc/lex \
           -Isrc/parser
LDFLAGS := 

SRC := $(shell find src -name '*.c')

OBJ := $(patsubst src/%.c, build/%.o, $(SRC))

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

build/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build $(TARGET)
