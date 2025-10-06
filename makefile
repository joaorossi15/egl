TARGET := egl

CC      := gcc
CFLAGS  := -Wall -Wextra -std=c11 \
           -Iinclude \
           -Isrc/lex \
           -Isrc/parser \
           -Isrc/runtime \
           -Isrc/eval \
           -Isrc/eval/eval-cat
LDFLAGS := 

# --- PCRE2 detection (prefer pcre2-config; fallback to pkg-config; then -lpcre2-8)
PCRE2_CFLAGS := $(shell pcre2-config --cflags 2>/dev/null)
PCRE2_LIBS   := $(shell pcre2-config --libs   2>/dev/null)

ifeq ($(strip $(PCRE2_LIBS)),)
  # try pkg-config if pcre2-config isn't available
  ifneq ($(shell pkg-config --exists pcre2-8 && echo yes),)
    PCRE2_CFLAGS := $(shell pkg-config --cflags pcre2-8)
    PCRE2_LIBS   := $(shell pkg-config --libs   pcre2-8)
  else
    # last-resort fallback
    PCRE2_CFLAGS :=
    PCRE2_LIBS   := -lpcre2-8
  endif
endif

CFLAGS  += $(PCRE2_CFLAGS)
LDFLAGS += $(PCRE2_LIBS)

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

# Optional helper targets
pcre2-info:
	@echo "PCRE2_CFLAGS=$(PCRE2_CFLAGS)"
	@echo "PCRE2_LIBS=$(PCRE2_LIBS)"

