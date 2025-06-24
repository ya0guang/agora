CC := clang
CFLAGS := -fsanitize=safe-stack
COMMON_CFLAGS := -O0
SRCS := $(wildcard *.c)
LLS := $(SRCS:.c=.ll)
ASMS := $(SRCS:.c=.s)
SAFESTACK_LLS := $(SRCS:.c=ss.ll)
SAFESTACK_ASMS := $(SRCS:.c=ss.s)

all: $(LLS) $(SAFESTACK_LLS) $(ASMS) $(SAFESTACK_ASMS)

$(LLS): $(SRCS)
	$(CC) -S -emit-llvm -o $@ $^

$(SAFESTACK_LLS): $(SRCS)
	$(CC) -S -emit-llvm -o $@ $^ $(CFLAGS)

$(ASMS): $(SRCS)
	$(CC) -S -o $@ $^

$(SAFESTACK_ASMS): $(SRCS)
	$(CC) -S -o $@ $^ $(CFLAGS)


.PHONY: clean

clean:
	rm $(LLS) $(SAFESTACK_LLS) $(ASMS) $(SAFESTACK_ASMS)