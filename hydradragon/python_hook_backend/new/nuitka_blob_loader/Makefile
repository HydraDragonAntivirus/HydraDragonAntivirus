# ============================================================
#  Makefile  --  nuitka_blob_loader
#
#  Targets:
#    make            -> build native (Linux/macOS)
#    make windows    -> cross-compile for Windows (MinGW)
#    make clean
# ============================================================

CC      = gcc
CFLAGS  = -std=c11 -O2 -Wall -Wextra -Iinclude
LDFLAGS = -lm

SRC     = src/main.c src/blob_loader.c src/crc32.c
TARGET  = blob_loader

# ---- native build ----
.PHONY: all
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built: $(TARGET)"

# ---- Windows cross-compile (requires mingw-w64) ----
.PHONY: windows
windows:
	x86_64-w64-mingw32-gcc $(CFLAGS) -o blob_loader.exe $(SRC) $(LDFLAGS)
	@echo "Built: blob_loader.exe"

# ---- MSVC build hint (run from Developer Command Prompt) ----
# cl /TC /O2 /Iinclude src\main.c src\blob_loader.c src\crc32.c /Fe:blob_loader.exe

.PHONY: clean
clean:
	rm -f $(TARGET) blob_loader.exe
