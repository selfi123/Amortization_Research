CONTIKI_PROJECT = node-sender node-gateway
all: $(CONTIKI_PROJECT)

# Source files for cryptographic operations
PROJECT_SOURCEFILES += crypto_core.c crypto_core_session.c

# Session amortization compile-time parameters
CFLAGS += -DSID_LEN=8 -DMASTER_KEY_LEN=32 -DMAX_SESSIONS=16


# Contiki-NG installation path
# MODIFY THIS PATH to point to your Contiki-NG installation
CONTIKI = contiki-ng

# Target platform - use 'native' for testing, 'z1' for hardware
# For development and testing, use native:
#   make TARGET=native
# For Z1 mote deployment:
#   make TARGET=z1

# Memory optimization flags for resource-constrained targets
ifeq ($(TARGET),z1)
  CFLAGS += -Os -ffunction-sections -fdata-sections
  LDFLAGS += -Wl,--gc-sections
endif

# Enable larger stack for native testing
ifeq ($(TARGET),native)
  CFLAGS += -DPROCESS_CONF_STACKSIZE=8192
endif

# Include Contiki-NG build system
include $(CONTIKI)/Makefile.include

# Additional build targets
clean-all:
	rm -f *.native *.z1 *.o *.d *~ symbols.c symbols.h

# Upload to Z1 mote (requires msp430-bsl tool)
upload-sender: node-sender.z1
	msp430-bsl --telosb -c /dev/ttyUSB0 -r -e -I -p node-sender.z1

upload-gateway: node-gateway.z1
	msp430-bsl --telosb -c /dev/ttyUSB0 -r -e -I -p node-gateway.z1

# Memory size check
size: $(CONTIKI_PROJECT)
	@echo "=== Memory Usage Report ==="
	@msp430-size node-sender.z1 node-gateway.z1 2>/dev/null || size *.native
	@echo "==========================="
	@echo "Z1 Mote Limits:"
	@echo "  RAM: 16384 bytes (16 KB)"
	@echo "  ROM: 94208 bytes (92 KB)"
	@echo "==========================="

# Help target
help:
	@echo "Post-Quantum Cryptography for Contiki-NG"
	@echo "========================================="
	@echo ""
	@echo "Usage:"
	@echo "  make TARGET=native              - Build for native (x86) testing"
	@echo "  make TARGET=z1                  - Build for Z1 mote hardware"
	@echo "  make clean                      - Remove build artifacts"
	@echo "  make size                       - Show memory usage"
	@echo "  make upload-sender TARGET=z1    - Upload sender to Z1 mote"
	@echo "  make upload-gateway TARGET=z1   - Upload gateway to Z1 mote"
	@echo ""
	@echo "Before building:"
	@echo "  1. Edit Makefile and set CONTIKI to your Contiki-NG path"
	@echo "  2. Ensure msp430-gcc is installed for Z1 target"
	@echo ""
	@echo "To run simulation in Cooja:"
	@echo "  1. Build with TARGET=z1"
	@echo "  2. Open Cooja simulator"
	@echo "  3. Create new simulation"
	@echo "  4. Add Z1 motes and load .z1 firmware files"
	@echo ""
