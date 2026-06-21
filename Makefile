# makefile for 3dsrelay
# supports native 3ds build

# native 3ds compilation configuration using devkitpro
export APP_TITLE       := FAT32 File System Diagnostics
export APP_DESCRIPTION := FAT32 File System Diagnostics Tool
export APP_AUTHOR      := xbotscythe

ifeq ($(strip $(DEVKITARM)),)
DEVKITARM := /opt/devkitpro/devkitARM
endif
ifeq ($(strip $(DEVKITPRO)),)
DEVKITPRO := /opt/devkitpro
endif
ifeq ($(strip $(CTRULIB)),)
CTRULIB := $(DEVKITPRO)/libctru
endif

TOPDIR ?= $(CURDIR)
include $(DEVKITARM)/3ds_rules

TARGET		:=	3DSRelay
BUILD		:=	build
SOURCES		:=	source source/quirc
DATA		:=	data
INCLUDES	:=	include
GRAPHICS	:=	gfx
GFXBUILD	:=	$(BUILD)
LIBDIRS		:=	$(CTRULIB)

ifneq ($(BUILD),$(notdir $(CURDIR)))
# first pass rules for the outer directory

export OUTPUT	:=	$(CURDIR)/$(TARGET)
export TOPDIR	:=	$(CURDIR)

export VPATH	:=	$(foreach dir,$(SOURCES),$(CURDIR)/$(dir)) \
			$(foreach dir,$(GRAPHICS),$(CURDIR)/$(dir)) \
			$(foreach dir,$(DATA),$(CURDIR)/$(dir))

export DEPSDIR	:=	$(CURDIR)/$(BUILD)

CFILES		:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
CPPFILES	:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
SFILES		:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.s)))

export LD	:=	$(CXX)

export OFILES_SOURCES 	:=	$(CPPFILES:.cpp=.o) $(CFILES:.c=.o) $(SFILES:.s=.o)
export OFILES := $(OFILES_SOURCES)

export INCLUDE	:=	$(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
			$(foreach dir,$(LIBDIRS),-I$(dir)/include) \
			-I$(CURDIR)/$(BUILD)

export LIBPATHS	:=	$(foreach dir,$(LIBDIRS),-L$(dir)/lib)

export _3DSXDEPS	:=	$(OUTPUT).smdh

export _3DSXFLAGS += --smdh=$(CURDIR)/$(TARGET).smdh

.PHONY: all clean update

all: $(BUILD) $(DEPSDIR)
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

$(BUILD):
	@mkdir -p $@

ifneq ($(DEPSDIR),$(BUILD))
$(DEPSDIR):
	@mkdir -p $@
endif

update: all
ifndef SIGNING_KEY
	$(error SIGNING_KEY is not set. pass as arg or env var)
endif
	@SIGNING_KEY=$(SIGNING_KEY) python3 pack_update.py

clean:
	@echo clean ...
	@rm -rf $(BUILD) $(TARGET).3dsx $(TARGET).smdh $(TARGET).elf $(TARGET).cia


else
# second pass rules for the inner build directory

ARCH	:=	-march=armv6k -mtune=mpcore -mfloat-abi=hard -mtp=soft

CFLAGS	:=	-g -Wall -O2 -mword-relocations \
			-ffunction-sections \
			$(ARCH)

CFLAGS	+=	$(INCLUDE) -D__3DS__ -Wno-sign-compare

CXXFLAGS	:= $(CFLAGS) -fno-rtti -fno-exceptions -std=gnu++11

ASFLAGS	:=	-g $(ARCH)
LDFLAGS	=	-specs=3dsx.specs -g $(ARCH) -Wl,-Map,$(notdir $*.map)

LIBS	:= -lcitro2d -lcitro3d -lctru -lm
LIBDIRS	:= $(CTRULIB)

all	:	$(OUTPUT).3dsx $(OUTPUT).cia

$(OUTPUT).3dsx	:	$(OUTPUT).elf $(_3DSXDEPS)

$(OUTPUT).cia	:	$(OUTPUT).elf $(_3DSXDEPS)
	makerom -f cia -o $@ -elf $< -rsf $(TOPDIR)/3DSRelay.rsf -icon $(OUTPUT).smdh -desc app:7.0

$(OUTPUT).elf	:	$(OFILES)

-include $(DEPSDIR)/*.d

endif
