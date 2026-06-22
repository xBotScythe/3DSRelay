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

.PHONY: all clean update push

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

# build + sign, then upload the .update and .cia to a 3ds running ftpd, replacing
# the staged files on its sd. start ftpd on the 3ds first; ip comes from .3ds_ip
# or as an argument: make push IP=10.0.0.5
push: update
	@python3 push_update.py $(IP)

clean:
	@echo clean ...
	@rm -rf $(BUILD) $(TARGET).3dsx $(TARGET).smdh $(TARGET).elf $(TARGET).cia


else
# second pass rules for the inner build directory

ARCH	:=	-march=armv6k -mtune=mpcore -mfloat-abi=hard -mtp=soft

CFLAGS	:=	-Wall -Os -mword-relocations \
			-ffunction-sections -fdata-sections \
			$(ARCH)

CFLAGS	+=	$(INCLUDE) -D__3DS__ -Wno-sign-compare

CXXFLAGS	:= $(CFLAGS) -fno-rtti -fno-exceptions -std=gnu++11

ASFLAGS	:=	$(ARCH)
LDFLAGS	=	-specs=3dsx.specs $(ARCH) -Wl,-Map,$(notdir $*.map) -Wl,--gc-sections

LIBS	:= -lcitro2d -lcitro3d -lctru -lm
LIBDIRS	:= $(CTRULIB)

all	:	$(OUTPUT).3dsx $(OUTPUT).cia

$(OUTPUT).3dsx	:	$(OUTPUT).elf $(_3DSXDEPS)

$(OUTPUT).cia	:	$(OUTPUT).elf $(_3DSXDEPS)
	makerom -f cia -o $@ -elf $< -rsf $(TOPDIR)/3DSRelay.rsf -icon $(OUTPUT).smdh -desc app:7.0

$(OUTPUT).elf	:	$(OFILES)

-include $(DEPSDIR)/*.d

endif
