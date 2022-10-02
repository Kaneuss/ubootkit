#!/bin/bash
./fusee-launcher/fusee-launcher.py ./payload/disable_security_fuses.bin -P 7130
sleep 2
./utils/nvflash_v1.13.87205_miniloader_patched --setbct --bct ./bct/surface_rt_bct.BIN --configfile ./utils/flash.cfg --bl ./u-boot/u-boot-dtb-tegra.bin --go
