#!/bin/bash
./fusee-launcher/fusee-launcher.py ./payload/disable_security_fuses.bin -P7130
sleep 1
./utils/nvflash_v1.13.87205 --getbct --bct ./bct/surface_rt_bct.BIN --configfile ./utils/flash.cfg
