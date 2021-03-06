ramstage-y += printk.c
ramstage-y += console.c
ramstage-y += vtxprintf.c
ramstage-y += vsprintf.c
ramstage-y += post.c
ramstage-y += die.c

smm-$(CONFIG_DEBUG_SMI) += vtxprintf.c printk.c
smm-$(CONFIG_SMM_TSEG) += die.c

romstage-$(CONFIG_EARLY_CONSOLE) += vtxprintf.c
romstage-y += console.c
romstage-y += post.c
romstage-y += die.c

bootblock-$(CONFIG_BOOTBLOCK_CONSOLE) += vtxprintf.c
bootblock-y += console.c
bootblock-y += die.c

ramstage-$(CONFIG_CONSOLE_SERIAL) += uart_console.c
ramstage-$(CONFIG_SPKMODEM) += spkmodem_console.c
ramstage-$(CONFIG_CONSOLE_USB) += usbdebug_console.c
ramstage-$(CONFIG_CONSOLE_NE2K) += ne2k_console.c
ramstage-$(CONFIG_CONSOLE_CBMEM) += cbmem_console.c
ramstage-$(CONFIG_CONSOLE_QEMU_DEBUGCON) += qemu_debugcon_console.c


$(obj)/console/console.ramstage.o : $(obj)/build.h
$(obj)/console/console.romstage.o : $(obj)/build.h
$(obj)/console/console.bootblock.o : $(obj)/build.h
