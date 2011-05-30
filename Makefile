TOP = .
CFLAGS := -Wall -I$(TOP) `pkg-config --cflags --libs glib-2.0`
VpnGrabber : vpngrabber.c
	gcc -o VpnGrabber -g vpngrabber.c $(CFLAGS)
