/* SPDX-License-Identifier: GPL-2.0-only */
/* Replacement libusb, not an interposer. No USB implementation is linked. */
#include <libusb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct libusb_device { unsigned number; };
static struct libusb_device first = {14}, second = {12};
static libusb_device *devices[] = {&first, &second, NULL};
static int fixture(const char *name) { return !strcmp(getenv("USB_CASE"), name); }

int libusb_init(libusb_context **ctx) { *ctx = NULL; return 0; }
void libusb_exit(libusb_context *ctx) { (void)ctx; }
ssize_t libusb_get_device_list(libusb_context *ctx, libusb_device ***list)
{
	(void)ctx;
	*list = devices;
	return fixture("empty") ? 0 : fixture("one") ? 1 : 2;
}
void libusb_free_device_list(libusb_device **list, int unref)
{
	(void)list;
	(void)unref;
}
int libusb_get_device_descriptor(libusb_device *d, struct libusb_device_descriptor *desc)
{
	if (fixture("unreadable") && d == &second)
		return LIBUSB_ERROR_IO;
	desc->idVendor = fixture("wrong") && d == &second ? 0 : 0x1f3a;
	desc->idProduct = 0xefe8;
	return 0;
}
uint8_t libusb_get_bus_number(libusb_device *d) { (void)d; return 3; }
uint8_t libusb_get_device_address(libusb_device *d) { return d->number; }
int libusb_get_port_numbers(libusb_device *d, uint8_t *ports, int length)
{
	if (length < 2)
		return LIBUSB_ERROR_OVERFLOW;
	if (d == &first || fixture("duplicate")) {
		ports[0] = 3;
		ports[1] = 4;
		return 2;
	}
	ports[0] = 6;
	return 1;
}
int libusb_open(libusb_device *d, libusb_device_handle **handle)
{
	fprintf(stderr, "mock open %u\n", d->number);
	if (fixture("receipt")) {
		*handle = (libusb_device_handle *)d;
		return 0;
	}
	return LIBUSB_ERROR_ACCESS;
}
int libusb_kernel_driver_active(libusb_device_handle *h, int i)
{
	(void)h; (void)i;
	return 0;
}
int libusb_claim_interface(libusb_device_handle *h, int i)
{
	(void)h; (void)i;
	return LIBUSB_ERROR_ACCESS;
}
void libusb_close(libusb_device_handle *h) { (void)h; }
