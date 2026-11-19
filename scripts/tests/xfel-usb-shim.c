/* SPDX-License-Identifier: GPL-2.0-only */
/* Replacement library inside the fixture mount namespace. No USB backend. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libusb.h>
#include <linux/usbdevice_fs.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int verified_fd = -1;
static int ack_count;
static int fixture(const char *name)
{
	const char *test = getenv("USB_CASE");
	return test && !strcmp(test, name);
}

int open(const char *path, int flags, ...)
{
	assert(!strncmp(path, "/dev/bus/usb/", 13) && !(flags & O_CREAT));
	if(fixture("open-gone"))
	{
		errno = ENODEV;
		return -1;
	}
	return syscall(SYS_openat, AT_FDCWD, path, flags, 0);
}

ssize_t pread(int fd, void *buf, size_t size, off_t offset)
{
	if(fixture("descriptor-gone"))
	{
		errno = ENODEV;
		return -1;
	}
	return syscall(SYS_pread64, fd, buf, size, offset);
}

int ioctl(int fd, unsigned long cmd, ...)
{
	char link[64], path[128];
	unsigned number;
	assert(cmd == USBDEVFS_CONNINFO_EX(sizeof(struct usbdevfs_conninfo_ex)));
	snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
	ssize_t n = readlink(link, path, sizeof(path) - 1);
	assert(n > 0);
	path[n] = 0;
	assert(sscanf(path, "/dev/bus/usb/003/%u", &number) == 1);
	fprintf(stderr, "mock fd %u\n", number);
	va_list ap;
	va_start(ap, cmd);
	struct usbdevfs_conninfo_ex *info = va_arg(ap, struct usbdevfs_conninfo_ex *);
	va_end(ap);
	info->size = sizeof(*info);
	info->busnum = fixture("fd-bus") ? 4 : 3;
	info->devnum = fixture("fd-address") ? 19 : number;
	info->num_ports = number == 14 ? 2 : 1;
	info->ports[0] = number == 14 ? 3 : fixture("fd-port") ? 7 : 6;
	info->ports[1] = 4;
	verified_fd = fd;
	if(fixture("no-conninfo"))
	{
		errno = ENOTTY;
		return -1;
	}
	return 0;
}

int libusb_init_context(libusb_context **ctx, const struct libusb_init_option opt[], int n)
{
	assert(n == 1 && opt[0].option == LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
	fprintf(stderr, "mock init\n");
	*ctx = (libusb_context *)(intptr_t)1;
	return 0;
}
int libusb_wrap_sys_device(libusb_context *ctx, intptr_t fd, libusb_device_handle **h)
{
	assert(ctx && fd == verified_fd && fd >= 0);
	*h = (libusb_device_handle *)(intptr_t)(fd + 1);
	fprintf(stderr, "mock wrap\n");
	return 0;
}
static void check_handle(libusb_device_handle *h)
{
	assert(verified_fd >= 0 && h == (libusb_device_handle *)(intptr_t)(verified_fd + 1));
}
int libusb_kernel_driver_active(libusb_device_handle *h, int i)
{
	check_handle(h);
	assert(i == 0);
	return 0;
}
int libusb_claim_interface(libusb_device_handle *h, int i)
{
	check_handle(h);
	assert(i == 0);
	fprintf(stderr, "mock claim\n");
	return 0;
}
libusb_device *libusb_get_device(libusb_device_handle *h)
{
	check_handle(h);
	return (libusb_device *)h;
}
int libusb_get_active_config_descriptor(libusb_device *dev, struct libusb_config_descriptor **out)
{
	static const struct libusb_endpoint_descriptor eps[] = {
		{.bmAttributes = 2, .bEndpointAddress = 0x81},
		{.bmAttributes = 2, .bEndpointAddress = 2}
	};
	static const struct libusb_interface_descriptor settings = {.bNumEndpoints = 2, .endpoint = eps};
	static const struct libusb_interface iface = {.altsetting = &settings, .num_altsetting = 1};
	static struct libusb_config_descriptor config = {.bNumInterfaces = 1, .interface = &iface};
	assert(dev);
	*out = &config;
	return 0;
}
void libusb_free_config_descriptor(struct libusb_config_descriptor *c) { (void)c; }
void libusb_close(libusb_device_handle *h) { check_handle(h); }
void libusb_exit(libusb_context *c) { (void)c; }
int libusb_bulk_transfer(libusb_device_handle *h, unsigned char ep, unsigned char *buf,
			 int len, int *actual, unsigned timeout)
{
	check_handle(h);
	assert(timeout == 60000);
	*actual = len;
	if(ep == 0x81) {
		if(fixture("read-gone") && len == 28)
			return LIBUSB_ERROR_NO_DEVICE;
		if(fixture("read-timeout") && len == 28)
			return LIBUSB_ERROR_TIMEOUT;
		memset(buf, 0, len);
		if(len == 13) memcpy(buf, "AWUS", 4);
		else if(len == 32) {
			memcpy(buf, "AWUSBFEX", 8);
			buf[9] = 3; buf[10] = 0x19;
		} else if(len == 8) {
			++ack_count;
			buf[0] = buf[1] = 0xff;
			if((ack_count == 1 && fixture("version-malformed")) ||
			   (ack_count == 2 && fixture("entry2-malformed")) ||
			   (ack_count == 4 && fixture("wdt-malformed")))
				buf[0] = 0x55;
			if((ack_count == 1 && fixture("version-rejected")) ||
			   (ack_count == 2 && fixture("entry2-rejected")) ||
			   (ack_count == 4 && fixture("wdt-rejected")))
				buf[4] = 1;
			if(ack_count == 1 && fixture("version-short"))
				*actual = 7;
		} else assert(len == 28);
	} else assert(ep == 2);
	return 0;
}
