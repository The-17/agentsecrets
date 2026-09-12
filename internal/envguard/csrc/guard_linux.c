/* env-guard: an LD_PRELOAD interposer for `agentsecrets env` children (Linux).
 *
 * Two jobs, both best-effort:
 *
 *   1. Mark the process non-dumpable, so no other process running as the same
 *      user can read its environment via /proc/<pid>/environ or its memory via
 *      /proc/<pid>/mem. This runs in the child after execve (a launcher shim
 *      cannot do it: execve resets the dumpable flag).
 *
 *   2. Redact secret values from what the process writes, replacing them with
 *      [REDACTED].
 *
 * The secret parsing and redaction (parse_secrets, redact) live in guard_common.h,
 * shared verbatim with the macOS interposer. This file provides only the pieces
 * that are Linux-specific: how the write path is hooked (ELF symbol precedence)
 * and how the process is made non-dumpable (prctl).
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <unistd.h>

#include "guard_common.h"

__attribute__((constructor)) static void guard_init(void) {
	prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
	parse_secrets();
}

ssize_t write(int fd, const void *buf, size_t n) {
	static ssize_t (*real)(int, const void *, size_t);
	if (!real) {
		real = dlsym(RTLD_NEXT, "write");
	}
	if (g_count == 0 || (fd != 1 && fd != 2)) {
		return real(fd, buf, n);
	}
	char *t = malloc(n + REPLACEMENT_LEN);
	if (!t) {
		return real(fd, buf, n);
	}
	memcpy(t, buf, n);
	size_t l = redact(t, n);
	ssize_t r = real(fd, t, l);
	free(t);
	return r < 0 ? r : (ssize_t)n;
}

ssize_t writev(int fd, const struct iovec *iov, int cnt) {
	static ssize_t (*real)(int, const struct iovec *, int);
	if (!real) {
		real = dlsym(RTLD_NEXT, "writev");
	}
	if (g_count == 0 || (fd != 1 && fd != 2)) {
		return real(fd, iov, cnt);
	}
	size_t tot = 0;
	for (int i = 0; i < cnt; i++) {
		tot += iov[i].iov_len;
	}
	char *t = malloc(tot + REPLACEMENT_LEN);
	if (!t) {
		return real(fd, iov, cnt);
	}
	size_t o = 0;
	for (int i = 0; i < cnt; i++) {
		memcpy(t + o, iov[i].iov_base, iov[i].iov_len);
		o += iov[i].iov_len;
	}
	size_t l = redact(t, tot);
	struct iovec one = {t, l};
	ssize_t r = real(fd, &one, 1);
	free(t);
	return r < 0 ? r : (ssize_t)tot;
}

size_t fwrite(const void *p, size_t sz, size_t nm, FILE *f) {
	static size_t (*real)(const void *, size_t, size_t, FILE *);
	if (!real) {
		real = dlsym(RTLD_NEXT, "fwrite");
	}
	size_t tot = sz * nm;
	if (!tot || g_count == 0) {
		return real(p, sz, nm, f);
	}
	char *t = malloc(tot + REPLACEMENT_LEN);
	if (!t) {
		return real(p, sz, nm, f);
	}
	memcpy(t, p, tot);
	size_t l = redact(t, tot);
	size_t r = real(t, 1, l, f);
	free(t);
	return r ? nm : 0;
}

int fputs(const char *s, FILE *f) {
	static int (*real)(const char *, FILE *);
	if (!real) {
		real = dlsym(RTLD_NEXT, "fputs");
	}
	if (!s || g_count == 0) {
		return real(s, f);
	}
	size_t n = strlen(s);
	char *t = malloc(n + REPLACEMENT_LEN);
	if (!t) {
		return real(s, f);
	}
	memcpy(t, s, n);
	size_t l = redact(t, n);
	int r = real(t, f);
	free(t);
	return r;
}

int puts(const char *s) {
	static int (*real)(const char *);
	if (!real) {
		real = dlsym(RTLD_NEXT, "puts");
	}
	if (!s || g_count == 0) {
		return real(s);
	}
	size_t n = strlen(s);
	char *t = malloc(n + REPLACEMENT_LEN);
	if (!t) {
		return real(s);
	}
	memcpy(t, s, n);
	size_t l = redact(t, n);
	int r = real(t);
	free(t);
	return r;
}
