/* env-guard: a DYLD_INSERT_LIBRARIES interposer for `agentsecrets env` children
 * (macOS).
 *
 * The mirror of guard_linux.c. It shares the secret parsing and redaction in
 * guard_common.h verbatim; only the platform mechanics differ:
 *
 *   1. Hooking. macOS does not resolve interposers by symbol precedence like ELF.
 *      Replacements are registered in a __DATA,__interpose section via the
 *      DYLD_INTERPOSE macro; dyld then swaps the bindings in every other image.
 *      Each replacement reaches the real libc function through dlsym(RTLD_NEXT),
 *      exactly as on Linux, so it never recurses into itself.
 *
 *   2. Un-attachability. macOS has no PR_SET_DUMPABLE. ptrace(PT_DENY_ATTACH)
 *      sets P_LNOATTACH on this process, which makes task_for_pid() and ptrace()
 *      against it fail for a same-user caller. Reading another process's memory
 *      on macOS already requires task_for_pid (root or the debugger entitlement),
 *      so this is defense in depth on top of an OS control, not the only lock.
 *
 * Attaching at all requires dyld to honour DYLD_INSERT_LIBRARIES: it is ignored
 * for hardened-runtime and SIP-protected binaries. The parent detects that case
 * (see machoHardened in env_sysproc_darwin.go) and warns; the child still runs.
 */

#define _DARWIN_C_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "guard_common.h"

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

/* Declared here rather than via <sys/ptrace.h>: on macOS the prototype is not
 * exposed by default, but the symbol is present in libSystem. */
extern int ptrace(int request, pid_t pid, caddr_t addr, int data);

/* DYLD_INTERPOSE registers (replacement, original) in the __interpose section so
 * dyld rebinds calls to `original` onto `replacement` across the process. */
#define DYLD_INTERPOSE(_repl, _orig)                                              \
	__attribute__((used)) static struct {                                         \
		const void *repl;                                                         \
		const void *orig;                                                         \
	} _interpose_##_orig __attribute__((section("__DATA,__interpose"))) = {        \
		(const void *)(unsigned long)&_repl, (const void *)(unsigned long)&_orig};

__attribute__((constructor)) static void guard_init(void) {
	ptrace(PT_DENY_ATTACH, 0, 0, 0);
	parse_secrets();
}

static ssize_t guard_write(int fd, const void *buf, size_t n) {
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
DYLD_INTERPOSE(guard_write, write)

static ssize_t guard_writev(int fd, const struct iovec *iov, int cnt) {
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
DYLD_INTERPOSE(guard_writev, writev)

static size_t guard_fwrite(const void *p, size_t sz, size_t nm, FILE *f) {
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
DYLD_INTERPOSE(guard_fwrite, fwrite)

static int guard_fputs(const char *s, FILE *f) {
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
DYLD_INTERPOSE(guard_fputs, fputs)

static int guard_puts(const char *s) {
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
DYLD_INTERPOSE(guard_puts, puts)
