/* Test-only interception of one file in one child VM. This holds the real
 * close call inside prim_file.close_nif; it does not simulate a kernel stall. */
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int delayed_close(int fd) {
  const char *target = getenv("HTTP_FETCH_NATIVE_CLOSE_TARGET");
  struct stat expected, actual;

  if (target && stat(target, &expected) == 0 && fstat(fd, &actual) == 0 &&
      expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino) {
    const char *entered = getenv("HTTP_FETCH_NATIVE_CLOSE_ENTERED");
    const char *release = getenv("HTTP_FETCH_NATIVE_CLOSE_RELEASE");

    if (entered && release) {
      int marker = open(entered, O_WRONLY | O_CREAT | O_EXCL, 0600);

      if (marker >= 0) {
        struct timespec start, current, pause = {0, 1000000};
        (void)write(marker, "C", 1);
        (void)close(marker);
        (void)clock_gettime(CLOCK_MONOTONIC, &start);

        do {
          if (access(release, F_OK) == 0) break;
          (void)nanosleep(&pause, NULL);
          (void)clock_gettime(CLOCK_MONOTONIC, &current);
        } while (current.tv_sec - start.tv_sec < 10);
      }
    }
  }

#ifdef __APPLE__
  /* dyld keeps this library's own references bound to the original function. */
  return close(fd);
#else
  typedef int (*close_fn)(int);
  close_fn original = (close_fn)dlsym(RTLD_NEXT, "close");
  return original(fd);
#endif
}

#ifdef __APPLE__
__attribute__((used)) static struct {
  const void *replacement;
  const void *original;
} interpose_close __attribute__((section("__DATA,__interpose"))) = {
    (const void *)delayed_close, (const void *)close};
#else
int close(int fd) { return delayed_close(fd); }
#endif
