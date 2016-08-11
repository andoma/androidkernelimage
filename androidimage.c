#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <openssl/sha.h>

#include "bootimg.h"


typedef struct loadedfile {
  void *ptr;
  size_t size;
} loadedfile_t;


static struct loadedfile
loadfile(const char *path)
{
  int fd = open(path, O_RDONLY);
  if(fd == -1) {
    fprintf(stderr, "Unable to open %s -- %s\n", path, strerror(errno));
    exit(1);
  }
  struct stat st;
  fstat(fd, &st);

  struct loadedfile lf;

  lf.size = st.st_size;
  lf.ptr = malloc(st.st_size);
  if(read(fd, lf.ptr, st.st_size) != st.st_size) {
    fprintf(stderr, "Unable to read %s -- %s\n", path, strerror(errno));
    exit(1);
  }
  close(fd);
  return lf;
}


static void
writefile(const char *path, const void *data, int size)
{
  int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0666);
  if(fd == -1) {
    fprintf(stderr, "Unable to open %s for writing -- %s",
            path, strerror(errno));
    exit(1);
  }

  if(write(fd, data, size) != size) {
    fprintf(stderr, "Unable to write to %s -- %s",
            path, strerror(errno));
    exit(1);
  }

  close(fd);
}


static void
usage(const char *argv0, const char *reason)
{
  if(reason)
    printf("\n%s\n", reason);
  printf("Usage: %s ...\n", argv0);
}



static void
printbin(const uint8_t *src, int len)
{
  int i;
  for(i = 0; i < len; i++) {
    printf("%02x", src[i]);
  }
}


#define ALIGN(a, b) (((a) + (b) - 1) & ~((b) - 1))


static void
printfile(const void *base)
{
  const struct boot_img_hdr *hdr = base;
  int magic_ok = !memcmp(hdr->magic, BOOT_MAGIC, 8);
  printf("Magic: \"%.8s\" [%s]\n", hdr->magic, magic_ok ? "OK" : "INVALID");

  if(!magic_ok) {
    exit(1);
  }

  printf("  Kernel size: 0x%08x addr: 0x%08x\n",
         hdr->kernel_size, hdr->kernel_addr);

  printf(" Ramdisk size: 0x%08x addr: 0x%08x\n",
         hdr->ramdisk_size, hdr->ramdisk_addr);

  printf("  Second size: 0x%08x addr: 0x%08x\n",
         hdr->second_size, hdr->second_addr);

  printf("    Tags addr: 0x%08x\n",
         hdr->tags_addr);

  printf("    Page size: 0x%08x (%d)\n",
         hdr->page_size, hdr->page_size);

  printf("     Name: \"%.16s\"\n", hdr->name);
  printf("  Cmdline: \"%.512s\"\n", hdr->cmdline);

  uint32_t koffset = hdr->page_size;
  uint32_t roffset = koffset + ALIGN(hdr->kernel_size, hdr->page_size);
  uint32_t soffset = roffset + ALIGN(hdr->ramdisk_size, hdr->page_size);

  printf(" File offsets: Kernel: 0x%08x  Ramdisk: 0x%08x  Second: 0x%08x\n",
         koffset, roffset, soffset);

  uint8_t digest[20];

  SHA_CTX ctx;
  SHA1_Init(&ctx);

  SHA1_Update(&ctx, base + koffset, hdr->kernel_size);
  SHA1_Update(&ctx, &hdr->kernel_size, sizeof(uint32_t));
  SHA1_Update(&ctx, base + roffset, hdr->ramdisk_size);
  SHA1_Update(&ctx, &hdr->ramdisk_size, sizeof(uint32_t));
  SHA1_Update(&ctx, base + soffset, hdr->second_size);
  SHA1_Update(&ctx, &hdr->second_size, sizeof(uint32_t));
  SHA1_Final(digest, &ctx);


  const uint8_t *storedsha = (const void *)hdr->id;
  printf("Computed SHA: ");
  printbin(digest, 20);
  printf("\n");
  printf("  Stored SHA: ");
  printbin(storedsha, 20);
  printf("\n");

  int sha_ok = !memcmp(digest, storedsha, 20);
  printf("SHA1 %s\n", sha_ok ? "MATCHES" : "NO MATCH");

}


int
main(int argc, char **argv)
{
  int opt;
  const char *kernelpath = NULL;
  const char *ramdiskpath = NULL;
  const char *secondarypath = NULL;

  const char *imagepath = NULL;

  unsigned int kerneladdr = 0;
  unsigned int ramdiskaddr = 0;
  unsigned int secondaryaddr = 0;
  int page_size = 2048;

  const char *mode = NULL;

  while((opt = getopt(argc, argv, "hi:k:r:s:K:R:S:m:")) != -1) {
    switch(opt) {
    case 'm':
      mode = optarg;
      break;
    case 'h':
      usage(argv[0], NULL);
      exit(0);
    case 'k':
      kernelpath = optarg;
      break;
    case 'r':
      ramdiskpath = optarg;
      break;
    case 's':
      secondarypath = optarg;
      break;
    case 'i':
      imagepath = optarg;
      break;

    case 'K':
      kerneladdr = strtol(optarg, NULL, 16);
      break;
    case 'R':
      ramdiskaddr = strtol(optarg, NULL, 16);
      break;
    case 'S':
      secondaryaddr = strtol(optarg, NULL, 16);
      break;


    default:
      usage(argv[0], "Unknown argument");
      exit(1);
    }
  }


  if(mode == NULL) {
    usage(argv[0], "Mode not specified");
    exit(1);
  }

  if(!strcmp(mode, "verify")) {
    loadedfile_t image = loadfile(imagepath);
    printfile(image.ptr);
    exit(0);
  }

  if(!strcmp(mode, "extract")) {
    loadedfile_t image = loadfile(imagepath);
    printfile(image.ptr);
    const struct boot_img_hdr *hdr = image.ptr;

    uint32_t koffset = hdr->page_size;
    uint32_t roffset = koffset + ALIGN(hdr->kernel_size, hdr->page_size);
    uint32_t soffset = roffset + ALIGN(hdr->ramdisk_size, hdr->page_size);

    if(kernelpath)
      writefile(kernelpath, image.ptr + koffset, hdr->kernel_size);

    if(ramdiskpath)
      writefile(ramdiskpath, image.ptr + roffset, hdr->ramdisk_size);

    if(secondarypath)
      writefile(secondarypath, image.ptr + soffset, hdr->second_size);
    exit(0);
  }


  if(!strcmp(mode, "generate")) {

    loadedfile_t kernel = loadfile(kernelpath);
    loadedfile_t ramdisk = loadfile(ramdiskpath);
    loadedfile_t secondary = loadfile(secondarypath);

    uint32_t ksize = ALIGN(kernel.size, page_size);
    uint32_t rsize = ALIGN(ramdisk.size, page_size);
    uint32_t ssize = ALIGN(secondary.size, page_size);

    void *out = calloc(1, page_size + ksize + rsize + ssize);

    struct boot_img_hdr *hdr = out;
    memcpy(hdr->magic, BOOT_MAGIC, 8);

    hdr->kernel_size = kernel.size;
    hdr->kernel_addr = kerneladdr;

    hdr->ramdisk_size = ramdisk.size;
    hdr->ramdisk_addr = ramdiskaddr;

    hdr->second_size = secondary.size;
    hdr->second_addr = secondaryaddr;

    hdr->tags_addr = 0x100;
    hdr->page_size = page_size;

    uint32_t koffset = hdr->page_size;
    uint32_t roffset = koffset  + ALIGN(hdr->kernel_size, hdr->page_size);
    uint32_t soffset = roffset  + ALIGN(hdr->ramdisk_size, hdr->page_size);
    uint32_t filesize = soffset + ALIGN(hdr->second_size, hdr->page_size);
    memcpy(out + koffset, kernel.ptr, kernel.size);
    memcpy(out + roffset, ramdisk.ptr, ramdisk.size);
    memcpy(out + soffset, secondary.ptr, secondary.size);

    void *base = out;

    SHA_CTX ctx;
    SHA1_Init(&ctx);

    SHA1_Update(&ctx, base + koffset, hdr->kernel_size);
    SHA1_Update(&ctx, &hdr->kernel_size, sizeof(uint32_t));
    SHA1_Update(&ctx, base + roffset, hdr->ramdisk_size);
    SHA1_Update(&ctx, &hdr->ramdisk_size, sizeof(uint32_t));
    SHA1_Update(&ctx, base + soffset, hdr->second_size);
    SHA1_Update(&ctx, &hdr->second_size, sizeof(uint32_t));
    SHA1_Final((void *)&hdr->id[0], &ctx);


    writefile(imagepath, out, filesize);
    printfile(out);
    exit(0);
  }



  usage(argv[0], "Unknown mode");
  exit(1);
}
