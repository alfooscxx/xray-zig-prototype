#define _GNU_SOURCE

#include <errno.h>
#include <linux/if_alg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

enum {
    block_len = 16 * 1024,
    total_len = 32 * 1024 * 1024,
    tag_len = 16,
    iv_len = 12,
};

static unsigned char plaintext[block_len];
static unsigned char ciphertext[block_len + tag_len];
static unsigned char decrypted[block_len];

static void fail(const char *operation) {
    fprintf(stderr, "%s: %s\n", operation, strerror(errno));
    exit(1);
}

static void crypt_record(int fd, uint32_t operation, const unsigned char *input,
                         size_t input_len, unsigned char *output,
                         size_t output_len) {
    unsigned char control[CMSG_SPACE(sizeof(uint32_t)) +
                          CMSG_SPACE(sizeof(struct af_alg_iv) + iv_len) +
                          CMSG_SPACE(sizeof(uint32_t))];
    struct iovec iov = {.iov_base = (void *)input, .iov_len = input_len};
    struct msghdr message = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };
    memset(control, 0, sizeof(control));

    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_ALG;
    header->cmsg_type = ALG_SET_OP;
    header->cmsg_len = CMSG_LEN(sizeof(operation));
    memcpy(CMSG_DATA(header), &operation, sizeof(operation));

    header = CMSG_NXTHDR(&message, header);
    header->cmsg_level = SOL_ALG;
    header->cmsg_type = ALG_SET_IV;
    header->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + iv_len);
    struct af_alg_iv *iv = (struct af_alg_iv *)CMSG_DATA(header);
    iv->ivlen = iv_len;
    memset(iv->iv, 0x24, iv_len);

    header = CMSG_NXTHDR(&message, header);
    header->cmsg_level = SOL_ALG;
    header->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    header->cmsg_len = CMSG_LEN(sizeof(uint32_t));
    uint32_t assoc_len = 0;
    memcpy(CMSG_DATA(header), &assoc_len, sizeof(assoc_len));

    if (sendmsg(fd, &message, 0) != (ssize_t)input_len)
        fail("sendmsg");

    size_t received = 0;
    while (received < output_len) {
        ssize_t result = read(fd, output + received, output_len - received);
        if (result <= 0)
            fail("read");
        received += (size_t)result;
    }
}

static double elapsed_seconds(struct timespec start, struct timespec end) {
    return (double)(end.tv_sec - start.tv_sec) +
           (double)(end.tv_nsec - start.tv_nsec) / 1000000000.0;
}

int main(int argc, char **argv) {
    const char *algorithm = argc > 1 ? argv[1] : "gcm(aes)";
    int transform = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (transform < 0)
        fail("socket(AF_ALG)");

    struct sockaddr_alg address = {.salg_family = AF_ALG};
    memcpy(address.salg_type, "aead", sizeof("aead"));
    if (strlen(algorithm) >= sizeof(address.salg_name)) {
        fprintf(stderr, "algorithm name too long\n");
        return 1;
    }
    memcpy(address.salg_name, algorithm, strlen(algorithm) + 1);
    if (bind(transform, (struct sockaddr *)&address, sizeof(address)) != 0)
        fail("bind(AF_ALG)");

    unsigned char key[16];
    memset(key, 0x42, sizeof(key));
    if (setsockopt(transform, SOL_ALG, ALG_SET_KEY, key, sizeof(key)) != 0)
        fail("setsockopt(ALG_SET_KEY)");
    if (setsockopt(transform, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, tag_len) != 0)
        fail("setsockopt(ALG_SET_AEAD_AUTHSIZE)");

    int operation = accept(transform, NULL, NULL);
    if (operation < 0)
        fail("accept(AF_ALG)");

    for (size_t index = 0; index < sizeof(plaintext); ++index)
        plaintext[index] = (unsigned char)(index * 131 + 17);

    struct timespec started;
    struct timespec finished;
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0)
        fail("clock_gettime");
    for (size_t processed = 0; processed < total_len; processed += block_len) {
        crypt_record(operation, ALG_OP_ENCRYPT, plaintext, block_len, ciphertext,
                     sizeof(ciphertext));
        crypt_record(operation, ALG_OP_DECRYPT, ciphertext, sizeof(ciphertext),
                     decrypted, sizeof(decrypted));
    }
    if (clock_gettime(CLOCK_MONOTONIC, &finished) != 0)
        fail("clock_gettime");
    if (memcmp(plaintext, decrypted, sizeof(plaintext)) != 0) {
        fprintf(stderr, "decrypted plaintext mismatch\n");
        return 1;
    }

    const double bytes = (double)total_len * 2.0;
    const double mib_per_second =
        bytes / elapsed_seconds(started, finished) / (1024.0 * 1024.0);
    printf("algorithm=%s block_bytes=%d %.2f MiB/s\n", algorithm, block_len,
           mib_per_second);
    close(operation);
    close(transform);
    return 0;
}
