/* otptool.c: Decrypt and print info about an OTP. */

#define GCRYPT_NO_DEPRECATED
#include <gcrypt.h>

#ifdef _WIN32
	#include <openssl/err.h>
#else
	#include <err.h>
#endif

#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "ec.h"

static const char *prog_name = "otptool";

/* Struct for OTP data. */
typedef struct {
    uint32_t magic;
    uint32_t device_id;
    uint8_t keyY[0x10];
    uint8_t version;
    bool is_dev;
    struct tm manu_tm;
    time_t expiry;
    uint8_t ec_privk[0x20];
    uint8_t cert_sig[0x3C];
} otp_t;

static uint32_t load32_le(const uint8_t a[4]) {
    return (uint32_t)a[0]
        | ((uint32_t)a[1] <<  8)
        | ((uint32_t)a[2] << 16)
        | ((uint32_t)a[3] << 24);
}

static uint32_t load32_be(const uint8_t a[4]) {
    return (uint32_t)a[3]
        | ((uint32_t)a[2] <<  8)
        | ((uint32_t)a[1] << 16)
        | ((uint32_t)a[0] << 24);
}

static void store32_be(uint8_t a[4], uint32_t n)
{
    a[3] =  n        & 0xff;
    a[2] = (n >>  8) & 0xff;
    a[1] = (n >> 16) & 0xff;
    a[0] = (n >> 24) & 0xff;
}

static int read_and_decrypt_otp(const char *path, uint8_t otp[0x100], bool is_dev) {
    FILE *f = NULL;
    uint8_t myhash[0x20], *theirhash = otp + 0xe0;
    const uint8_t *otp_key, *otp_iv;
    gcry_cipher_hd_t c = NULL;
    int ret = -1;
    const uint8_t otp_key_retail[0x10] = {
        0x06, 0x45, 0x79, 0x01, 0xd4, 0x85, 0xa3, 0x67,
        0xac, 0x4f, 0x2a, 0xd0, 0x1c, 0x53, 0xcf, 0x74
    };
    const uint8_t otp_iv_retail[0x10] = {
        0xba, 0x4f, 0x59, 0x9b, 0x0a, 0xe1, 0x12, 0x2c,
        0x80, 0xe1, 0x3f, 0x68, 0x65, 0xc4, 0xfa, 0x49
    };
    const uint8_t otp_key_dev[0x10] = {
        0x9c, 0xea, 0x65, 0x6e, 0x96, 0x28, 0x7b, 0xc1,
        0x8f, 0xd7, 0xd4, 0xbb, 0xd4, 0x58, 0x72, 0x70
    };
    const uint8_t otp_iv_dev[0x10] = {
        0x3e, 0x00, 0x9a, 0xfb, 0xb8, 0x5f, 0x13, 0x62,
        0x72, 0x68, 0x75, 0x7c, 0xe3, 0xb4, 0xbe, 0xcc
    };

    if (is_dev) {
        otp_key = otp_key_dev;
        otp_iv = otp_iv_dev;
    } else {
        otp_key = otp_key_retail;
        otp_iv = otp_iv_retail;
    }

    if ((f = fopen(path, "rb")) == NULL) {
        fprintf(stderr, "cannot open %s\n", path);
        goto clean;
    }
    if (fread(otp, 0x100, 1, f) < 1) {
        fprintf(stderr, "cannot read %s\n", path);
        goto clean;
    }

    if (load32_le(otp + 0x00) == 0xdeadb00fUL) {
        printf("Found OTP magic; assuming decrypted dump.\n");
    } else {
        if (gcry_cipher_open(&c, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0) != 0) {
            fprintf(stderr, "unable to open cipher\n");
            goto clean;
        }
        if (gcry_cipher_setkey(c, otp_key, 0x10) != 0) {
            fprintf(stderr, "unable to set OTP key\n");
            goto clean;
        }
        if (gcry_cipher_setiv(c, otp_iv, 0x10) != 0) {
            fprintf(stderr, "unable to set OTP IV\n");
            goto clean;
        }
        if (gcry_cipher_final(c) != 0) {
            fprintf(stderr, "unable to set final\n");
            goto clean;
        }
        if (gcry_cipher_decrypt(c, otp, 0x100, NULL, 0) != 0) {
            fprintf(stderr, "unable to decrypt OTP\n");
            goto clean;
        }
    }

    if (load32_le(otp + 0x00) != 0xdeadb00fUL) {
        fprintf(stderr, "OTP magic mismatch\n");
        goto clean;
    }

    gcry_md_hash_buffer(GCRY_MD_SHA256, myhash, otp, 0xe0);

    if (memcmp(myhash, theirhash, 0x20) != 0) {
        fprintf(stderr, "OTP hash mismatch\n");
        goto clean;
    }

    ret = 0;
clean:
    if (f != NULL) {
        fclose(f);
    }
    if (c != NULL) {
        gcry_cipher_close(c);
    }
    return ret;
}

static void hexdump(const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; ++i)
        printf("%02x", *data++);
}

static void parse_dec_otp(otp_t *otp, const uint8_t rawotp[0x100]) {
    memset(otp, 0, sizeof(*otp));

    memset(&otp->manu_tm, 0, sizeof(otp->manu_tm));
    otp->magic = load32_le(rawotp + 0x00);
    otp->device_id = load32_le(rawotp + 0x04);
    memcpy(otp->keyY, rawotp + 0x08, 0x10);
    otp->version = rawotp[0x18];
    otp->is_dev = (rawotp[0x19] != 0);
    otp->manu_tm.tm_sec = rawotp[0x1f];
    otp->manu_tm.tm_min = rawotp[0x1e];
    otp->manu_tm.tm_hour = rawotp[0x1d];
    otp->manu_tm.tm_mday = rawotp[0x1c];
    otp->manu_tm.tm_mon = rawotp[0x1b];
    otp->manu_tm.tm_year = rawotp[0x1a];
    otp->expiry = (rawotp[0x18] < 5) ? load32_be(rawotp + 0x20) : load32_le(rawotp + 0x20);
    memcpy(otp->ec_privk, rawotp + 0x24, 0x20);
    memcpy(otp->cert_sig, rawotp + 0x44, 0x3C);
}

static void print_otp_info(const otp_t *otp) {
    printf("Device ID:     0x%08x\n", otp->device_id);
    printf("Fallback keyY: ");
    hexdump(otp->keyY, 0x10);
    puts("");
    printf("Version:       %03u\n", otp->version);
    printf("Is dev unit:   %s\n", otp->is_dev ? "true" : "false");
    printf("Manufactured:  %s", asctime(&otp->manu_tm));
    printf("CTCert expiry: %s", ctime(&otp->expiry));
    printf("EC PrivKey:    ");
    hexdump(otp->ec_privk, sizeof(otp->ec_privk));
    puts("");
    printf("Signature:     ");
    hexdump(otp->cert_sig, sizeof(otp->cert_sig));
    puts("");
}

static void convert_otp_to_device_cert(unsigned char cert[0x180], const otp_t *otp) {
    char buf[0x40];

    memset(cert, 0, 0x180);
    memset(buf, 0, sizeof(buf));
    /* signature type: ECC 512-bits over SHA-256 */
    cert[0] = 0x00;
    cert[1] = 0x01;
    cert[2] = 0x00;
    cert[3] = 0x05;
    memcpy(cert + 4, otp->cert_sig, sizeof(otp->cert_sig));
    strcpy((char *)cert + 0x80,
            otp->is_dev ?
            "Nintendo CA - G3_NintendoCTR2dev" :
            "Nintendo CA - G3_NintendoCTR2prod");
    /* hard-coded value 2 that's been static since the Wii */
    /* (see http://git.infradead.org/users/segher/wii.git twintig.c) */
    cert[0xC3] = 2;
    snprintf(buf, sizeof(buf), "CT%08X-%02X", otp->device_id, otp->is_dev);
    memcpy(cert + 0xC4, buf, sizeof(buf));
    store32_be(cert + 0x104, (uint32_t)otp->expiry);
    ec_priv_to_pub(otp->ec_privk + 2, cert + 0x108);

#if 0
    /* TODO: verify cert; public key obtained from Process9 NintendoCTR2prod cert, but seems wrong? */
    unsigned char certhash[0x20];
    gcry_md_hash_buffer(GCRY_MD_SHA256, certhash, cert + 0x80, 0x100);
    uint8_t Q[] = {
        0x00, 0x4e, 0x3b, 0xb7, 0x4d, 0x5d, 0x95, 0x9e, 0x68, 0xce, 0x90, 0x04, 0x34, 0xfe, 0x9e, 0x4a, 0x3f, 0x09, 0x4a, 0x33, 0x77, 0x1f, 0xa7, 0xc0, 0xe4, 0xb0, 0x23, 0x26, 0x4d, 0x98, 0x01, 0x4c, 0xa1, 0xfc, 0x79, 0x9d, 0x3f, 0xa5, 0x21, 0x71, 0xd5, 0xf9, 0xbd, 0x5b, 0x17, 0x77, 0xec, 0x0f, 0xef, 0x7a, 0x38, 0xd1, 0x66, 0x9b, 0xbf, 0x83, 0x03, 0x25, 0x84, 0x3a
    };
    printf("%d\n", check_ecdsa(Q, otp->cert_sig + 30, otp->cert_sig, certhash));
#endif
}

static int save_file(const char *path, const char *desc, const unsigned char *data, size_t len) {
    FILE *f = NULL;
    int ret = -1;

    if ((f = fopen(path, "wb")) == NULL) {
        fprintf(stderr, "unable to open %s for writing\n", path);
        goto clean;
    }
    if (fwrite(data, len, 1, f) < 1) {
        fprintf(stderr, "error writing %s\n", desc);
        goto clean;
    }
    printf("wrote decrypted OTP to %s\n", path);

    ret = 0;
clean:
    if (f != NULL) {
        fclose(f);
    }
    return ret;
}

static _Noreturn void usage(const char *prog, int status) {
        fprintf(stderr, "usage: %s [-c ctcert_out] [-d decrypted_otp_out] [-D] otp\n\n"
                " -c [ctcert_out]           if given, writes the CTCert to given path\n"
                " -d [decrypted_otp_out]    if given, writes the decrypted OTP to given path\n"
                " -D                        use dev key instead of retail\n"
                " -h                        prints this message and exits\n",
                prog);
        exit(status);
}

int main(int argc, char *argv[]) {
    const char *ctcert_out = NULL, *decrypted_otp_out = NULL;
    unsigned char rawotp[0x100];
    unsigned char cert[0x180];
    otp_t otp;
    int ch, ret = EXIT_SUCCESS;
    bool is_dev = false;
	
	prog_name = (argc < 1) ? "otptool" : argv[0];

    if (gcry_check_version("1.4.0") == NULL) {
        fprintf(stderr, "libgcrypt >= 1.4.0 required\n");
        return EXIT_FAILURE;
    }
    if (gcry_control(GCRYCTL_DISABLE_SECMEM, 0) != 0) {
        fprintf(stderr, "unable to disable gcrypt paranoia\n");
        return EXIT_FAILURE;
    }
    if (gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0) != 0) {
        fprintf(stderr, "unable to finish gcrypt initialization\n");
        return EXIT_FAILURE;
    }

    while ((ch = getopt(argc, argv, "c:d:Dh")) != -1) {
        switch (ch) {
        case 'c':
            ctcert_out = optarg;
            break;
        case 'd':
            decrypted_otp_out = optarg;
            break;
        case 'D':
            is_dev = true;
            break;
        case 'h':
            usage(prog_name, EXIT_SUCCESS);
        default:
            usage(prog_name, EXIT_FAILURE);
        }
    }
    argc -= optind;
    argv += optind;
    
	
    if (argc < 1) {
        usage(prog_name, EXIT_FAILURE);
    }

    if (read_and_decrypt_otp(argv[0], rawotp, is_dev) != 0) {
        return EXIT_FAILURE;
    }
    parse_dec_otp(&otp, rawotp);
    print_otp_info(&otp);
    if (decrypted_otp_out != NULL) {
        if (save_file(decrypted_otp_out, "decrypted OTP", rawotp, sizeof(rawotp)) == 0) {
            ret = EXIT_SUCCESS;
        } else {
            ret = EXIT_FAILURE;
        }
    }

    if (ctcert_out != NULL) {
        convert_otp_to_device_cert(cert, &otp);
        if (save_file(ctcert_out, "CTCert", cert, sizeof(cert)) == 0) {
            ret = EXIT_SUCCESS;
        } else {
            ret = EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

