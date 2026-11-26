/*
 * Signed firmware updates with roll back, on the release channel's format
 * (docs/UPDATE-MANIFEST.md): a targets document, signed by the release key in
 * an envelope, names each platform's image by length and SHA-256. A device
 * takes an image only from a targets document the release key signed, whose
 * version is above the one it installed last, with an entry for its own
 * platform; it then writes the image to its spare slot, checks the digest
 * as it writes, and boots it on trial. The bootloader goes back to the old
 * image unless the new one marks itself good after reaching a node.
 */
#ifndef TENZRO_UPDATE_H
#define TENZRO_UPDATE_H

#include <stddef.h>
#include <stdint.h>

#include "tenzro/sign.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The name a firmware image carries in a targets document. */
#define TZ_FIRMWARE_NAME "firmware"
/* Longest release, platform and image path a device takes. */
#define TZ_UPDATE_RELEASE_MAX 32
#define TZ_UPDATE_PLATFORM_MAX 64
#define TZ_UPDATE_PATH_MAX 128
/*
 * Room for the signed bytes of a targets document the device takes, with the
 * domain before them: tz_update_target_of needs this much scratch.
 */
#define TZ_UPDATE_SCRATCH_MAX 4096

/* The image a targets document names for this device. */
typedef struct {
    /* The document's version: stored once the image is good, the floor for the next one. */
    uint64_t version;
    /* The release, `major.minor.patch`. */
    char release[TZ_UPDATE_RELEASE_MAX + 1];
    /* Where the image is, under the channel's base URL. */
    char path[TZ_UPDATE_PATH_MAX + 1];
    uint64_t length;
    uint8_t sha256[32];
} tz_update_target;

/*
 * Checks a targets envelope (`envelope`, the file as served) against the
 * release key `release_key` (0x04 || x || y) and finds the image for
 * `platform` (named as the channel names it, e.g. `xtensa-esp32s3`).
 * `installed_version` is the version of the document the running image came
 * from (0 on a device that never updated): a document not above it is
 * refused. `scratch` holds the decoded document while it is read.
 */
tz_status tz_update_target_of(const char *envelope, size_t envelope_len,
                              const uint8_t release_key[65],
                              const char *platform, uint64_t installed_version,
                              uint8_t *scratch, size_t scratch_len,
                              tz_update_target *target);

#ifdef __cplusplus
}
#endif

#endif
