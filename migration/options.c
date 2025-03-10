/*
 * QEMU migration capabilities
 *
 * Copyright (c) 2012-2023 Red Hat Inc
 *
 * Authors:
 *   Orit Wasserman <owasserm@redhat.com>
 *   Juan Quintela <quintela@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "exec/target_page.h"
#include "qapi/clone-visitor.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-migration.h"
#include "qapi/qapi-visit-migration.h"
#include "qapi/qmp/qerror.h"
#include "qapi/qmp/qnull.h"
#include "sysemu/runstate.h"
#include "migration/colo.h"
#include "migration/misc.h"
#include "migration.h"
#include "qemu-file.h"
#include "ram.h"
#include "options.h"

/* Maximum migrate downtime set to 2000 seconds */
#define MAX_MIGRATE_DOWNTIME_SECONDS 2000
#define MAX_MIGRATE_DOWNTIME (MAX_MIGRATE_DOWNTIME_SECONDS * 1000)

bool migrate_auto_converge(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_AUTO_CONVERGE];
}

bool migrate_background_snapshot(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_BACKGROUND_SNAPSHOT];
}

bool migrate_block(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_BLOCK];
}

bool migrate_colo(void)
{
    MigrationState *s = migrate_get_current();
    return s->capabilities[MIGRATION_CAPABILITY_X_COLO];
}

bool migrate_compress(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_COMPRESS];
}

bool migrate_dirty_bitmaps(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_DIRTY_BITMAPS];
}

bool migrate_events(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_EVENTS];
}

bool migrate_ignore_shared(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_X_IGNORE_SHARED];
}

bool migrate_late_block_activate(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_LATE_BLOCK_ACTIVATE];
}

bool migrate_multifd(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_MULTIFD];
}

bool migrate_pause_before_switchover(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_PAUSE_BEFORE_SWITCHOVER];
}

bool migrate_postcopy_blocktime(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_POSTCOPY_BLOCKTIME];
}

bool migrate_postcopy_preempt(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_POSTCOPY_PREEMPT];
}

bool migrate_postcopy_ram(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_POSTCOPY_RAM];
}

bool migrate_rdma_pin_all(void)
{
    MigrationState *s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_RDMA_PIN_ALL];
}

bool migrate_release_ram(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_RELEASE_RAM];
}

bool migrate_return_path(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_RETURN_PATH];
}

bool migrate_validate_uuid(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_VALIDATE_UUID];
}

bool migrate_xbzrle(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_XBZRLE];
}

bool migrate_zero_blocks(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_ZERO_BLOCKS];
}

bool migrate_zero_copy_send(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->capabilities[MIGRATION_CAPABILITY_ZERO_COPY_SEND];
}

/* pseudo capabilities */

bool migrate_postcopy(void)
{
    return migrate_postcopy_ram() || migrate_dirty_bitmaps();
}

bool migrate_tls(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.tls_creds && *s->parameters.tls_creds;
}

typedef enum WriteTrackingSupport {
    WT_SUPPORT_UNKNOWN = 0,
    WT_SUPPORT_ABSENT,
    WT_SUPPORT_AVAILABLE,
    WT_SUPPORT_COMPATIBLE
} WriteTrackingSupport;

static
WriteTrackingSupport migrate_query_write_tracking(void)
{
    /* Check if kernel supports required UFFD features */
    if (!ram_write_tracking_available()) {
        return WT_SUPPORT_ABSENT;
    }
    /*
     * Check if current memory configuration is
     * compatible with required UFFD features.
     */
    if (!ram_write_tracking_compatible()) {
        return WT_SUPPORT_AVAILABLE;
    }

    return WT_SUPPORT_COMPATIBLE;
}

/* Migration capabilities set */
struct MigrateCapsSet {
    int size;                       /* Capability set size */
    MigrationCapability caps[];     /* Variadic array of capabilities */
};
typedef struct MigrateCapsSet MigrateCapsSet;

/* Define and initialize MigrateCapsSet */
#define INITIALIZE_MIGRATE_CAPS_SET(_name, ...)   \
    MigrateCapsSet _name = {    \
        .size = sizeof((int []) { __VA_ARGS__ }) / sizeof(int), \
        .caps = { __VA_ARGS__ } \
    }

/* Background-snapshot compatibility check list */
static const
INITIALIZE_MIGRATE_CAPS_SET(check_caps_background_snapshot,
    MIGRATION_CAPABILITY_POSTCOPY_RAM,
    MIGRATION_CAPABILITY_DIRTY_BITMAPS,
    MIGRATION_CAPABILITY_POSTCOPY_BLOCKTIME,
    MIGRATION_CAPABILITY_LATE_BLOCK_ACTIVATE,
    MIGRATION_CAPABILITY_RETURN_PATH,
    MIGRATION_CAPABILITY_MULTIFD,
    MIGRATION_CAPABILITY_PAUSE_BEFORE_SWITCHOVER,
    MIGRATION_CAPABILITY_AUTO_CONVERGE,
    MIGRATION_CAPABILITY_RELEASE_RAM,
    MIGRATION_CAPABILITY_RDMA_PIN_ALL,
    MIGRATION_CAPABILITY_COMPRESS,
    MIGRATION_CAPABILITY_XBZRLE,
    MIGRATION_CAPABILITY_X_COLO,
    MIGRATION_CAPABILITY_VALIDATE_UUID,
    MIGRATION_CAPABILITY_ZERO_COPY_SEND);

/**
 * @migration_caps_check - check capability compatibility
 *
 * @old_caps: old capability list
 * @new_caps: new capability list
 * @errp: set *errp if the check failed, with reason
 *
 * Returns true if check passed, otherwise false.
 */
bool migrate_caps_check(bool *old_caps, bool *new_caps, Error **errp)
{
    MigrationIncomingState *mis = migration_incoming_get_current();

    ERRP_GUARD();
#ifndef CONFIG_LIVE_BLOCK_MIGRATION
    if (new_caps[MIGRATION_CAPABILITY_BLOCK]) {
        error_setg(errp, "QEMU compiled without old-style (blk/-b, inc/-i) "
                   "block migration");
        error_append_hint(errp, "Use drive_mirror+NBD instead.\n");
        return false;
    }
#endif

#ifndef CONFIG_REPLICATION
    if (new_caps[MIGRATION_CAPABILITY_X_COLO]) {
        error_setg(errp, "QEMU compiled without replication module"
                   " can't enable COLO");
        error_append_hint(errp, "Please enable replication before COLO.\n");
        return false;
    }
#endif

    if (new_caps[MIGRATION_CAPABILITY_POSTCOPY_RAM]) {
        /* This check is reasonably expensive, so only when it's being
         * set the first time, also it's only the destination that needs
         * special support.
         */
        if (!old_caps[MIGRATION_CAPABILITY_POSTCOPY_RAM] &&
            runstate_check(RUN_STATE_INMIGRATE) &&
            !postcopy_ram_supported_by_host(mis, errp)) {
            error_prepend(errp, "Postcopy is not supported: ");
            return false;
        }

        if (new_caps[MIGRATION_CAPABILITY_X_IGNORE_SHARED]) {
            error_setg(errp, "Postcopy is not compatible with ignore-shared");
            return false;
        }

        if (new_caps[MIGRATION_CAPABILITY_MULTIFD]) {
            error_setg(errp, "Postcopy is not yet compatible with multifd");
            return false;
        }
    }

    if (new_caps[MIGRATION_CAPABILITY_BACKGROUND_SNAPSHOT]) {
        WriteTrackingSupport wt_support;
        int idx;
        /*
         * Check if 'background-snapshot' capability is supported by
         * host kernel and compatible with guest memory configuration.
         */
        wt_support = migrate_query_write_tracking();
        if (wt_support < WT_SUPPORT_AVAILABLE) {
            error_setg(errp, "Background-snapshot is not supported by host kernel");
            return false;
        }
        if (wt_support < WT_SUPPORT_COMPATIBLE) {
            error_setg(errp, "Background-snapshot is not compatible "
                    "with guest memory configuration");
            return false;
        }

        /*
         * Check if there are any migration capabilities
         * incompatible with 'background-snapshot'.
         */
        for (idx = 0; idx < check_caps_background_snapshot.size; idx++) {
            int incomp_cap = check_caps_background_snapshot.caps[idx];
            if (new_caps[incomp_cap]) {
                error_setg(errp,
                        "Background-snapshot is not compatible with %s",
                        MigrationCapability_str(incomp_cap));
                return false;
            }
        }
    }

#ifdef CONFIG_LINUX
    if (new_caps[MIGRATION_CAPABILITY_ZERO_COPY_SEND] &&
        (!new_caps[MIGRATION_CAPABILITY_MULTIFD] ||
         new_caps[MIGRATION_CAPABILITY_COMPRESS] ||
         new_caps[MIGRATION_CAPABILITY_XBZRLE] ||
         migrate_multifd_compression() ||
         migrate_tls())) {
        error_setg(errp,
                   "Zero copy only available for non-compressed non-TLS multifd migration");
        return false;
    }
#else
    if (new_caps[MIGRATION_CAPABILITY_ZERO_COPY_SEND]) {
        error_setg(errp,
                   "Zero copy currently only available on Linux");
        return false;
    }
#endif

    if (new_caps[MIGRATION_CAPABILITY_POSTCOPY_PREEMPT]) {
        if (!new_caps[MIGRATION_CAPABILITY_POSTCOPY_RAM]) {
            error_setg(errp, "Postcopy preempt requires postcopy-ram");
            return false;
        }

        /*
         * Preempt mode requires urgent pages to be sent in separate
         * channel, OTOH compression logic will disorder all pages into
         * different compression channels, which is not compatible with the
         * preempt assumptions on channel assignments.
         */
        if (new_caps[MIGRATION_CAPABILITY_COMPRESS]) {
            error_setg(errp, "Postcopy preempt not compatible with compress");
            return false;
        }
    }

    if (new_caps[MIGRATION_CAPABILITY_MULTIFD]) {
        if (new_caps[MIGRATION_CAPABILITY_COMPRESS]) {
            error_setg(errp, "Multifd is not compatible with compress");
            return false;
        }
    }

    return true;
}

bool migrate_cap_set(int cap, bool value, Error **errp)
{
    MigrationState *s = migrate_get_current();
    bool new_caps[MIGRATION_CAPABILITY__MAX];

    if (migration_is_running(s->state)) {
        error_setg(errp, QERR_MIGRATION_ACTIVE);
        return false;
    }

    memcpy(new_caps, s->capabilities, sizeof(new_caps));
    new_caps[cap] = value;

    if (!migrate_caps_check(s->capabilities, new_caps, errp)) {
        return false;
    }
    s->capabilities[cap] = value;
    return true;
}

MigrationCapabilityStatusList *qmp_query_migrate_capabilities(Error **errp)
{
    MigrationCapabilityStatusList *head = NULL, **tail = &head;
    MigrationCapabilityStatus *caps;
    MigrationState *s = migrate_get_current();
    int i;

    for (i = 0; i < MIGRATION_CAPABILITY__MAX; i++) {
#ifndef CONFIG_LIVE_BLOCK_MIGRATION
        if (i == MIGRATION_CAPABILITY_BLOCK) {
            continue;
        }
#endif
        caps = g_malloc0(sizeof(*caps));
        caps->capability = i;
        caps->state = s->capabilities[i];
        QAPI_LIST_APPEND(tail, caps);
    }

    return head;
}

void qmp_migrate_set_capabilities(MigrationCapabilityStatusList *params,
                                  Error **errp)
{
    MigrationState *s = migrate_get_current();
    MigrationCapabilityStatusList *cap;
    bool new_caps[MIGRATION_CAPABILITY__MAX];

    if (migration_is_running(s->state)) {
        error_setg(errp, QERR_MIGRATION_ACTIVE);
        return;
    }

    memcpy(new_caps, s->capabilities, sizeof(new_caps));
    for (cap = params; cap; cap = cap->next) {
        new_caps[cap->value->capability] = cap->value->state;
    }

    if (!migrate_caps_check(s->capabilities, new_caps, errp)) {
        return;
    }

    for (cap = params; cap; cap = cap->next) {
        s->capabilities[cap->value->capability] = cap->value->state;
    }
}

/* parameters */

bool migrate_block_incremental(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.block_incremental;
}

uint32_t migrate_checkpoint_delay(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.x_checkpoint_delay;
}

int migrate_compress_level(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.compress_level;
}

int migrate_compress_threads(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.compress_threads;
}

int migrate_compress_wait_thread(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.compress_wait_thread;
}

uint8_t migrate_cpu_throttle_increment(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.cpu_throttle_increment;
}

uint8_t migrate_cpu_throttle_initial(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.cpu_throttle_initial;
}

bool migrate_cpu_throttle_tailslow(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.cpu_throttle_tailslow;
}

int migrate_decompress_threads(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.decompress_threads;
}

uint8_t migrate_max_cpu_throttle(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.max_cpu_throttle;
}

uint64_t migrate_max_bandwidth(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.max_bandwidth;
}

int64_t migrate_max_postcopy_bandwidth(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.max_postcopy_bandwidth;
}

int migrate_multifd_channels(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.multifd_channels;
}

MultiFDCompression migrate_multifd_compression(void)
{
    MigrationState *s;

    s = migrate_get_current();

    assert(s->parameters.multifd_compression < MULTIFD_COMPRESSION__MAX);
    return s->parameters.multifd_compression;
}

int migrate_multifd_zlib_level(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.multifd_zlib_level;
}

int migrate_multifd_zstd_level(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.multifd_zstd_level;
}

uint8_t migrate_throttle_trigger_threshold(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.throttle_trigger_threshold;
}

uint64_t migrate_xbzrle_cache_size(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.xbzrle_cache_size;
}

/* parameters helpers */

AnnounceParameters *migrate_announce_params(void)
{
    static AnnounceParameters ap;

    MigrationState *s = migrate_get_current();

    ap.initial = s->parameters.announce_initial;
    ap.max = s->parameters.announce_max;
    ap.rounds = s->parameters.announce_rounds;
    ap.step = s->parameters.announce_step;

    return &ap;
}

MigrationParameters *qmp_query_migrate_parameters(Error **errp)
{
    MigrationParameters *params;
    MigrationState *s = migrate_get_current();

    /* TODO use QAPI_CLONE() instead of duplicating it inline */
    params = g_malloc0(sizeof(*params));
    params->has_compress_level = true;
    params->compress_level = s->parameters.compress_level;
    params->has_compress_threads = true;
    params->compress_threads = s->parameters.compress_threads;
    params->has_compress_wait_thread = true;
    params->compress_wait_thread = s->parameters.compress_wait_thread;
    params->has_decompress_threads = true;
    params->decompress_threads = s->parameters.decompress_threads;
    params->has_throttle_trigger_threshold = true;
    params->throttle_trigger_threshold = s->parameters.throttle_trigger_threshold;
    params->has_cpu_throttle_initial = true;
    params->cpu_throttle_initial = s->parameters.cpu_throttle_initial;
    params->has_cpu_throttle_increment = true;
    params->cpu_throttle_increment = s->parameters.cpu_throttle_increment;
    params->has_cpu_throttle_tailslow = true;
    params->cpu_throttle_tailslow = s->parameters.cpu_throttle_tailslow;
    params->tls_creds = g_strdup(s->parameters.tls_creds);
    params->tls_hostname = g_strdup(s->parameters.tls_hostname);
    params->tls_authz = g_strdup(s->parameters.tls_authz ?
                                 s->parameters.tls_authz : "");
    params->has_max_bandwidth = true;
    params->max_bandwidth = s->parameters.max_bandwidth;
    params->has_downtime_limit = true;
    params->downtime_limit = s->parameters.downtime_limit;
    params->has_x_checkpoint_delay = true;
    params->x_checkpoint_delay = s->parameters.x_checkpoint_delay;
    params->has_block_incremental = true;
    params->block_incremental = s->parameters.block_incremental;
    params->has_multifd_channels = true;
    params->multifd_channels = s->parameters.multifd_channels;
    params->has_multifd_compression = true;
    params->multifd_compression = s->parameters.multifd_compression;
    params->has_multifd_zlib_level = true;
    params->multifd_zlib_level = s->parameters.multifd_zlib_level;
    params->has_multifd_zstd_level = true;
    params->multifd_zstd_level = s->parameters.multifd_zstd_level;
    params->has_xbzrle_cache_size = true;
    params->xbzrle_cache_size = s->parameters.xbzrle_cache_size;
    params->has_max_postcopy_bandwidth = true;
    params->max_postcopy_bandwidth = s->parameters.max_postcopy_bandwidth;
    params->has_max_cpu_throttle = true;
    params->max_cpu_throttle = s->parameters.max_cpu_throttle;
    params->has_announce_initial = true;
    params->announce_initial = s->parameters.announce_initial;
    params->has_announce_max = true;
    params->announce_max = s->parameters.announce_max;
    params->has_announce_rounds = true;
    params->announce_rounds = s->parameters.announce_rounds;
    params->has_announce_step = true;
    params->announce_step = s->parameters.announce_step;

    if (s->parameters.has_block_bitmap_mapping) {
        params->has_block_bitmap_mapping = true;
        params->block_bitmap_mapping =
            QAPI_CLONE(BitmapMigrationNodeAliasList,
                       s->parameters.block_bitmap_mapping);
    }

    return params;
}

/*
 * Check whether the parameters are valid. Error will be put into errp
 * (if provided). Return true if valid, otherwise false.
 */
bool migrate_params_check(MigrationParameters *params, Error **errp)
{
    if (params->has_compress_level &&
        (params->compress_level > 9)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "compress_level",
                   "a value between 0 and 9");
        return false;
    }

    if (params->has_compress_threads && (params->compress_threads < 1)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "compress_threads",
                   "a value between 1 and 255");
        return false;
    }

    if (params->has_decompress_threads && (params->decompress_threads < 1)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "decompress_threads",
                   "a value between 1 and 255");
        return false;
    }

    if (params->has_throttle_trigger_threshold &&
        (params->throttle_trigger_threshold < 1 ||
         params->throttle_trigger_threshold > 100)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "throttle_trigger_threshold",
                   "an integer in the range of 1 to 100");
        return false;
    }

    if (params->has_cpu_throttle_initial &&
        (params->cpu_throttle_initial < 1 ||
         params->cpu_throttle_initial > 99)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "cpu_throttle_initial",
                   "an integer in the range of 1 to 99");
        return false;
    }

    if (params->has_cpu_throttle_increment &&
        (params->cpu_throttle_increment < 1 ||
         params->cpu_throttle_increment > 99)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "cpu_throttle_increment",
                   "an integer in the range of 1 to 99");
        return false;
    }

    if (params->has_max_bandwidth && (params->max_bandwidth > SIZE_MAX)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "max_bandwidth",
                   "an integer in the range of 0 to "stringify(SIZE_MAX)
                   " bytes/second");
        return false;
    }

    if (params->has_downtime_limit &&
        (params->downtime_limit > MAX_MIGRATE_DOWNTIME)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "downtime_limit",
                   "an integer in the range of 0 to "
                    stringify(MAX_MIGRATE_DOWNTIME)" ms");
        return false;
    }

    /* x_checkpoint_delay is now always positive */

    if (params->has_multifd_channels && (params->multifd_channels < 1)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "multifd_channels",
                   "a value between 1 and 255");
        return false;
    }

    if (params->has_multifd_zlib_level &&
        (params->multifd_zlib_level > 9)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "multifd_zlib_level",
                   "a value between 0 and 9");
        return false;
    }

    if (params->has_multifd_zstd_level &&
        (params->multifd_zstd_level > 20)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "multifd_zstd_level",
                   "a value between 0 and 20");
        return false;
    }

    if (params->has_xbzrle_cache_size &&
        (params->xbzrle_cache_size < qemu_target_page_size() ||
         !is_power_of_2(params->xbzrle_cache_size))) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "xbzrle_cache_size",
                   "a power of two no less than the target page size");
        return false;
    }

    if (params->has_max_cpu_throttle &&
        (params->max_cpu_throttle < params->cpu_throttle_initial ||
         params->max_cpu_throttle > 99)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "max_cpu_throttle",
                   "an integer in the range of cpu_throttle_initial to 99");
        return false;
    }

    if (params->has_announce_initial &&
        params->announce_initial > 100000) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "announce_initial",
                   "a value between 0 and 100000");
        return false;
    }
    if (params->has_announce_max &&
        params->announce_max > 100000) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "announce_max",
                   "a value between 0 and 100000");
       return false;
    }
    if (params->has_announce_rounds &&
        params->announce_rounds > 1000) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "announce_rounds",
                   "a value between 0 and 1000");
       return false;
    }
    if (params->has_announce_step &&
        (params->announce_step < 1 ||
        params->announce_step > 10000)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "announce_step",
                   "a value between 0 and 10000");
       return false;
    }

    if (params->has_block_bitmap_mapping &&
        !check_dirty_bitmap_mig_alias_map(params->block_bitmap_mapping, errp)) {
        error_prepend(errp, "Invalid mapping given for block-bitmap-mapping: ");
        return false;
    }

#ifdef CONFIG_LINUX
    if (migrate_zero_copy_send() &&
        ((params->has_multifd_compression && params->multifd_compression) ||
         (params->tls_creds && *params->tls_creds))) {
        error_setg(errp,
                   "Zero copy only available for non-compressed non-TLS multifd migration");
        return false;
    }
#endif

    return true;
}

static void migrate_params_test_apply(MigrateSetParameters *params,
                                      MigrationParameters *dest)
{
    *dest = migrate_get_current()->parameters;

    /* TODO use QAPI_CLONE() instead of duplicating it inline */

    if (params->has_compress_level) {
        dest->compress_level = params->compress_level;
    }

    if (params->has_compress_threads) {
        dest->compress_threads = params->compress_threads;
    }

    if (params->has_compress_wait_thread) {
        dest->compress_wait_thread = params->compress_wait_thread;
    }

    if (params->has_decompress_threads) {
        dest->decompress_threads = params->decompress_threads;
    }

    if (params->has_throttle_trigger_threshold) {
        dest->throttle_trigger_threshold = params->throttle_trigger_threshold;
    }

    if (params->has_cpu_throttle_initial) {
        dest->cpu_throttle_initial = params->cpu_throttle_initial;
    }

    if (params->has_cpu_throttle_increment) {
        dest->cpu_throttle_increment = params->cpu_throttle_increment;
    }

    if (params->has_cpu_throttle_tailslow) {
        dest->cpu_throttle_tailslow = params->cpu_throttle_tailslow;
    }

    if (params->tls_creds) {
        assert(params->tls_creds->type == QTYPE_QSTRING);
        dest->tls_creds = params->tls_creds->u.s;
    }

    if (params->tls_hostname) {
        assert(params->tls_hostname->type == QTYPE_QSTRING);
        dest->tls_hostname = params->tls_hostname->u.s;
    }

    if (params->has_max_bandwidth) {
        dest->max_bandwidth = params->max_bandwidth;
    }

    if (params->has_downtime_limit) {
        dest->downtime_limit = params->downtime_limit;
    }

    if (params->has_x_checkpoint_delay) {
        dest->x_checkpoint_delay = params->x_checkpoint_delay;
    }

    if (params->has_block_incremental) {
        dest->block_incremental = params->block_incremental;
    }
    if (params->has_multifd_channels) {
        dest->multifd_channels = params->multifd_channels;
    }
    if (params->has_multifd_compression) {
        dest->multifd_compression = params->multifd_compression;
    }
    if (params->has_xbzrle_cache_size) {
        dest->xbzrle_cache_size = params->xbzrle_cache_size;
    }
    if (params->has_max_postcopy_bandwidth) {
        dest->max_postcopy_bandwidth = params->max_postcopy_bandwidth;
    }
    if (params->has_max_cpu_throttle) {
        dest->max_cpu_throttle = params->max_cpu_throttle;
    }
    if (params->has_announce_initial) {
        dest->announce_initial = params->announce_initial;
    }
    if (params->has_announce_max) {
        dest->announce_max = params->announce_max;
    }
    if (params->has_announce_rounds) {
        dest->announce_rounds = params->announce_rounds;
    }
    if (params->has_announce_step) {
        dest->announce_step = params->announce_step;
    }

    if (params->has_block_bitmap_mapping) {
        dest->has_block_bitmap_mapping = true;
        dest->block_bitmap_mapping = params->block_bitmap_mapping;
    }
}

static void migrate_params_apply(MigrateSetParameters *params, Error **errp)
{
    MigrationState *s = migrate_get_current();

    /* TODO use QAPI_CLONE() instead of duplicating it inline */

    if (params->has_compress_level) {
        s->parameters.compress_level = params->compress_level;
    }

    if (params->has_compress_threads) {
        s->parameters.compress_threads = params->compress_threads;
    }

    if (params->has_compress_wait_thread) {
        s->parameters.compress_wait_thread = params->compress_wait_thread;
    }

    if (params->has_decompress_threads) {
        s->parameters.decompress_threads = params->decompress_threads;
    }

    if (params->has_throttle_trigger_threshold) {
        s->parameters.throttle_trigger_threshold = params->throttle_trigger_threshold;
    }

    if (params->has_cpu_throttle_initial) {
        s->parameters.cpu_throttle_initial = params->cpu_throttle_initial;
    }

    if (params->has_cpu_throttle_increment) {
        s->parameters.cpu_throttle_increment = params->cpu_throttle_increment;
    }

    if (params->has_cpu_throttle_tailslow) {
        s->parameters.cpu_throttle_tailslow = params->cpu_throttle_tailslow;
    }

    if (params->tls_creds) {
        g_free(s->parameters.tls_creds);
        assert(params->tls_creds->type == QTYPE_QSTRING);
        s->parameters.tls_creds = g_strdup(params->tls_creds->u.s);
    }

    if (params->tls_hostname) {
        g_free(s->parameters.tls_hostname);
        assert(params->tls_hostname->type == QTYPE_QSTRING);
        s->parameters.tls_hostname = g_strdup(params->tls_hostname->u.s);
    }

    if (params->tls_authz) {
        g_free(s->parameters.tls_authz);
        assert(params->tls_authz->type == QTYPE_QSTRING);
        s->parameters.tls_authz = g_strdup(params->tls_authz->u.s);
    }

    if (params->has_max_bandwidth) {
        s->parameters.max_bandwidth = params->max_bandwidth;
        if (s->to_dst_file && !migration_in_postcopy()) {
            qemu_file_set_rate_limit(s->to_dst_file,
                                s->parameters.max_bandwidth / XFER_LIMIT_RATIO);
        }
    }

    if (params->has_downtime_limit) {
        s->parameters.downtime_limit = params->downtime_limit;
    }

    if (params->has_x_checkpoint_delay) {
        s->parameters.x_checkpoint_delay = params->x_checkpoint_delay;
        if (migration_in_colo_state()) {
            colo_checkpoint_notify(s);
        }
    }

    if (params->has_block_incremental) {
        s->parameters.block_incremental = params->block_incremental;
    }
    if (params->has_multifd_channels) {
        s->parameters.multifd_channels = params->multifd_channels;
    }
    if (params->has_multifd_compression) {
        s->parameters.multifd_compression = params->multifd_compression;
    }
    if (params->has_xbzrle_cache_size) {
        s->parameters.xbzrle_cache_size = params->xbzrle_cache_size;
        xbzrle_cache_resize(params->xbzrle_cache_size, errp);
    }
    if (params->has_max_postcopy_bandwidth) {
        s->parameters.max_postcopy_bandwidth = params->max_postcopy_bandwidth;
        if (s->to_dst_file && migration_in_postcopy()) {
            qemu_file_set_rate_limit(s->to_dst_file,
                    s->parameters.max_postcopy_bandwidth / XFER_LIMIT_RATIO);
        }
    }
    if (params->has_max_cpu_throttle) {
        s->parameters.max_cpu_throttle = params->max_cpu_throttle;
    }
    if (params->has_announce_initial) {
        s->parameters.announce_initial = params->announce_initial;
    }
    if (params->has_announce_max) {
        s->parameters.announce_max = params->announce_max;
    }
    if (params->has_announce_rounds) {
        s->parameters.announce_rounds = params->announce_rounds;
    }
    if (params->has_announce_step) {
        s->parameters.announce_step = params->announce_step;
    }

    if (params->has_block_bitmap_mapping) {
        qapi_free_BitmapMigrationNodeAliasList(
            s->parameters.block_bitmap_mapping);

        s->parameters.has_block_bitmap_mapping = true;
        s->parameters.block_bitmap_mapping =
            QAPI_CLONE(BitmapMigrationNodeAliasList,
                       params->block_bitmap_mapping);
    }
}

void qmp_migrate_set_parameters(MigrateSetParameters *params, Error **errp)
{
    MigrationParameters tmp;

    /* TODO Rewrite "" to null instead */
    if (params->tls_creds
        && params->tls_creds->type == QTYPE_QNULL) {
        qobject_unref(params->tls_creds->u.n);
        params->tls_creds->type = QTYPE_QSTRING;
        params->tls_creds->u.s = strdup("");
    }
    /* TODO Rewrite "" to null instead */
    if (params->tls_hostname
        && params->tls_hostname->type == QTYPE_QNULL) {
        qobject_unref(params->tls_hostname->u.n);
        params->tls_hostname->type = QTYPE_QSTRING;
        params->tls_hostname->u.s = strdup("");
    }

    migrate_params_test_apply(params, &tmp);

    if (!migrate_params_check(&tmp, errp)) {
        /* Invalid parameter */
        return;
    }

    migrate_params_apply(params, errp);
}
