# Example 1

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/cmd/zdb/zdb.c:6019:2*

fnptr: *vdev_indirect_ops.vdev_op_remap*

targets: vdev_indirect_remap

## Related Code Snippets

```c
static void
claim_segment_cb(void *arg, uint64_t offset, uint64_t size)
{
	vdev_t *vd = arg;

	vdev_indirect_ops.vdev_op_remap(vd, offset, size,
	    claim_segment_impl_cb, NULL);
}
```

```c
vdev_ops_t vdev_indirect_ops = {
	.vdev_op_init = NULL,
	.vdev_op_fini = NULL,
	.vdev_op_open = vdev_indirect_open,
	.vdev_op_close = vdev_indirect_close,
	.vdev_op_asize = vdev_default_asize,
	.vdev_op_min_asize = vdev_default_min_asize,
	.vdev_op_min_alloc = NULL,
	.vdev_op_io_start = vdev_indirect_io_start,
	.vdev_op_io_done = vdev_indirect_io_done,
	.vdev_op_state_change = NULL,
	.vdev_op_need_resilver = NULL,
	.vdev_op_hold = NULL,
	.vdev_op_rele = NULL,
	.vdev_op_remap = vdev_indirect_remap,
	.vdev_op_xlate = NULL,
	.vdev_op_rebuild_asize = NULL,
	.vdev_op_metaslab_init = NULL,
	.vdev_op_config_generate = NULL,
	.vdev_op_nparity = NULL,
	.vdev_op_ndisks = NULL,
	.vdev_op_type = VDEV_TYPE_INDIRECT,	/* name of this vdev type */
	.vdev_op_leaf = B_FALSE			/* leaf vdev */
};
```

```c
static void
vdev_indirect_remap(vdev_t *vd, uint64_t offset, uint64_t asize,
    void (*func)(uint64_t, vdev_t *, uint64_t, uint64_t, void *), void *arg)
```

# Example 2

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/curl-build/lib/../../curl-8.5.0/lib/vtls/vtls.c:1018:14*

fnptr: *Curl_ssl->sha256sum*

targets: ossl_sha256sum

## Related Code Snippets

```c
CURLcode Curl_pin_peer_pubkey(struct Curl_easy *data,
                              const char *pinnedpubkey,
                              const unsigned char *pubkey, size_t pubkeylen)
{
...
/* compute sha256sum of public key */
   sha256sumdigest = malloc(CURL_SHA256_DIGEST_LENGTH);
   if(!sha256sumdigest)
     return CURLE_OUT_OF_MEMORY;
   encode = Curl_ssl->sha256sum(pubkey, pubkeylen,
                                sha256sumdigest, CURL_SHA256_DIGEST_LENGTH);
...
}
```

```c
const struct Curl_ssl *Curl_ssl =
#if defined(CURL_WITH_MULTI_SSL)
  &Curl_ssl_multi;
#elif defined(USE_WOLFSSL)
  &Curl_ssl_wolfssl;
#elif defined(USE_SECTRANSP)
  &Curl_ssl_sectransp;
#elif defined(USE_GNUTLS)
  &Curl_ssl_gnutls;
#elif defined(USE_MBEDTLS)
  &Curl_ssl_mbedtls;
#elif defined(USE_RUSTLS)
  &Curl_ssl_rustls;
#elif defined(USE_OPENSSL)
  &Curl_ssl_openssl;
#elif defined(USE_SCHANNEL)
  &Curl_ssl_schannel;
#elif defined(USE_BEARSSL)
  &Curl_ssl_bearssl;
#else
#error "Missing struct Curl_ssl for selected SSL backend"
#endif
```

```c
const struct Curl_ssl Curl_ssl_openssl = {
  { CURLSSLBACKEND_OPENSSL, "openssl" }, /* info */
...
  ossl_get_internals,       /* get_internals */
  ossl_close,               /* close_one */
  ossl_close_all,           /* close_all */
  ossl_session_free,        /* session_free */
  ossl_set_engine,          /* set_engine */
  ossl_set_engine_default,  /* set_engine_default */
  ossl_engines_list,        /* engines_list */
  Curl_none_false_start,    /* false_start */
#if (OPENSSL_VERSION_NUMBER >= 0x0090800fL) && !defined(OPENSSL_NO_SHA256)
  ossl_sha256sum,           /* sha256sum */
#else
  NULL,                     /* sha256sum */
#endif
  NULL,                     /* use of data in this connection */
...
};

```

# Example 3

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/src/pubsub.c:167:24*

fnptr: *type.clientPubSubChannels*

targets: getClientPubSubChannels

## Related Code Snippets

```c
/*
 * Pub/Sub type for global channels.
 */
pubsubtype pubSubType = {
    .shard = 0,
    .clientPubSubChannels = getClientPubSubChannels,
    .subscriptionCount = clientSubscriptionsCount,
    .serverPubSubChannels = &server.pubsub_channels,
    .subscribeMsg = &shared.subscribebulk,
    .unsubscribeMsg = &shared.unsubscribebulk,
    .messageBulk = &shared.messagebulk,
};
```

```c
/* SUBSCRIBE channel [channel ...] */
void subscribeCommand(client *c) {
    int j;
    if ((c->flags & CLIENT_DENY_BLOCKING) && !(c->flags & CLIENT_MULTI)) {
        /**
         * A client that has CLIENT_DENY_BLOCKING flag on
         * expect a reply per command and so can not execute subscribe.
         *
         * Notice that we have a special treatment for multi because of
         * backward compatibility
         */
        addReplyError(c, "SUBSCRIBE isn't allowed for a DENY BLOCKING client");
        return;
    }
    for (j = 1; j < c->argc; j++)
        pubsubSubscribeChannel(c,c->argv[j],pubSubType);
    c->flags |= CLIENT_PUBSUB;
}
```

```c
/* Subscribe a client to a channel. Returns 1 if the operation succeeded, or
 * 0 if the client was already subscribed to that channel. */
int pubsubSubscribeChannel(client *c, robj *channel, pubsubtype type) {
    dictEntry *de;
    list *clients = NULL;
    int retval = 0;

    /* Add the channel to the client -> channels hash table */
    if (dictAdd(type.clientPubSubChannels(c),channel,NULL) == DICT_OK) {
        retval = 1;
        incrRefCount(channel);
        /* Add the client to the channel -> list of clients hash table */
        de = dictFind(*type.serverPubSubChannels, channel);
        if (de == NULL) {
            clients = listCreate();
            dictAdd(*type.serverPubSubChannels, channel, clients);
            incrRefCount(channel);
        } else {
            clients = dictGetVal(de);
        }
        listAddNodeTail(clients,c);
    }
    /* Notify the client */
    addReplyPubsubSubscribed(c,channel,type);
    return retval;
}
```

# Example 4

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/module/zfs/zfs_ioctl.c:7848:11*

fnptr: *vec->zvec_legacy_func*

targets: zfs_ioc_clear, zfs_ioc_clear_fault, zfs_ioc_dataset_list_next, zfs_ioc_destroy, zfs_ioc_diff, zfs_ioc_dsobj_to_dsname, zfs_ioc_error_log, zfs_ioc_events_clear, zfs_ioc_events_next, zfs_ioc_events_seek, zfs_ioc_get_fsacl, zfs_ioc_inherit_prop, zfs_ioc_inject_fault, zfs_ioc_inject_list_next, zfs_ioc_next_obj, zfs_ioc_obj_to_path, zfs_ioc_obj_to_stats, zfs_ioc_objset_recvd_props, zfs_ioc_objset_stats, zfs_ioc_objset_zplprops, zfs_ioc_pool_configs, zfs_ioc_pool_create, zfs_ioc_pool_destroy, zfs_ioc_pool_export, zfs_ioc_pool_freeze, zfs_ioc_pool_get_history, zfs_ioc_pool_get_props, zfs_ioc_pool_import, zfs_ioc_pool_reguid, zfs_ioc_pool_scan, zfs_ioc_pool_set_props, zfs_ioc_pool_stats, zfs_ioc_pool_tryimport, zfs_ioc_pool_upgrade, zfs_ioc_promote, zfs_ioc_recv, zfs_ioc_rename, zfs_ioc_send, zfs_ioc_send_progress, zfs_ioc_set_fsacl, zfs_ioc_set_prop, zfs_ioc_share, zfs_ioc_smb_acl, zfs_ioc_snapshot_list_next, zfs_ioc_space_written, zfs_ioc_tmp_snapshot, zfs_ioc_userspace_many, zfs_ioc_userspace_one, zfs_ioc_userspace_upgrade, zfs_ioc_vdev_add, zfs_ioc_vdev_attach, zfs_ioc_vdev_detach, zfs_ioc_vdev_remove, zfs_ioc_vdev_set_state, zfs_ioc_vdev_setfru, zfs_ioc_vdev_setpath, zfs_ioc_vdev_split

## Related Code Snippets

```c
long zfsdev_ioctl_common(uint_t vecnum, zfs_cmd_t *zc, int flag)
{
	...
	if (vec->zvec_func != NULL) {
		....

		if ((error == 0 ||
		    (cmd == ZFS_IOC_CHANNEL_PROGRAM && error != EINVAL)) &&
		    vec->zvec_allow_log &&
		    spa_open(zc->zc_name, &spa, FTAG) == 0) {
			...
	} else {
		cookie = spl_fstrans_mark();
		error = vec->zvec_legacy_func(zc);
		spl_fstrans_unmark(cookie);
	}
    ...
    }
}
```

```c
static void zfs_ioctl_register_legacy(zfs_ioc_t ioc, zfs_ioc_legacy_func_t *func,
    zfs_secpolicy_func_t *secpolicy, zfs_ioc_namecheck_t namecheck,
    boolean_t log_history, zfs_ioc_poolcheck_t pool_check)
{
	zfs_ioc_vec_t *vec = &zfs_ioc_vec[ioc - ZFS_IOC_FIRST];

	...

	vec->zvec_legacy_func = func;
	vec->zvec_secpolicy = secpolicy;
	vec->zvec_namecheck = namecheck;
	vec->zvec_allow_log = log_history;
	vec->zvec_pool_check = pool_check;
}

static void
zfs_ioctl_register_pool(zfs_ioc_t ioc, zfs_ioc_legacy_func_t *func,
    zfs_secpolicy_func_t *secpolicy, boolean_t log_history,
    zfs_ioc_poolcheck_t pool_check)
{
	zfs_ioctl_register_legacy(ioc, func, secpolicy,
	    POOL_NAME, log_history, pool_check);
}

void
zfs_ioctl_register_dataset_nolog(zfs_ioc_t ioc, zfs_ioc_legacy_func_t *func,
    zfs_secpolicy_func_t *secpolicy, zfs_ioc_poolcheck_t pool_check)
{
	zfs_ioctl_register_legacy(ioc, func, secpolicy,
	    DATASET_NAME, B_FALSE, pool_check);
}

static void
zfs_ioctl_register_pool_modify(zfs_ioc_t ioc, zfs_ioc_legacy_func_t *func)
{
	zfs_ioctl_register_legacy(ioc, func, zfs_secpolicy_config,
	    POOL_NAME, B_TRUE, POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY);
}

static void
zfs_ioctl_register_pool_meta(zfs_ioc_t ioc, zfs_ioc_legacy_func_t *func,
    zfs_secpolicy_func_t *secpolicy)
{
	zfs_ioctl_register_legacy(ioc, func, secpolicy,
	    NO_NAME, B_FALSE, POOL_CHECK_NONE);
}

static void
zfs_ioctl_register_dataset_read_secpolicy(zfs_ioc_t ioc,
    zfs_ioc_legacy_func_t *func, zfs_secpolicy_func_t *secpolicy)
{
	zfs_ioctl_register_legacy(ioc, func, secpolicy,
	    DATASET_NAME, B_FALSE, POOL_CHECK_SUSPENDED);
}

static void
zfs_ioctl_register_dataset_read(zfs_ioc_t ioc, zfs_ioc_legacy_func_t *func)
{
	zfs_ioctl_register_dataset_read_secpolicy(ioc, func,
	    zfs_secpolicy_read);
}

static void
zfs_ioctl_register_dataset_modify(zfs_ioc_t ioc, zfs_ioc_legacy_func_t *func,
    zfs_secpolicy_func_t *secpolicy)
{
	zfs_ioctl_register_legacy(ioc, func, secpolicy,
	    DATASET_NAME, B_TRUE, POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY);
}
```

```c
static void
zfs_ioctl_init(void)
{
	zfs_ioctl_register("snapshot", ZFS_IOC_SNAPSHOT,
	    zfs_ioc_snapshot, zfs_secpolicy_snapshot, POOL_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_TRUE, B_TRUE,
	    zfs_keys_snapshot, ARRAY_SIZE(zfs_keys_snapshot));

	zfs_ioctl_register("log_history", ZFS_IOC_LOG_HISTORY,
	    zfs_ioc_log_history, zfs_secpolicy_log_history, NO_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_FALSE, B_FALSE,
	    zfs_keys_log_history, ARRAY_SIZE(zfs_keys_log_history));

	zfs_ioctl_register("space_snaps", ZFS_IOC_SPACE_SNAPS,
	    zfs_ioc_space_snaps, zfs_secpolicy_read, DATASET_NAME,
	    POOL_CHECK_SUSPENDED, B_FALSE, B_FALSE,
	    zfs_keys_space_snaps, ARRAY_SIZE(zfs_keys_space_snaps));

	zfs_ioctl_register("send", ZFS_IOC_SEND_NEW,
	    zfs_ioc_send_new, zfs_secpolicy_send_new, DATASET_NAME,
	    POOL_CHECK_SUSPENDED, B_FALSE, B_FALSE,
	    zfs_keys_send_new, ARRAY_SIZE(zfs_keys_send_new));

	zfs_ioctl_register("send_space", ZFS_IOC_SEND_SPACE,
	    zfs_ioc_send_space, zfs_secpolicy_read, DATASET_NAME,
	    POOL_CHECK_SUSPENDED, B_FALSE, B_FALSE,
	    zfs_keys_send_space, ARRAY_SIZE(zfs_keys_send_space));

	zfs_ioctl_register("create", ZFS_IOC_CREATE,
	    zfs_ioc_create, zfs_secpolicy_create_clone, DATASET_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_TRUE, B_TRUE,
	    zfs_keys_create, ARRAY_SIZE(zfs_keys_create));

	zfs_ioctl_register("clone", ZFS_IOC_CLONE,
	    zfs_ioc_clone, zfs_secpolicy_create_clone, DATASET_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_TRUE, B_TRUE,
	    zfs_keys_clone, ARRAY_SIZE(zfs_keys_clone));

	zfs_ioctl_register("remap", ZFS_IOC_REMAP,
	    zfs_ioc_remap, zfs_secpolicy_none, DATASET_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_FALSE, B_TRUE,
	    zfs_keys_remap, ARRAY_SIZE(zfs_keys_remap));

	zfs_ioctl_register("destroy_snaps", ZFS_IOC_DESTROY_SNAPS,
	    zfs_ioc_destroy_snaps, zfs_secpolicy_destroy_snaps, POOL_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_TRUE, B_TRUE,
	    zfs_keys_destroy_snaps, ARRAY_SIZE(zfs_keys_destroy_snaps));

	zfs_ioctl_register("hold", ZFS_IOC_HOLD,
	    zfs_ioc_hold, zfs_secpolicy_hold, POOL_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_TRUE, B_TRUE,
	    zfs_keys_hold, ARRAY_SIZE(zfs_keys_hold));
	zfs_ioctl_register("release", ZFS_IOC_RELEASE,
	    zfs_ioc_release, zfs_secpolicy_release, POOL_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_TRUE, B_TRUE,
	    zfs_keys_release, ARRAY_SIZE(zfs_keys_release));

	zfs_ioctl_register("get_holds", ZFS_IOC_GET_HOLDS,
	    zfs_ioc_get_holds, zfs_secpolicy_read, DATASET_NAME,
	    POOL_CHECK_SUSPENDED, B_FALSE, B_FALSE,
	    zfs_keys_get_holds, ARRAY_SIZE(zfs_keys_get_holds));

	zfs_ioctl_register("rollback", ZFS_IOC_ROLLBACK,
	    zfs_ioc_rollback, zfs_secpolicy_rollback, DATASET_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_FALSE, B_TRUE,
	    zfs_keys_rollback, ARRAY_SIZE(zfs_keys_rollback));

	zfs_ioctl_register("bookmark", ZFS_IOC_BOOKMARK,
	    zfs_ioc_bookmark, zfs_secpolicy_bookmark, POOL_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_TRUE, B_TRUE,
	    zfs_keys_bookmark, ARRAY_SIZE(zfs_keys_bookmark));

	zfs_ioctl_register("get_bookmarks", ZFS_IOC_GET_BOOKMARKS,
	    zfs_ioc_get_bookmarks, zfs_secpolicy_read, DATASET_NAME,
	    POOL_CHECK_SUSPENDED, B_FALSE, B_FALSE,
	    zfs_keys_get_bookmarks, ARRAY_SIZE(zfs_keys_get_bookmarks));

	zfs_ioctl_register("get_bookmark_props", ZFS_IOC_GET_BOOKMARK_PROPS,
	    zfs_ioc_get_bookmark_props, zfs_secpolicy_read, ENTITY_NAME,
	    POOL_CHECK_SUSPENDED, B_FALSE, B_FALSE, zfs_keys_get_bookmark_props,
	    ARRAY_SIZE(zfs_keys_get_bookmark_props));

	zfs_ioctl_register("destroy_bookmarks", ZFS_IOC_DESTROY_BOOKMARKS,
	    zfs_ioc_destroy_bookmarks, zfs_secpolicy_destroy_bookmarks,
	    POOL_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_TRUE, B_TRUE,
	    zfs_keys_destroy_bookmarks,
	    ARRAY_SIZE(zfs_keys_destroy_bookmarks));

	zfs_ioctl_register("receive", ZFS_IOC_RECV_NEW,
	    zfs_ioc_recv_new, zfs_secpolicy_recv, DATASET_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_TRUE, B_TRUE,
	    zfs_keys_recv_new, ARRAY_SIZE(zfs_keys_recv_new));
	zfs_ioctl_register("load-key", ZFS_IOC_LOAD_KEY,
	    zfs_ioc_load_key, zfs_secpolicy_load_key,
	    DATASET_NAME, POOL_CHECK_SUSPENDED, B_TRUE, B_TRUE,
	    zfs_keys_load_key, ARRAY_SIZE(zfs_keys_load_key));
	zfs_ioctl_register("unload-key", ZFS_IOC_UNLOAD_KEY,
	    zfs_ioc_unload_key, zfs_secpolicy_load_key,
	    DATASET_NAME, POOL_CHECK_SUSPENDED, B_TRUE, B_TRUE,
	    zfs_keys_unload_key, ARRAY_SIZE(zfs_keys_unload_key));
	zfs_ioctl_register("change-key", ZFS_IOC_CHANGE_KEY,
	    zfs_ioc_change_key, zfs_secpolicy_change_key,
	    DATASET_NAME, POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY,
	    B_TRUE, B_TRUE, zfs_keys_change_key,
	    ARRAY_SIZE(zfs_keys_change_key));

	zfs_ioctl_register("sync", ZFS_IOC_POOL_SYNC,
	    zfs_ioc_pool_sync, zfs_secpolicy_none, POOL_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_FALSE, B_FALSE,
	    zfs_keys_pool_sync, ARRAY_SIZE(zfs_keys_pool_sync));
	zfs_ioctl_register("reopen", ZFS_IOC_POOL_REOPEN, zfs_ioc_pool_reopen,
	    zfs_secpolicy_config, POOL_NAME, POOL_CHECK_SUSPENDED, B_TRUE,
	    B_TRUE, zfs_keys_pool_reopen, ARRAY_SIZE(zfs_keys_pool_reopen));

	zfs_ioctl_register("channel_program", ZFS_IOC_CHANNEL_PROGRAM,
	    zfs_ioc_channel_program, zfs_secpolicy_config,
	    POOL_NAME, POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_TRUE,
	    B_TRUE, zfs_keys_channel_program,
	    ARRAY_SIZE(zfs_keys_channel_program));

	zfs_ioctl_register("redact", ZFS_IOC_REDACT,
	    zfs_ioc_redact, zfs_secpolicy_config, DATASET_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_TRUE, B_TRUE,
	    zfs_keys_redact, ARRAY_SIZE(zfs_keys_redact));

	zfs_ioctl_register("zpool_checkpoint", ZFS_IOC_POOL_CHECKPOINT,
	    zfs_ioc_pool_checkpoint, zfs_secpolicy_config, POOL_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_TRUE, B_TRUE,
	    zfs_keys_pool_checkpoint, ARRAY_SIZE(zfs_keys_pool_checkpoint));

	zfs_ioctl_register("zpool_discard_checkpoint",
	    ZFS_IOC_POOL_DISCARD_CHECKPOINT, zfs_ioc_pool_discard_checkpoint,
	    zfs_secpolicy_config, POOL_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_TRUE, B_TRUE,
	    zfs_keys_pool_discard_checkpoint,
	    ARRAY_SIZE(zfs_keys_pool_discard_checkpoint));

	zfs_ioctl_register("initialize", ZFS_IOC_POOL_INITIALIZE,
	    zfs_ioc_pool_initialize, zfs_secpolicy_config, POOL_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_TRUE, B_TRUE,
	    zfs_keys_pool_initialize, ARRAY_SIZE(zfs_keys_pool_initialize));

	zfs_ioctl_register("trim", ZFS_IOC_POOL_TRIM,
	    zfs_ioc_pool_trim, zfs_secpolicy_config, POOL_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_TRUE, B_TRUE,
	    zfs_keys_pool_trim, ARRAY_SIZE(zfs_keys_pool_trim));

	zfs_ioctl_register("wait", ZFS_IOC_WAIT,
	    zfs_ioc_wait, zfs_secpolicy_none, POOL_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_FALSE, B_FALSE,
	    zfs_keys_pool_wait, ARRAY_SIZE(zfs_keys_pool_wait));

	zfs_ioctl_register("wait_fs", ZFS_IOC_WAIT_FS,
	    zfs_ioc_wait_fs, zfs_secpolicy_none, DATASET_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_FALSE, B_FALSE,
	    zfs_keys_fs_wait, ARRAY_SIZE(zfs_keys_fs_wait));

	zfs_ioctl_register("set_bootenv", ZFS_IOC_SET_BOOTENV,
	    zfs_ioc_set_bootenv, zfs_secpolicy_config, POOL_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_FALSE, B_TRUE,
	    zfs_keys_set_bootenv, ARRAY_SIZE(zfs_keys_set_bootenv));

	zfs_ioctl_register("get_bootenv", ZFS_IOC_GET_BOOTENV,
	    zfs_ioc_get_bootenv, zfs_secpolicy_none, POOL_NAME,
	    POOL_CHECK_SUSPENDED, B_FALSE, B_TRUE,
	    zfs_keys_get_bootenv, ARRAY_SIZE(zfs_keys_get_bootenv));

	zfs_ioctl_register("zpool_vdev_get_props", ZFS_IOC_VDEV_GET_PROPS,
	    zfs_ioc_vdev_get_props, zfs_secpolicy_read, POOL_NAME,
	    POOL_CHECK_NONE, B_FALSE, B_FALSE, zfs_keys_vdev_get_props,
	    ARRAY_SIZE(zfs_keys_vdev_get_props));

	zfs_ioctl_register("zpool_vdev_set_props", ZFS_IOC_VDEV_SET_PROPS,
	    zfs_ioc_vdev_set_props, zfs_secpolicy_config, POOL_NAME,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY, B_FALSE, B_FALSE,
	    zfs_keys_vdev_set_props, ARRAY_SIZE(zfs_keys_vdev_set_props));

	zfs_ioctl_register("scrub", ZFS_IOC_POOL_SCRUB,
	    zfs_ioc_pool_scrub, zfs_secpolicy_config, POOL_NAME,
	    POOL_CHECK_NONE, B_TRUE, B_TRUE,
	    zfs_keys_pool_scrub, ARRAY_SIZE(zfs_keys_pool_scrub));

	/* IOCTLS that use the legacy function signature */

	zfs_ioctl_register_legacy(ZFS_IOC_POOL_FREEZE, zfs_ioc_pool_freeze,
	    zfs_secpolicy_config, NO_NAME, B_FALSE, POOL_CHECK_READONLY);

	zfs_ioctl_register_pool(ZFS_IOC_POOL_CREATE, zfs_ioc_pool_create,
	    zfs_secpolicy_config, B_TRUE, POOL_CHECK_NONE);
	zfs_ioctl_register_pool_modify(ZFS_IOC_POOL_SCAN,
	    zfs_ioc_pool_scan);
	zfs_ioctl_register_pool_modify(ZFS_IOC_POOL_UPGRADE,
	    zfs_ioc_pool_upgrade);
	zfs_ioctl_register_pool_modify(ZFS_IOC_VDEV_ADD,
	    zfs_ioc_vdev_add);
	zfs_ioctl_register_pool_modify(ZFS_IOC_VDEV_REMOVE,
	    zfs_ioc_vdev_remove);
	zfs_ioctl_register_pool_modify(ZFS_IOC_VDEV_SET_STATE,
	    zfs_ioc_vdev_set_state);
	zfs_ioctl_register_pool_modify(ZFS_IOC_VDEV_ATTACH,
	    zfs_ioc_vdev_attach);
	zfs_ioctl_register_pool_modify(ZFS_IOC_VDEV_DETACH,
	    zfs_ioc_vdev_detach);
	zfs_ioctl_register_pool_modify(ZFS_IOC_VDEV_SETPATH,
	    zfs_ioc_vdev_setpath);
	zfs_ioctl_register_pool_modify(ZFS_IOC_VDEV_SETFRU,
	    zfs_ioc_vdev_setfru);
	zfs_ioctl_register_pool_modify(ZFS_IOC_POOL_SET_PROPS,
	    zfs_ioc_pool_set_props);
	zfs_ioctl_register_pool_modify(ZFS_IOC_VDEV_SPLIT,
	    zfs_ioc_vdev_split);
	zfs_ioctl_register_pool_modify(ZFS_IOC_POOL_REGUID,
	    zfs_ioc_pool_reguid);

	zfs_ioctl_register_pool_meta(ZFS_IOC_POOL_CONFIGS,
	    zfs_ioc_pool_configs, zfs_secpolicy_none);
	zfs_ioctl_register_pool_meta(ZFS_IOC_POOL_TRYIMPORT,
	    zfs_ioc_pool_tryimport, zfs_secpolicy_config);
	zfs_ioctl_register_pool_meta(ZFS_IOC_INJECT_FAULT,
	    zfs_ioc_inject_fault, zfs_secpolicy_inject);
	zfs_ioctl_register_pool_meta(ZFS_IOC_CLEAR_FAULT,
	    zfs_ioc_clear_fault, zfs_secpolicy_inject);
	zfs_ioctl_register_pool_meta(ZFS_IOC_INJECT_LIST_NEXT,
	    zfs_ioc_inject_list_next, zfs_secpolicy_inject);

	/*
	 * pool destroy, and export don't log the history as part of
	 * zfsdev_ioctl, but rather zfs_ioc_pool_export
	 * does the logging of those commands.
	 */
	zfs_ioctl_register_pool(ZFS_IOC_POOL_DESTROY, zfs_ioc_pool_destroy,
	    zfs_secpolicy_config, B_FALSE, POOL_CHECK_SUSPENDED);
	zfs_ioctl_register_pool(ZFS_IOC_POOL_EXPORT, zfs_ioc_pool_export,
	    zfs_secpolicy_config, B_FALSE, POOL_CHECK_SUSPENDED);

	zfs_ioctl_register_pool(ZFS_IOC_POOL_STATS, zfs_ioc_pool_stats,
	    zfs_secpolicy_read, B_FALSE, POOL_CHECK_NONE);
	zfs_ioctl_register_pool(ZFS_IOC_POOL_GET_PROPS, zfs_ioc_pool_get_props,
	    zfs_secpolicy_read, B_FALSE, POOL_CHECK_NONE);

	zfs_ioctl_register_pool(ZFS_IOC_ERROR_LOG, zfs_ioc_error_log,
	    zfs_secpolicy_inject, B_FALSE, POOL_CHECK_SUSPENDED);
	zfs_ioctl_register_pool(ZFS_IOC_DSOBJ_TO_DSNAME,
	    zfs_ioc_dsobj_to_dsname,
	    zfs_secpolicy_diff, B_FALSE, POOL_CHECK_SUSPENDED);
	zfs_ioctl_register_pool(ZFS_IOC_POOL_GET_HISTORY,
	    zfs_ioc_pool_get_history,
	    zfs_secpolicy_config, B_FALSE, POOL_CHECK_SUSPENDED);

	zfs_ioctl_register_pool(ZFS_IOC_POOL_IMPORT, zfs_ioc_pool_import,
	    zfs_secpolicy_config, B_TRUE, POOL_CHECK_NONE);

	zfs_ioctl_register_pool(ZFS_IOC_CLEAR, zfs_ioc_clear,
	    zfs_secpolicy_config, B_TRUE, POOL_CHECK_READONLY);

	zfs_ioctl_register_dataset_read(ZFS_IOC_SPACE_WRITTEN,
	    zfs_ioc_space_written);
	zfs_ioctl_register_dataset_read(ZFS_IOC_OBJSET_RECVD_PROPS,
	    zfs_ioc_objset_recvd_props);
	zfs_ioctl_register_dataset_read(ZFS_IOC_NEXT_OBJ,
	    zfs_ioc_next_obj);
	zfs_ioctl_register_dataset_read(ZFS_IOC_GET_FSACL,
	    zfs_ioc_get_fsacl);
	zfs_ioctl_register_dataset_read(ZFS_IOC_OBJSET_STATS,
	    zfs_ioc_objset_stats);
	zfs_ioctl_register_dataset_read(ZFS_IOC_OBJSET_ZPLPROPS,
	    zfs_ioc_objset_zplprops);
	zfs_ioctl_register_dataset_read(ZFS_IOC_DATASET_LIST_NEXT,
	    zfs_ioc_dataset_list_next);
	zfs_ioctl_register_dataset_read(ZFS_IOC_SNAPSHOT_LIST_NEXT,
	    zfs_ioc_snapshot_list_next);
	zfs_ioctl_register_dataset_read(ZFS_IOC_SEND_PROGRESS,
	    zfs_ioc_send_progress);

	zfs_ioctl_register_dataset_read_secpolicy(ZFS_IOC_DIFF,
	    zfs_ioc_diff, zfs_secpolicy_diff);
	zfs_ioctl_register_dataset_read_secpolicy(ZFS_IOC_OBJ_TO_STATS,
	    zfs_ioc_obj_to_stats, zfs_secpolicy_diff);
	zfs_ioctl_register_dataset_read_secpolicy(ZFS_IOC_OBJ_TO_PATH,
	    zfs_ioc_obj_to_path, zfs_secpolicy_diff);
	zfs_ioctl_register_dataset_read_secpolicy(ZFS_IOC_USERSPACE_ONE,
	    zfs_ioc_userspace_one, zfs_secpolicy_userspace_one);
	zfs_ioctl_register_dataset_read_secpolicy(ZFS_IOC_USERSPACE_MANY,
	    zfs_ioc_userspace_many, zfs_secpolicy_userspace_many);
	zfs_ioctl_register_dataset_read_secpolicy(ZFS_IOC_SEND,
	    zfs_ioc_send, zfs_secpolicy_send);

	zfs_ioctl_register_dataset_modify(ZFS_IOC_SET_PROP, zfs_ioc_set_prop,
	    zfs_secpolicy_none);
	zfs_ioctl_register_dataset_modify(ZFS_IOC_DESTROY, zfs_ioc_destroy,
	    zfs_secpolicy_destroy);
	zfs_ioctl_register_dataset_modify(ZFS_IOC_RENAME, zfs_ioc_rename,
	    zfs_secpolicy_rename);
	zfs_ioctl_register_dataset_modify(ZFS_IOC_RECV, zfs_ioc_recv,
	    zfs_secpolicy_recv);
	zfs_ioctl_register_dataset_modify(ZFS_IOC_PROMOTE, zfs_ioc_promote,
	    zfs_secpolicy_promote);
	zfs_ioctl_register_dataset_modify(ZFS_IOC_INHERIT_PROP,
	    zfs_ioc_inherit_prop, zfs_secpolicy_inherit_prop);
	zfs_ioctl_register_dataset_modify(ZFS_IOC_SET_FSACL, zfs_ioc_set_fsacl,
	    zfs_secpolicy_set_fsacl);

	zfs_ioctl_register_dataset_nolog(ZFS_IOC_SHARE, zfs_ioc_share,
	    zfs_secpolicy_share, POOL_CHECK_NONE);
	zfs_ioctl_register_dataset_nolog(ZFS_IOC_SMB_ACL, zfs_ioc_smb_acl,
	    zfs_secpolicy_smb_acl, POOL_CHECK_NONE);
	zfs_ioctl_register_dataset_nolog(ZFS_IOC_USERSPACE_UPGRADE,
	    zfs_ioc_userspace_upgrade, zfs_secpolicy_userspace_upgrade,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY);
	zfs_ioctl_register_dataset_nolog(ZFS_IOC_TMP_SNAPSHOT,
	    zfs_ioc_tmp_snapshot, zfs_secpolicy_tmp_snapshot,
	    POOL_CHECK_SUSPENDED | POOL_CHECK_READONLY);

	zfs_ioctl_register_legacy(ZFS_IOC_EVENTS_NEXT, zfs_ioc_events_next,
	    zfs_secpolicy_config, NO_NAME, B_FALSE, POOL_CHECK_NONE);
	zfs_ioctl_register_legacy(ZFS_IOC_EVENTS_CLEAR, zfs_ioc_events_clear,
	    zfs_secpolicy_config, NO_NAME, B_FALSE, POOL_CHECK_NONE);
	zfs_ioctl_register_legacy(ZFS_IOC_EVENTS_SEEK, zfs_ioc_events_seek,
	    zfs_secpolicy_config, NO_NAME, B_FALSE, POOL_CHECK_NONE);

	zfs_ioctl_init_os();
}
```

# Example 5

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/src/unix.c:134:12*

fnptr: *connectionTypeTcp()->read*

targets: connTLSRead

## Related Code Snippets

```c
static int connUnixRead(connection *conn, void *buf, size_t buf_len) {
    return connectionTypeTcp()->read(conn, buf, buf_len);
}
```

```c
ConnectionType *connectionByType(const char *typename) {
    ConnectionType *ct;

    for (int type = 0; type < CONN_TYPE_MAX; type++) {
        ct = connTypes[type];
        if (!ct)
            break;

        if (!strcasecmp(typename, ct->get_type(NULL)))
            return ct;
    }

    serverLog(LL_WARNING, "Missing implement of connection type %s", typename);

    return NULL;
}
```

```c
/* Cache TCP connection type, query it by string once */
ConnectionType *connectionTypeTcp(void) {
    static ConnectionType *ct_tcp = NULL;

    if (ct_tcp != NULL)
        return ct_tcp;

    ct_tcp = connectionByType(CONN_TYPE_SOCKET);
    serverAssert(ct_tcp != NULL);

    return ct_tcp;
}
```

```c
static ConnectionType *connTypes[CONN_TYPE_MAX];

int connTypeRegister(ConnectionType *ct) {
    ...
    serverLog(LL_VERBOSE, "Connection type %s registered", typename);
    connTypes[type] = ct;
    ...
    return C_OK;
}
```

```c
int RedisRegisterConnectionTypeSocket(void)
{
    return connTypeRegister(&CT_Socket);
}
```

```c
int RedisRegisterConnectionTypeTLS(void) {
    return connTypeRegister(&CT_TLS);
}
```

```c
static ConnectionType CT_Socket = {
   ...
    .read = connTLSRead,
    .write = connTLSWrite,
    .writev = connTLSWritev,
    ...
};

static ConnectionType CT_TLS = {
    ...

    .read = connTLSRead,
    .write = connTLSWrite,
    .writev = connTLSWritev,
    ...
}
```


# Example 6

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/deps/hiredis/read.c:323:23*

fnptr: *r->fn->createDouble*

targets: createDoubleObject

## Related Code Snippets

```c
static int processLineItem(redisReader *r) {
    redisReadTask *cur = r->task[r->ridx];
    void *obj;
    char *p;
    int len;

    if ((p = readLine(r,&len)) != NULL) {
        if (cur->type == REDIS_REPLY_INTEGER) {
            ...
        } else if (cur->type == REDIS_REPLY_DOUBLE) {
            ...

            if (r->fn && r->fn->createDouble) {
                obj = r->fn->createDouble(cur,d,buf,len);
            } else {
                obj = (void*)REDIS_REPLY_DOUBLE;
            }
        } else if (cur->type == REDIS_REPLY_NIL) {
		}
	}
	...
    return REDIS_ERR;
}
```

```c
static int processItem(redisReader *r) {
    redisReadTask *cur = r->task[r->ridx];
    ...

    /* process typed item */
    switch(cur->type) {
    case REDIS_REPLY_ERROR:
    case REDIS_REPLY_STATUS:
    case REDIS_REPLY_INTEGER:
    case REDIS_REPLY_DOUBLE:
    case REDIS_REPLY_NIL:
    case REDIS_REPLY_BOOL:
    case REDIS_REPLY_BIGNUM:
        return processLineItem(r);
    case REDIS_REPLY_STRING:
    case REDIS_REPLY_VERB:
        return processBulkItem(r);
    case REDIS_REPLY_ARRAY:
    case REDIS_REPLY_MAP:
    case REDIS_REPLY_SET:
    case REDIS_REPLY_PUSH:
        return processAggregateItem(r);
    default:
        assert(NULL);
        return REDIS_ERR; /* Avoid warning. */
    }
}
```

```c
int redisReaderGetReply(redisReader *r, void **reply) {
    ...

    /* Process items in reply. */
    while (r->ridx >= 0)
        if (processItem(r) != REDIS_OK)
            break;

    ...
    return REDIS_OK;
}
```

```c
static void test_reply_reader(void) {
    redisReader *reader;
    void *reply, *root;
    int ret;
    int i;

    test("Error handling in reply parser: ");
    reader = redisReaderCreate();
    redisReaderFeed(reader,(char*)"@foo\r\n",6);
    ret = redisReaderGetReply(reader,NULL);
	...
}
```

```c
redisReader *redisReaderCreate(void) {
    return redisReaderCreateWithFunctions(&defaultFunctions);
}
```

```c
redisReader *redisReaderCreateWithFunctions(redisReplyObjectFunctions *fn) {
    redisReader *r;

    r = hi_calloc(1,sizeof(redisReader));
    if (r == NULL)
        return NULL;

    r->buf = hi_sdsempty();
    if (r->buf == NULL)
        goto oom;

    r->task = hi_calloc(REDIS_READER_STACK_SIZE, sizeof(*r->task));
    if (r->task == NULL)
        goto oom;

    for (; r->tasks < REDIS_READER_STACK_SIZE; r->tasks++) {
        r->task[r->tasks] = hi_calloc(1, sizeof(**r->task));
        if (r->task[r->tasks] == NULL)
            goto oom;
    }

    r->fn = fn;
    r->maxbuf = REDIS_READER_MAX_BUF;
    r->maxelements = REDIS_READER_MAX_ARRAY_ELEMENTS;
    r->ridx = -1;

    return r;
oom:
    redisReaderFree(r);
    return NULL;
}
```

```c
static redisReplyObjectFunctions defaultFunctions = {
    createStringObject,
    createArrayObject,
    createIntegerObject,
    createDoubleObject,
    createNilObject,
    createBoolObject,
    freeReplyObject
};
```

# Example 7

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/module/os/linux/zfs/zfs_acl.c:1603:14*

fnptr: *aclp->z_ops->ace_size*

targets: zfs_ace_v0_size, zfs_ace_fuid_size

## Related Code Snippets

```c
static void
zfs_acl_chmod(boolean_t isdir, uint64_t mode, boolean_t split, boolean_t trim,
    zfs_acl_t *aclp)
{
	...
	while ((acep = zfs_acl_next_ace(aclp, acep, &who, &access_mask,
	    &iflags, &type))) {
		...
		zfs_set_ace(aclp, zacep, access_mask, type, who, iflags);
		ace_size = aclp->z_ops->ace_size(acep);
		zacep = (void *)((uintptr_t)zacep + ace_size);
		new_count++;
		new_bytes += ace_size;
	}
}
```

```c
int
zfs_acl_chmod_setattr(znode_t *zp, zfs_acl_t **aclp, uint64_t mode)
{
	int error = 0;

	mutex_enter(&zp->z_acl_lock);
	mutex_enter(&zp->z_lock);
	if (ZTOZSB(zp)->z_acl_mode == ZFS_ACL_DISCARD)
		*aclp = zfs_acl_alloc(zfs_acl_version_zp(zp));
	else
		error = zfs_acl_node_read(zp, B_TRUE, aclp, B_TRUE);

	if (error == 0) {
		(*aclp)->z_hints = zp->z_pflags & V4_ACL_WIDE_FLAGS;
		zfs_acl_chmod(S_ISDIR(ZTOI(zp)->i_mode), mode, B_TRUE,
		    (ZTOZSB(zp)->z_acl_mode == ZFS_ACL_GROUPMASK), *aclp);
	}
	mutex_exit(&zp->z_lock);
	mutex_exit(&zp->z_acl_lock);

	return (error);
}
```

```c
int
zfs_acl_ids_create(znode_t *dzp, int flag, vattr_t *vap, cred_t *cr,
    vsecattr_t *vsecp, zfs_acl_ids_t *acl_ids, zidmap_t *mnt_ns)
{
	...

	memset(acl_ids, 0, sizeof (zfs_acl_ids_t));
	acl_ids->z_mode = vap->va_mode;

	...

	if (acl_ids->z_aclp == NULL) {
		...
		if (!(flag & IS_ROOT_NODE) &&
		    (dzp->z_pflags & ZFS_INHERIT_ACE) &&
		    !(dzp->z_pflags & ZFS_XATTR)) {
			...
			acl_ids->z_aclp = zfs_acl_inherit(zfsvfs,
			    vap->va_mode, paclp, acl_ids->z_mode, &need_chmod);
			inherited = B_TRUE;
		} else {
			acl_ids->z_aclp =
			    zfs_acl_alloc(zfs_acl_version_zp(dzp));
			acl_ids->z_aclp->z_hints |= ZFS_ACL_TRIVIAL;
		}
		mutex_exit(&dzp->z_lock);
		mutex_exit(&dzp->z_acl_lock);

		if (need_chmod) {
			if (S_ISDIR(vap->va_mode))
				acl_ids->z_aclp->z_hints |=
				    ZFS_ACL_AUTO_INHERIT;

			if (zfsvfs->z_acl_mode == ZFS_ACL_GROUPMASK &&
			    zfsvfs->z_acl_inherit != ZFS_ACL_PASSTHROUGH &&
			    zfsvfs->z_acl_inherit != ZFS_ACL_PASSTHROUGH_X)
				trim = B_TRUE;
			zfs_acl_chmod(vap->va_mode, acl_ids->z_mode, B_FALSE,
			    trim, acl_ids->z_aclp);
		}
	}

	if (inherited || vsecp) {
		acl_ids->z_mode = zfs_mode_compute(acl_ids->z_mode,
		    acl_ids->z_aclp, &acl_ids->z_aclp->z_hints,
		    acl_ids->z_fuid, acl_ids->z_fgid);
		if (ace_trivial_common(acl_ids->z_aclp, 0, zfs_ace_walk) == 0)
			acl_ids->z_aclp->z_hints |= ZFS_ACL_TRIVIAL;
	}

	return (0);
}
```

```c
static zfs_acl_t *
zfs_acl_inherit(zfsvfs_t *zfsvfs, umode_t va_mode, zfs_acl_t *paclp,
    uint64_t mode, boolean_t *need_chmod)
{
	void		*pacep = NULL;
	void		*acep;
	...

	aclp = zfs_acl_alloc(paclp->z_version);
	aclinherit = zfsvfs->z_acl_inherit;
	if (aclinherit == ZFS_ACL_DISCARD || S_ISLNK(va_mode))
		return (aclp);

	while ((pacep = zfs_acl_next_ace(paclp, pacep, &who,
	    &access_mask, &iflags, &type))) {
			...
	}

	return (aclp);
}
```

```c
zfs_acl_t *
zfs_acl_alloc(int vers)
{
	zfs_acl_t *aclp;

	aclp = kmem_zalloc(sizeof (zfs_acl_t), KM_SLEEP);
	list_create(&aclp->z_acl, sizeof (zfs_acl_node_t),
	    offsetof(zfs_acl_node_t, z_next));
	aclp->z_version = vers;
	if (vers == ZFS_ACL_VERSION_FUID)
		aclp->z_ops = &zfs_acl_fuid_ops;
	else
		aclp->z_ops = &zfs_acl_v0_ops;
	return (aclp);
}
```

```c
static const acl_ops_t zfs_acl_v0_ops = {
	.ace_mask_get = zfs_ace_v0_get_mask,
	.ace_mask_set = zfs_ace_v0_set_mask,
	.ace_flags_get = zfs_ace_v0_get_flags,
	.ace_flags_set = zfs_ace_v0_set_flags,
	.ace_type_get = zfs_ace_v0_get_type,
	.ace_type_set = zfs_ace_v0_set_type,
	.ace_who_get = zfs_ace_v0_get_who,
	.ace_who_set = zfs_ace_v0_set_who,
	.ace_size = zfs_ace_v0_size,
	.ace_abstract_size = zfs_ace_v0_abstract_size,
	.ace_mask_off = zfs_ace_v0_mask_off,
	.ace_data = zfs_ace_v0_data
};

static const acl_ops_t zfs_acl_fuid_ops = {
	.ace_mask_get = zfs_ace_fuid_get_mask,
	.ace_mask_set = zfs_ace_fuid_set_mask,
	.ace_flags_get = zfs_ace_fuid_get_flags,
	.ace_flags_set = zfs_ace_fuid_set_flags,
	.ace_type_get = zfs_ace_fuid_get_type,
	.ace_type_set = zfs_ace_fuid_set_type,
	.ace_who_get = zfs_ace_fuid_get_who,
	.ace_who_set = zfs_ace_fuid_set_who,
	.ace_size = zfs_ace_fuid_size,
	.ace_abstract_size = zfs_ace_fuid_abstract_size,
	.ace_mask_off = zfs_ace_fuid_mask_off,
	.ace_data = zfs_ace_fuid_data
};
```

# Example 8

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/curl-build/lib/../../curl-8.5.0/lib/vtls/vtls.c:1308:10*

fnptr: *Curl_ssl->send_plain*

targets: multissl_send_plain

## Related Code Snippets

```c
static ssize_t multissl_send_plain(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   const void *mem, size_t len,
                                   CURLcode *code)
{
  if(multissl_setup(NULL))
    return CURLE_FAILED_INIT;
  return Curl_ssl->send_plain(cf, data, mem, len, code);
}
```

```c
static const struct Curl_ssl Curl_ssl_multi = {
  { CURLSSLBACKEND_NONE, "multi" },  /* info */
  0, /* supports nothing */
  (size_t)-1, /* something insanely large to be on the safe side */

  multissl_init,                     /* init */
  Curl_none_cleanup,                 /* cleanup */
  multissl_version,                  /* version */
  Curl_none_check_cxn,               /* check_cxn */
  Curl_none_shutdown,                /* shutdown */
  Curl_none_data_pending,            /* data_pending */
  Curl_none_random,                  /* random */
  Curl_none_cert_status_request,     /* cert_status_request */
  multissl_connect,                  /* connect */
  multissl_connect_nonblocking,      /* connect_nonblocking */
  multissl_adjust_pollset,          /* adjust_pollset */
  multissl_get_internals,            /* get_internals */
  multissl_close,                    /* close_one */
  Curl_none_close_all,               /* close_all */
  Curl_none_session_free,            /* session_free */
  Curl_none_set_engine,              /* set_engine */
  Curl_none_set_engine_default,      /* set_engine_default */
  Curl_none_engines_list,            /* engines_list */
  Curl_none_false_start,             /* false_start */
  NULL,                              /* sha256sum */
  NULL,                              /* associate_connection */
  NULL,                              /* disassociate_connection */
  NULL,                              /* free_multi_ssl_backend_data */
  multissl_recv_plain,               /* recv decrypted data */
  multissl_send_plain,               /* send data to encrypt */
};

const struct Curl_ssl *Curl_ssl =
#if defined(CURL_WITH_MULTI_SSL)
  &Curl_ssl_multi;
#elif defined(USE_WOLFSSL)
  &Curl_ssl_wolfssl;
#elif defined(USE_SECTRANSP)
  &Curl_ssl_sectransp;
#elif defined(USE_GNUTLS)
  &Curl_ssl_gnutls;
#elif defined(USE_MBEDTLS)
  &Curl_ssl_mbedtls;
#elif defined(USE_RUSTLS)
  &Curl_ssl_rustls;
#elif defined(USE_OPENSSL)
  &Curl_ssl_openssl;
#elif defined(USE_SCHANNEL)
  &Curl_ssl_schannel;
#elif defined(USE_BEARSSL)
  &Curl_ssl_bearssl;
#else
#error "Missing struct Curl_ssl for selected SSL backend"
#endif
```

```c
struct Curl_ssl {
  /*
   * This *must* be the first entry to allow returning the list of available
   * backends in curl_global_sslset().
   */
  curl_ssl_backend info;
  unsigned int supports; /* bitfield, see above */
  size_t sizeof_ssl_backend_data;

  int (*init)(void);
  void (*cleanup)(void);

  size_t (*version)(char *buffer, size_t size);
  int (*check_cxn)(struct Curl_cfilter *cf, struct Curl_easy *data);
  int (*shut_down)(struct Curl_cfilter *cf,
                   struct Curl_easy *data);
  bool (*data_pending)(struct Curl_cfilter *cf,
                       const struct Curl_easy *data);

  /* return 0 if a find random is filled in */
  CURLcode (*random)(struct Curl_easy *data, unsigned char *entropy,
                     size_t length);
  bool (*cert_status_request)(void);

  CURLcode (*connect_blocking)(struct Curl_cfilter *cf,
                               struct Curl_easy *data);
  CURLcode (*connect_nonblocking)(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  bool *done);

  /* During handshake, adjust the pollset to include the socket
   * for POLLOUT or POLLIN as needed.
   * Mandatory. */
  void (*adjust_pollset)(struct Curl_cfilter *cf, struct Curl_easy *data,
                          struct easy_pollset *ps);
  void *(*get_internals)(struct ssl_connect_data *connssl, CURLINFO info);
  void (*close)(struct Curl_cfilter *cf, struct Curl_easy *data);
  void (*close_all)(struct Curl_easy *data);
  void (*session_free)(void *ptr);

  CURLcode (*set_engine)(struct Curl_easy *data, const char *engine);
  CURLcode (*set_engine_default)(struct Curl_easy *data);
  struct curl_slist *(*engines_list)(struct Curl_easy *data);

  bool (*false_start)(void);
  CURLcode (*sha256sum)(const unsigned char *input, size_t inputlen,
                    unsigned char *sha256sum, size_t sha256sumlen);

  bool (*attach_data)(struct Curl_cfilter *cf, struct Curl_easy *data);
  void (*detach_data)(struct Curl_cfilter *cf, struct Curl_easy *data);

  void (*free_multi_ssl_backend_data)(struct multi_ssl_backend_data *mbackend);

  ssize_t (*recv_plain)(struct Curl_cfilter *cf, struct Curl_easy *data,
                        char *buf, size_t len, CURLcode *code);
  ssize_t (*send_plain)(struct Curl_cfilter *cf, struct Curl_easy *data,
                        const void *mem, size_t len, CURLcode *code);

};
```

# Example 9

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/gcc-clang-build/gcc/../../gcc-13.2.0/gcc/lto-streamer-in.cc:1176:14*

fnptr: *stream_read_tree*

targets: lto_input_tree

## Related Code Snippets

```c
static void
input_ssa_names (class lto_input_block *ib, class data_in *data_in,
		 struct function *fn)
{
  unsigned int i, size;

  size = streamer_read_uhwi (ib);
  init_tree_ssa (fn, size);
  cfun->gimple_df->in_ssa_p = true;
  init_ssa_operands (fn);

  i = streamer_read_uhwi (ib);
  while (i)
    {
      tree ssa_name, name;
      bool is_default_def;

      /* Skip over the elements that had been freed.  */
      while (SSANAMES (fn)->length () < i)
	SSANAMES (fn)->quick_push (NULL_TREE);

      is_default_def = (streamer_read_uchar (ib) != 0);
      name = stream_read_tree (ib, data_in);
      ssa_name = make_ssa_name_fn (fn, name, NULL);

      if (is_default_def)
	{
	  set_ssa_default_def (cfun, SSA_NAME_VAR (ssa_name), ssa_name);
	  SSA_NAME_DEF_STMT (ssa_name) = gimple_build_nop ();
	}

      i = streamer_read_uhwi (ib);
    }
}
```

```c
#define stream_read_tree(IB, DATA_IN) \
    streamer_hooks.read_tree (IB, DATA_IN)
```

```c
void
lto_streamer_hooks_init (void)
{
  streamer_hooks_init ();
  streamer_hooks.write_tree = lto_output_tree;
  streamer_hooks.read_tree = lto_input_tree;
  streamer_hooks.input_location = lto_input_location;
  streamer_hooks.output_location = lto_output_location;
  streamer_hooks.output_location_and_block = lto_output_location_and_block;
}
```

# Example 10

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/openssh-build/../openssh-9.6p1/ssh-ecdsa-sk.c:79:7*

fnptr: *sshkey_ecdsa_funcs.equal*

targets: ssh_ecdsa_equal

## Related Code Snippets

```c
static int
ssh_ecdsa_sk_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (!sshkey_sk_fields_equal(a, b))
		return 0;
	if (!sshkey_ecdsa_funcs.equal(a, b))
		return 0;
	return 1;
}
```

```c
/* NB. not static; used by ECDSA-SK */
const struct sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_size,
	/* .alloc = */		NULL,
	/* .cleanup = */	ssh_ecdsa_cleanup,
	/* .equal = */		ssh_ecdsa_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ecdsa_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ecdsa_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ecdsa_deserialize_private,
	/* .generate = */	ssh_ecdsa_generate,
	/* .copy_public = */	ssh_ecdsa_copy_public,
	/* .sign = */		ssh_ecdsa_sign,
	/* .verify = */		ssh_ecdsa_verify,
};
```

```c
struct sshkey_impl_funcs {
	u_int (*size)(const struct sshkey *);	/* optional */
	int (*alloc)(struct sshkey *);		/* optional */
	void (*cleanup)(struct sshkey *);	/* optional */
	int (*equal)(const struct sshkey *, const struct sshkey *);
	int (*serialize_public)(const struct sshkey *, struct sshbuf *,
	    enum sshkey_serialize_rep);
	int (*deserialize_public)(const char *, struct sshbuf *,
	    struct sshkey *);
	int (*serialize_private)(const struct sshkey *, struct sshbuf *,
	    enum sshkey_serialize_rep);
	int (*deserialize_private)(const char *, struct sshbuf *,
	    struct sshkey *);
	int (*generate)(struct sshkey *, int);	/* optional */
	int (*copy_public)(const struct sshkey *, struct sshkey *);
	int (*sign)(struct sshkey *, u_char **, size_t *,
	    const u_char *, size_t, const char *,
	    const char *, const char *, u_int); /* optional */
	int (*verify)(const struct sshkey *, const u_char *, size_t,
	    const u_char *, size_t, const char *, u_int,
	    struct sshkey_sig_details **);
};
```

# Example 11

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/openssh-build/../openssh-9.6p1/ssh-ed25519-sk.c:64:11*

fnptr: *sshkey_ed25519_funcs.serialize_public*

targets: ssh_ed25519_serialize_public

## Related Code Snippets

```c
static int
ssh_ed25519_sk_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;

	if ((r = sshkey_ed25519_funcs.serialize_public(key, b, opts)) != 0)
		return r;
	if ((r = sshkey_serialize_sk(key, b)) != 0)
		return r;

	return 0;
}
```

```c
/* NB. not static; used by ED25519-SK */
const struct sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		NULL,
	/* .alloc = */		NULL,
	/* .cleanup = */	ssh_ed25519_cleanup,
	/* .equal = */		ssh_ed25519_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ed25519_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ed25519_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ed25519_deserialize_private,
	/* .generate = */	ssh_ed25519_generate,
	/* .copy_public = */	ssh_ed25519_copy_public,
	/* .sign = */		ssh_ed25519_sign,
	/* .verify = */		ssh_ed25519_verify,
};
```

```c
struct sshkey_impl_funcs {
	u_int (*size)(const struct sshkey *);	/* optional */
	int (*alloc)(struct sshkey *);		/* optional */
	void (*cleanup)(struct sshkey *);	/* optional */
	int (*equal)(const struct sshkey *, const struct sshkey *);
	int (*serialize_public)(const struct sshkey *, struct sshbuf *,
	    enum sshkey_serialize_rep);
	int (*deserialize_public)(const char *, struct sshbuf *,
	    struct sshkey *);
	int (*serialize_private)(const struct sshkey *, struct sshbuf *,
	    enum sshkey_serialize_rep);
	int (*deserialize_private)(const char *, struct sshbuf *,
	    struct sshkey *);
	int (*generate)(struct sshkey *, int);	/* optional */
	int (*copy_public)(const struct sshkey *, struct sshkey *);
	int (*sign)(struct sshkey *, u_char **, size_t *,
	    const u_char *, size_t, const char *,
	    const char *, const char *, u_int); /* optional */
	int (*verify)(const struct sshkey *, const u_char *, size_t,
	    const u_char *, size_t, const char *, u_int,
	    struct sshkey_sig_details **);
};
```