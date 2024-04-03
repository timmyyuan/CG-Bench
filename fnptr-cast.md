# Example 1

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/deps/jemalloc/src/hpa_hooks.c:57:2*

fnptr: *nstime_update*

targets: nstime_update_impl

## Related Code Snippets

```c
static void
hpa_hooks_curtime(nstime_t *r_nstime, bool first_reading) {
	if (first_reading) {
		nstime_init_zero(r_nstime);
	}
	nstime_update(r_nstime);
}
```

```c
typedef void (nstime_update_t)(nstime_t *);
extern nstime_update_t *JET_MUTABLE nstime_update;
nstime_update_t *JET_MUTABLE nstime_update = nstime_update_impl;
```

```c
/* Various function pointers are static and immutable except during testing. */
#ifdef JEMALLOC_JET
#  define JET_MUTABLE
#else
#  define JET_MUTABLE const
#endif
```

# Example 2

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/cmd/zed/agents/fmd_api.c:328:3*

fnptr: *ops->fmdo_close*

targets: zfs_fm_close

## Related Code Snippets

```c
void fmd_case_close(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	fmd_module_t *mp = (fmd_module_t *)hdl;
	const fmd_hdl_ops_t *ops = mp->mod_info->fmdi_ops;

	fmd_hdl_debug(hdl, "case closed (%s)", cp->ci_uuid);

	if (ops->fmdo_close != NULL)
		ops->fmdo_close(hdl, cp);

	mp->mod_stats.ms_caseopen.fmds_value.ui64--;
	mp->mod_stats.ms_caseclosed.fmds_value.ui64++;

	if (cp->ci_bufptr != NULL && cp->ci_bufsiz > 0)
		fmd_hdl_free(hdl, cp->ci_bufptr, cp->ci_bufsiz);

	fmd_hdl_free(hdl, cp, sizeof (fmd_case_t));
}
```

```c
int fmd_hdl_register(fmd_hdl_t *hdl, int version, const fmd_hdl_info_t *mip)
{
	(void) version;
	fmd_module_t *mp = (fmd_module_t *)hdl;

	mp->mod_info = mip;
	mp->mod_name = mip->fmdi_desc + 4;	/* drop 'ZFS ' prefix */
	mp->mod_spec = NULL;

	/* bare minimum module stats */
	(void) strcpy(mp->mod_stats.ms_accepted.fmds_name, "fmd.accepted");
	(void) strcpy(mp->mod_stats.ms_caseopen.fmds_name, "fmd.caseopen");
	(void) strcpy(mp->mod_stats.ms_casesolved.fmds_name, "fmd.casesolved");
	(void) strcpy(mp->mod_stats.ms_caseclosed.fmds_name, "fmd.caseclosed");

	fmd_serd_hash_create(&mp->mod_serds);

	fmd_hdl_debug(hdl, "register module");

	return (0);
}
```

```c
void _zfs_retire_init(fmd_hdl_t *hdl)
{
	zfs_retire_data_t *zdp;
	libzfs_handle_t *zhdl;

	if ((zhdl = libzfs_init()) == NULL)
		return;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0) {
		libzfs_fini(zhdl);
		return;
	}

	zdp = fmd_hdl_zalloc(hdl, sizeof (zfs_retire_data_t), FMD_SLEEP);
	zdp->zrd_hdl = zhdl;

	fmd_hdl_setspecific(hdl, zdp);
}
```

```c
static const fmd_hdl_info_t fmd_info = {
	"ZFS Diagnosis Engine", "1.0", &fmd_ops, fmd_props
};
```

```c
static const fmd_hdl_ops_t fmd_ops = {
	zfs_fm_recv,	/* fmdo_recv */
	zfs_fm_timeout,	/* fmdo_timeout */
	zfs_fm_close,	/* fmdo_close */
	NULL,		/* fmdo_stats */
	zfs_fm_gc,	/* fmdo_gc */
};
```

```c
void
fmd_hdl_debug(fmd_hdl_t *hdl, const char *format, ...)
{
	char message[256];
	va_list vargs;
	fmd_module_t *mp = (fmd_module_t *)hdl;

	va_start(vargs, format);
	(void) vsnprintf(message, sizeof (message), format, vargs);
	va_end(vargs);

	/* prefix message with module name */
	zed_log_msg(LOG_INFO, "%s: %s", mp->mod_name, message);
}
```

```c
void
fmd_hdl_free(fmd_hdl_t *hdl, void *data, size_t size)
{
	(void) hdl;
	umem_free(data, size);
}
```

```c
void
fmd_serd_hash_create(fmd_serd_hash_t *shp)
{
	shp->sh_hashlen = FMD_STR_BUCKETS;
	shp->sh_hash = calloc(shp->sh_hashlen, sizeof (void *));
	shp->sh_count = 0;

	if (shp->sh_hash == NULL) {
		perror("calloc");
		exit(EXIT_FAILURE);
	}

}
```

```c
_LIBZFS_H libzfs_handle_t *libzfs_init(void) {
	...
	return (hdl);
}
```

```c
static void
zfs_fm_close(fmd_hdl_t *hdl, fmd_case_t *cs)
{
	zfs_case_t *zcp = fmd_case_getspecific(hdl, cs);

	if (zcp->zc_data.zc_serd_checksum[0] != '\0')
		fmd_serd_destroy(hdl, zcp->zc_data.zc_serd_checksum);
	if (zcp->zc_data.zc_serd_io[0] != '\0')
		fmd_serd_destroy(hdl, zcp->zc_data.zc_serd_io);
	if (zcp->zc_data.zc_has_remove_timer)
		fmd_timer_remove(hdl, zcp->zc_remove_timer);

	uu_list_remove(zfs_cases, zcp);
	uu_list_node_fini(zcp, &zcp->zc_node, zfs_case_pool);
	fmd_hdl_free(hdl, zcp, sizeof (zfs_case_t));
}
```

```c
static void
zfs_fm_gc(fmd_hdl_t *hdl)
{
	zfs_purge_cases(hdl);
}
```

```c
static void
zfs_fm_timeout(fmd_hdl_t *hdl, id_t id, void *data)
{
	zfs_case_t *zcp = data;

	if (id == zcp->zc_remove_timer)
		zfs_case_solve(hdl, zcp, "fault.fs.zfs.vdev.io");
}
```

```c
static void
zfs_fm_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	...
}
```

# Example 3

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/curl-build/lib/../../curl-8.5.0/lib/md5.c:628:6*

fnptr: **md5params->md5_init_func*

targets: my_md5_init

## Related Code Snippets

```c
struct MD5_context *Curl_MD5_init(const struct MD5_params *md5params)
{
  struct MD5_context *ctxt;

  ...

  if((*md5params->md5_init_func)(ctxt->md5_hashctx)) {
    free(ctxt->md5_hashctx);
    free(ctxt);
    return NULL;
  }

  return ctxt;
}
```

```c
/* Decode the challenge message */
CURLcode result = auth_decode_digest_md5_message(chlg,
                                                 nonce, sizeof(nonce),
                                                 realm, sizeof(realm),
                                                 algorithm,
                                                 sizeof(algorithm),
                                                 qop_options,
                                                 sizeof(qop_options)) {
if(result)
  return result;
...
ctxt = Curl_MD5_init(Curl_DIGEST_MD5);
...
}
```

```c
#define CURLX_FUNCTION_CAST(target_type, func) \
  (target_type)(void (*) (void))(func)

```

```c
const struct MD5_params Curl_DIGEST_MD5[] = {
  {
    /* Digest initialization function */
    CURLX_FUNCTION_CAST(Curl_MD5_init_func, my_md5_init),
    /* Digest update function */
    CURLX_FUNCTION_CAST(Curl_MD5_update_func, my_md5_update),
    /* Digest computation end function */
    CURLX_FUNCTION_CAST(Curl_MD5_final_func, my_md5_final),
    /* Size of digest context struct */
    sizeof(my_md5_ctx),
    /* Result size */
    16
  }
};
```

# Example 4

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/curl-build/lib/../../curl-8.5.0/lib/md5.c:641:3*

fnptr: **context->md5_hash->md5_update_func*

targets: my_md5_update

## Related Code Snippets

```c
CURLcode Curl_MD5_update(struct MD5_context *context,
                         const unsigned char *data,
                         unsigned int len)
{
  (*context->md5_hash->md5_update_func)(context->md5_hashctx, data, len);

  return CURLE_OK;
}
```

```c
static CURLcode pop3_perform_apop(struct Curl_easy *data,
                                  struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  ...
  /* Create the digest */
  ctxt = Curl_MD5_init(Curl_DIGEST_MD5);
  if(!ctxt)
     return CURLE_OUT_OF_MEMORY;
  Curl_MD5_update(ctxt, (const unsigned char *) pop3c->apoptimestamp,
                  curlx_uztoui(strlen(pop3c->apoptimestamp)));
  ...
}
```

```c
struct MD5_context *Curl_MD5_init(const struct MD5_params *md5params)
{
  struct MD5_context *ctxt;

  /* Create MD5 context */
  ctxt = malloc(sizeof(*ctxt));
  ...
  ctxt->md5_hash = md5params;
  ...
  return ctxt;
}
```

```c
const struct MD5_params Curl_DIGEST_MD5[] = {
  {
    /* Digest initialization function */
    CURLX_FUNCTION_CAST(Curl_MD5_init_func, my_md5_init),
    /* Digest update function */
    CURLX_FUNCTION_CAST(Curl_MD5_update_func, my_md5_update),
    /* Digest computation end function */
    CURLX_FUNCTION_CAST(Curl_MD5_final_func, my_md5_final),
    /* Size of digest context struct */
    sizeof(my_md5_ctx),
    /* Result size */
    16
  }
};
```

# Example 5

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/gcc-clang-build/gmp/printf/../../../gcc-13.2.0/gmp/printf/doprnti.c:119:7*

fnptr: *funs->memory*

targets: __gmp_asprintf_memory

## Related Code Snippets

```c
int __gmp_doprnt_integer (const struct doprnt_funs_t *funs,
		      void *data,
		      const struct doprnt_params_t *p,
		      const char *s)
{
  ...
  if (den_showbaselen != 0)
  {
    ASSERT (slash != NULL);
    slashlen = slash+1 - s;
    DOPRNT_MEMORY (s, slashlen);                 /* numerator and slash */
    slen -= slashlen;
    s += slashlen;
    DOPRNT_MEMORY (showbase, den_showbaselen);
  }
  ...
}
```

```c
#define DOPRNT_ACCUMULATE(call)						\
  do {									\
    int  __ret;								\
    __ret = call;							\
    if (__ret == -1)							\
      goto error;							\
    retval += __ret;							\
  } while (0)
#define DOPRNT_ACCUMULATE_FUN(fun, params)				\
  do {									\
    ASSERT ((fun) != NULL);						\
    DOPRNT_ACCUMULATE ((*(fun)) params);				\
  } while (0)

#define DOPRNT_MEMORY(ptr, len)						\
  DOPRNT_ACCUMULATE_FUN (funs->memory, (data, ptr, len))
```

```c
ostream& __gmp_doprnt_integer_ostream (ostream &o, struct doprnt_params_t *p,
                              char *s)
{
  struct gmp_asprintf_t   d;
  ...

  GMP_ASPRINTF_T_INIT (d, &result);
  ret = __gmp_doprnt_integer (&__gmp_asprintf_funs_noformat, &d, p, s);
  ...
  return o.write (t.str, t.len);
}
```

```c
typedef int (*doprnt_format_t) (void *, const char *, va_list);
typedef int (*doprnt_memory_t) (void *, const char *, size_t);
typedef int (*doprnt_reps_t)   (void *, int, int);
typedef int (*doprnt_final_t)  (void *);

struct doprnt_funs_t {
  doprnt_format_t  format;
  doprnt_memory_t  memory;
  doprnt_reps_t    reps;
  doprnt_final_t   final;   /* NULL if not required */
};
```

```c
const struct doprnt_funs_t  __gmp_asprintf_funs_noformat = {
  NULL,
  (doprnt_memory_t) __gmp_asprintf_memory,
  (doprnt_reps_t)   __gmp_asprintf_reps,
  NULL
};
```

```c
int
__gmp_asprintf_memory (struct gmp_asprintf_t *d, const char *str, size_t len)
{
  GMP_ASPRINTF_T_NEED (d, len);
  memcpy (d->buf + d->size, str, len);
  d->size += len;
  return len;
}
```

# Example 6

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/module/zfs/dsl_userhold.c:534:3*

fnptr: *holdfunc*

targets: dsl_dataset_hold, dsl_dataset_hold_obj_string

## Related Code Snippets

```c
static void
dsl_dataset_user_release_sync(void *arg, dmu_tx_t *tx)
{
	dsl_dataset_user_release_arg_t *ddura = arg;
	dsl_holdfunc_t *holdfunc = ddura->ddura_holdfunc;
	dsl_pool_t *dp = dmu_tx_pool(tx);

	ASSERT(RRW_WRITE_HELD(&dp->dp_config_rwlock));

	for (nvpair_t *pair = nvlist_next_nvpair(ddura->ddura_chkholds, NULL);
	    pair != NULL; pair = nvlist_next_nvpair(ddura->ddura_chkholds,
	    pair)) {
		dsl_dataset_t *ds;
		const char *name = nvpair_name(pair);

		VERIFY0(holdfunc(dp, name, FTAG, &ds));

		dsl_dataset_user_release_sync_one(ds,
		    fnvpair_value_nvlist(pair), tx);
		if (nvlist_exists(ddura->ddura_todelete, name)) {
			ASSERT(ds->ds_userrefs == 0 &&
			    dsl_dataset_phys(ds)->ds_num_children == 1 &&
			    DS_IS_DEFER_DESTROY(ds));
			dsl_destroy_snapshot_sync_impl(ds, B_FALSE, tx);
		}
		dsl_dataset_rele(ds, FTAG);
	}
}
```

```c
static int
dsl_dataset_user_release_impl(nvlist_t *holds, nvlist_t *errlist,
    dsl_pool_t *tmpdp)
{
	dsl_dataset_user_release_arg_t ddura;
	nvpair_t *pair;
	const char *pool;
	int error;

	pair = nvlist_next_nvpair(holds, NULL);
	if (pair == NULL)
		return (0);

	/*
	 * The release may cause snapshots to be destroyed; make sure they
	 * are not mounted.
	 */
	if (tmpdp != NULL) {
		/* Temporary holds are specified by dsobj string. */
		ddura.ddura_holdfunc = dsl_dataset_hold_obj_string;
		pool = spa_name(tmpdp->dp_spa);
    ...
	} else {
		/* Non-temporary holds are specified by name. */
		ddura.ddura_holdfunc = dsl_dataset_hold;
		pool = nvpair_name(pair);
    ...
	}

	ddura.ddura_holds = holds;
	ddura.ddura_errlist = errlist;
	VERIFY0(nvlist_alloc(&ddura.ddura_todelete, NV_UNIQUE_NAME,
	    KM_SLEEP));
	VERIFY0(nvlist_alloc(&ddura.ddura_chkholds, NV_UNIQUE_NAME,
	    KM_SLEEP));

	error = dsl_sync_task(pool, dsl_dataset_user_release_check,
	    dsl_dataset_user_release_sync, &ddura, 0,
	    ZFS_SPACE_CHECK_EXTRA_RESERVED);
	fnvlist_free(ddura.ddura_todelete);
	fnvlist_free(ddura.ddura_chkholds);

	return (error);
}
```

```c
int
dsl_sync_task(const char *pool, dsl_checkfunc_t *checkfunc,
    dsl_syncfunc_t *syncfunc, void *arg,
    int blocks_modified, zfs_space_check_t space_check)
{
	return (dsl_sync_task_common(pool, checkfunc, syncfunc, NULL, arg,
	    blocks_modified, space_check, B_FALSE));
}
```

```c
static int
dsl_sync_task_common(const char *pool, dsl_checkfunc_t *checkfunc,
    dsl_syncfunc_t *syncfunc, dsl_sigfunc_t *sigfunc, void *arg,
    int blocks_modified, zfs_space_check_t space_check, boolean_t early)
{
	...

	err = spa_open(pool, &spa, FTAG);
	if (err != 0)
		return (err);
	dp = spa_get_dsl(spa);

top:
	tx = dmu_tx_create_dd(dp->dp_mos_dir);
	VERIFY0(dmu_tx_assign(tx, TXG_WAIT));

	dst.dst_pool = dp;
	dst.dst_txg = dmu_tx_get_txg(tx);
	dst.dst_space = blocks_modified << DST_AVG_BLKSHIFT;
	dst.dst_space_check = space_check;
	dst.dst_checkfunc = checkfunc != NULL ? checkfunc : dsl_null_checkfunc;
	dst.dst_syncfunc = syncfunc;
	dst.dst_arg = arg;
	dst.dst_error = 0;
	dst.dst_nowaiter = B_FALSE;

	...

	spa_close(spa, FTAG);
	return (dst.dst_error);
}
```

```c
int
spa_open(const char *name, spa_t **spapp, const void *tag)
{
	return (spa_open_common(name, spapp, tag, NULL, NULL));
}
```

```c
static int
spa_open_common(const char *pool, spa_t **spapp, const void *tag,
    nvlist_t *nvpolicy, nvlist_t **config)
{
	...

	if (spa->spa_state == POOL_STATE_UNINITIALIZED) {
		zpool_load_policy_t policy;

		firstopen = B_TRUE;

		...

		if (state != SPA_LOAD_RECOVER)
			spa->spa_last_ubsync_txg = spa->spa_load_txg = 0;
		spa->spa_config_source = SPA_CONFIG_SRC_CACHEFILE;

		zfs_dbgmsg("spa_open_common: opening %s", pool);
		error = spa_load_best(spa, state, policy.zlp_txg,
		    policy.zlp_rewind);

		if (error == EBADF) {
			...
			return (SET_ERROR(ENOENT));
		}
	}

	return (0);
}
```

```c
static int
spa_load_best(spa_t *spa, spa_load_state_t state, uint64_t max_request,
    int rewind_flags)
{
	nvlist_t *loadinfo = NULL;
	nvlist_t *config = NULL;
	int load_error, rewind_error;
	uint64_t safe_rewind_txg;
	uint64_t min_txg;

	...

	load_error = rewind_error = spa_load(spa, state, SPA_IMPORT_EXISTING);
	if (load_error == 0)
		return (0);
	...
}
```

```c
static int
spa_load(spa_t *spa, spa_load_state_t state, spa_import_type_t type)
{
	const char *ereport = FM_EREPORT_ZFS_POOL;
	int error;

	spa->spa_load_state = state;
	(void) spa_import_progress_set_state(spa_guid(spa),
	    spa_load_state(spa));

	gethrestime(&spa->spa_loaded_ts);
	error = spa_load_impl(spa, type, &ereport);

	...
	(void) spa_import_progress_set_state(spa_guid(spa),
	    spa_load_state(spa));

	return (error);
}
```

```c
static int spa_load_impl(spa_t *spa, spa_import_type_t type, const char **ereport)
{
	int error = 0;
	boolean_t missing_feat_write = B_FALSE;
	boolean_t checkpoint_rewind =
	    (spa->spa_import_flags & ZFS_IMPORT_CHECKPOINT);
	boolean_t update_config_cache = B_FALSE;

	...
	if (spa_writeable(spa) && (spa->spa_load_state == SPA_LOAD_RECOVER ||
	    spa->spa_load_max_txg == UINT64_MAX)) {
		uint64_t config_cache_txg = spa->spa_config_txg;

		...

		/*
		 * Traverse the ZIL and claim all blocks.
		 */
		spa_ld_claim_log_blocks(spa);

		/*
		 * Kick-off the syncing thread.
		 */
		spa->spa_sync_on = B_TRUE;
		txg_sync_start(spa->spa_dsl_pool);
		mmp_thread_start(spa);

		...
  }

	spa_load_note(spa, "LOADED");

	return (0);
}
```

```c
void
txg_sync_start(dsl_pool_t *dp)
{
	...

	tx->tx_quiesce_thread = thread_create(NULL, 0, txg_quiesce_thread,
	    dp, 0, &p0, TS_RUN, defclsyspri);

	tx->tx_sync_thread = thread_create(NULL, 0, txg_sync_thread,
	    dp, 0, &p0, TS_RUN, defclsyspri);

	mutex_exit(&tx->tx_sync_lock);
}
```

```c
static __attribute__((noreturn)) void
txg_sync_thread(void *arg)
{
	dsl_pool_t *dp = arg;
	spa_t *spa = dp->dp_spa;
	tx_state_t *tx = &dp->dp_tx;
	callb_cpr_t cpr;
	clock_t start, delta;

	(void) spl_fstrans_mark();
	txg_thread_enter(tx, &cpr);

	start = delta = 0;
	for (;;) {
		...

		txg_stat_t *ts = spa_txg_history_init_io(spa, txg, dp);
		start = ddi_get_lbolt();
		spa_sync(spa, txg);
		...
		txg_dispatch_callbacks(dp, txg);
	}
}
```

```c
void
spa_sync(spa_t *spa, uint64_t txg)
{
	vdev_t *vd = NULL;

	VERIFY(spa_writeable(spa));

	...

	spa_sync_adjust_vdev_max_queue_depth(spa);

	spa_sync_condense_indirect(spa, tx);

	spa_sync_iterate_to_convergence(spa, tx);

  ...

	dsl_pool_sync_done(dp, txg);
	...
	spa->spa_ubsync = spa->spa_uberblock;
	spa_config_exit(spa, SCL_CONFIG, FTAG);

	spa_handle_ignored_writes(spa);

	spa_async_dispatch(spa);
}
```

```c
static void
spa_sync_iterate_to_convergence(spa_t *spa, dmu_tx_t *tx)
{
  ...

	do {
		int pass = ++spa->spa_sync_pass;
    ...
		dsl_pool_sync(dp, txg);

		...
		spa_sync_deferred_frees(spa, tx);
	} while (dmu_objset_is_dirty(mos, txg));
}
```

```c
void
dsl_pool_sync(dsl_pool_t *dp, uint64_t txg)
{
	...

	list_create(&synced_datasets, sizeof (dsl_dataset_t),
	    offsetof(dsl_dataset_t, ds_synced_link));

	tx = dmu_tx_create_assigned(dp, txg);
	...
	if (!txg_list_empty(&dp->dp_sync_tasks, txg)) {
		dsl_sync_task_t *dst;

		ASSERT3U(spa_sync_pass(dp->dp_spa), ==, 1);
		while ((dst =
		    txg_list_remove(&dp->dp_early_sync_tasks, txg)) != NULL) {
			ASSERT(dsl_early_sync_task_verify(dp, txg));
			dsl_sync_task_sync(dst, tx);
		}
	}

	dmu_tx_commit(tx);

	DTRACE_PROBE2(dsl_pool_sync__done, dsl_pool_t *dp, dp, uint64_t, txg);
}
```

```c
void
dsl_sync_task_sync(dsl_sync_task_t *dst, dmu_tx_t *tx)
{
	...

	rrw_enter(&dp->dp_config_rwlock, RW_WRITER, FTAG);
	dst->dst_error = dst->dst_checkfunc(dst->dst_arg, tx);
	if (dst->dst_error == 0)
		dst->dst_syncfunc(dst->dst_arg, tx);
	rrw_exit(&dp->dp_config_rwlock, FTAG);
	if (dst->dst_nowaiter)
		kmem_free(dst, sizeof (*dst));
}
```

# Example 7

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/module/zcommon/zfs_fletcher.c:887:4*

fnptr: *ops->compute_native*

targets: fletcher_4_scalar_native, fletcher_4_superscalar_native, fletcher_4_superscalar4_native

## Related Code Snippets

```c
static int
abd_fletcher_4_iter(void *data, size_t size, void *private)
{
	zio_abd_checksum_data_t *cdp = (zio_abd_checksum_data_t *)private;
	fletcher_4_ctx_t *ctx = cdp->acd_ctx;
	fletcher_4_ops_t *ops = (fletcher_4_ops_t *)cdp->acd_private;
	boolean_t native = cdp->acd_byteorder == ZIO_CHECKSUM_NATIVE;
	uint64_t asize = P2ALIGN(size, FLETCHER_MIN_SIMD_SIZE);

	ASSERT(IS_P2ALIGNED(size, sizeof (uint32_t)));

	if (asize > 0) {
		if (native)
			ops->compute_native(ctx, data, asize);
		else
			ops->compute_byteswap(ctx, data, asize);

		size -= asize;
		data = (char *)data + asize;
	}

	if (size > 0) {
		ASSERT3U(size, <, FLETCHER_MIN_SIMD_SIZE);
		/* At this point we have to switch to scalar impl */
		abd_fletcher_4_simd2scalar(native, data, size, cdp);
	}

	return (0);
}

zio_abd_checksum_func_t fletcher_4_abd_ops = {
	.acf_init = abd_fletcher_4_init,
	.acf_fini = abd_fletcher_4_fini,
	.acf_iter = abd_fletcher_4_iter
};
```

```c
typedef const struct zio_abd_checksum_func {
	zio_abd_checksum_init_t *acf_init;
	zio_abd_checksum_fini_t *acf_fini;
	zio_abd_checksum_iter_t *acf_iter;
} zio_abd_checksum_func_t;
```

```c
static inline void
abd_fletcher_4_impl(abd_t *abd, uint64_t size, zio_abd_checksum_data_t *acdp)
{
	fletcher_4_abd_ops.acf_init(acdp);
	abd_iterate_func(abd, 0, size, fletcher_4_abd_ops.acf_iter, acdp);
	fletcher_4_abd_ops.acf_fini(acdp);
}
```

```c
static void
abd_fletcher_4_init(zio_abd_checksum_data_t *cdp)
{
	const fletcher_4_ops_t *ops = fletcher_4_impl_get();
	cdp->acd_private = (void *) ops;

	if (ops->uses_fpu == B_TRUE) {
		kfpu_begin();
	}
	if (cdp->acd_byteorder == ZIO_CHECKSUM_NATIVE)
		ops->init_native(cdp->acd_ctx);
	else
		ops->init_byteswap(cdp->acd_ctx);

}
```

```c
typedef int abd_iter_func_t(void *buf, size_t len, void *priv);
```

```c
static inline const fletcher_4_ops_t *
fletcher_4_impl_get(void)
{
	if (!kfpu_allowed())
		return (&fletcher_4_superscalar4_ops);

	const fletcher_4_ops_t *ops = NULL;
	uint32_t impl = IMPL_READ(fletcher_4_impl_chosen);

	switch (impl) {
	case IMPL_FASTEST:
		ASSERT(fletcher_4_initialized);
		ops = &fletcher_4_fastest_impl;
		break;
	case IMPL_CYCLE:
		/* Cycle through supported implementations */
		ASSERT(fletcher_4_initialized);
		ASSERT3U(fletcher_4_supp_impls_cnt, >, 0);
		static uint32_t cycle_count = 0;
		uint32_t idx = (++cycle_count) % fletcher_4_supp_impls_cnt;
		ops = fletcher_4_supp_impls[idx];
		break;
	default:
		ASSERT3U(fletcher_4_supp_impls_cnt, >, 0);
		ASSERT3U(impl, <, fletcher_4_supp_impls_cnt);
		ops = fletcher_4_supp_impls[impl];
		break;
	}

	ASSERT3P(ops, !=, NULL);

	return (ops);
}
```

```c
static const fletcher_4_ops_t fletcher_4_scalar_ops = {
	.init_native = fletcher_4_scalar_init,
	.fini_native = fletcher_4_scalar_fini,
	.compute_native = fletcher_4_scalar_native,
	.init_byteswap = fletcher_4_scalar_init,
	.fini_byteswap = fletcher_4_scalar_fini,
	.compute_byteswap = fletcher_4_scalar_byteswap,
	.valid = fletcher_4_scalar_valid,
	.uses_fpu = B_FALSE,
	.name = "scalar"
};

static fletcher_4_ops_t fletcher_4_fastest_impl = {
	.name = "fastest",
	.valid = fletcher_4_scalar_valid
};

static const fletcher_4_ops_t *fletcher_4_impls[] = {
	&fletcher_4_scalar_ops,
	&fletcher_4_superscalar_ops,
	&fletcher_4_superscalar4_ops,
#if defined(HAVE_SSE2)
	&fletcher_4_sse2_ops,
#endif
#if defined(HAVE_SSE2) && defined(HAVE_SSSE3)
	&fletcher_4_ssse3_ops,
#endif
#if defined(HAVE_AVX) && defined(HAVE_AVX2)
	&fletcher_4_avx2_ops,
#endif
#if defined(__x86_64) && defined(HAVE_AVX512F)
	&fletcher_4_avx512f_ops,
#endif
#if defined(__x86_64) && defined(HAVE_AVX512BW)
	&fletcher_4_avx512bw_ops,
#endif
#if defined(__aarch64__) && !defined(__FreeBSD__)
	&fletcher_4_aarch64_neon_ops,
#endif
};
```

```c
const fletcher_4_ops_t fletcher_4_superscalar_ops = {
	.init_native = fletcher_4_superscalar_init,
	.compute_native = fletcher_4_superscalar_native,
	.fini_native = fletcher_4_superscalar_fini,
	.init_byteswap = fletcher_4_superscalar_init,
	.compute_byteswap = fletcher_4_superscalar_byteswap,
	.fini_byteswap = fletcher_4_superscalar_fini,
	.valid = fletcher_4_superscalar_valid,
	.uses_fpu = B_FALSE,
	.name = "superscalar"
};
```

```c
const fletcher_4_ops_t fletcher_4_superscalar4_ops = {
	.init_native = fletcher_4_superscalar4_init,
	.compute_native = fletcher_4_superscalar4_native,
	.fini_native = fletcher_4_superscalar4_fini,
	.init_byteswap = fletcher_4_superscalar4_init,
	.compute_byteswap = fletcher_4_superscalar4_byteswap,
	.fini_byteswap = fletcher_4_superscalar4_fini,
	.valid = fletcher_4_superscalar4_valid,
	.uses_fpu = B_FALSE,
	.name = "superscalar4"
};
```

