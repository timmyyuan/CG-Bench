# Example 1

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/src/t_zset.c:3102:9*

fnptr: *handler->finalizeResultEmission*

targets: zrangeResultFinalizeClient, zrangeResultFinalizeStore

## Related Code Snippets

```c
void genericZrangebyrankCommand(zrange_result_handler *handler,
    robj *zobj, long start, long end, int withscores, int reverse) {
    if (start > end || start >= llen) {
        handler->beginResultEmission(handler, 0);
        handler->finalizeResultEmission(handler, 0);
        return;
    }
}

static void zrangeResultHandlerInit(zrange_result_handler *handler,
    client *client, zrange_consumer_type type)
{
    memset(handler, 0, sizeof(*handler));

    handler->client = client;

    switch (type) {
    case ZRANGE_CONSUMER_TYPE_CLIENT:
        handler->beginResultEmission = zrangeResultBeginClient;
        handler->finalizeResultEmission = zrangeResultFinalizeClient;
        handler->emitResultFromCBuffer = zrangeResultEmitCBufferToClient;
        handler->emitResultFromLongLong = zrangeResultEmitLongLongToClient;
        break;

    case ZRANGE_CONSUMER_TYPE_INTERNAL:
        handler->beginResultEmission = zrangeResultBeginStore;
        handler->finalizeResultEmission = zrangeResultFinalizeStore;
        handler->emitResultFromCBuffer = zrangeResultEmitCBufferForStore;
        handler->emitResultFromLongLong = zrangeResultEmitLongLongForStore;
        break;
    }
}
```

```c
void zrangestoreCommand (client *c) {
    robj *dstkey = c->argv[1];
    zrange_result_handler handler;
    zrangeResultHandlerInit(&handler, c, ZRANGE_CONSUMER_TYPE_INTERNAL);
    zrangeResultHandlerDestinationKeySet(&handler, dstkey);
    zrangeGenericCommand(&handler, 2, 1, ZRANGE_AUTO, ZRANGE_DIRECTION_AUTO);
}
```

```c
void zrangeGenericCommand(zrange_result_handler *handler, int argc_start, int store,
                          zrange_type rangetype, zrange_direction direction)
{
    switch (rangetype) {
    case ZRANGE_AUTO:
    case ZRANGE_RANK:
        genericZrangebyrankCommand(handler, zobj, opt_start, opt_end,
            opt_withscores || store, direction == ZRANGE_DIRECTION_REVERSE);
        break;

    case ZRANGE_SCORE:
        genericZrangebyscoreCommand(handler, &range, zobj, opt_offset,
            opt_limit, direction == ZRANGE_DIRECTION_REVERSE);
        break;

    case ZRANGE_LEX:
        genericZrangebylexCommand(handler, &lexrange, zobj, opt_withscores || store,
            opt_offset, opt_limit, direction == ZRANGE_DIRECTION_REVERSE);
        break;
    }
}
```

```c
static void zrangeResultBeginClient(zrange_result_handler *handler, long length) {
    if (length > 0) {
        /* In case of WITHSCORES, respond with a single array in RESP2, and
        * nested arrays in RESP3. We can't use a map response type since the
        * client library needs to know to respect the order. */
        if (handler->withscores && (handler->client->resp == 2)) {
            length *= 2;
        }
        addReplyArrayLen(handler->client, length);
        handler->userdata = NULL;
        return;
    }
    handler->userdata = addReplyDeferredLen(handler->client);
}
```

```c
static void zrangeResultFinalizeClient(zrange_result_handler *handler,
    size_t result_count)
{
    /* If the reply size was know at start there's nothing left to do */
    if (!handler->userdata)
        return;
    /* In case of WITHSCORES, respond with a single array in RESP2, and
     * nested arrays in RESP3. We can't use a map response type since the
     * client library needs to know to respect the order. */
    if (handler->withscores && (handler->client->resp == 2)) {
        result_count *= 2;
    }

    setDeferredArrayLen(handler->client, handler->userdata, result_count);
}
```

```c
static void zrangeResultEmitCBufferToClient(zrange_result_handler *handler,
    const void *value, size_t value_length_in_bytes, double score)
{
    if (handler->should_emit_array_length) {
        addReplyArrayLen(handler->client, 2);
    }

    addReplyBulkCBuffer(handler->client, value, value_length_in_bytes);

    if (handler->withscores) {
        addReplyDouble(handler->client, score);
    }
}
```

```c
static void zrangeResultEmitLongLongToClient(zrange_result_handler *handler,
    long long value, double score)
{
    if (handler->should_emit_array_length) {
        addReplyArrayLen(handler->client, 2);
    }

    addReplyBulkLongLong(handler->client, value);

    if (handler->withscores) {
        addReplyDouble(handler->client, score);
    }
}
```

```c
static void zrangeResultBeginStore(zrange_result_handler *handler, long length)
{
    handler->dstobj = zsetTypeCreate(length, 0);
}
```

```c
static void zrangeResultFinalizeStore(zrange_result_handler *handler, size_t result_count)
{
    if (result_count) {
        setKey(handler->client, handler->client->db, handler->dstkey, handler->dstobj, 0);
        addReplyLongLong(handler->client, result_count);
        notifyKeyspaceEvent(NOTIFY_ZSET, "zrangestore", handler->dstkey, handler->client->db->id);
        server.dirty++;
    } else {
        addReply(handler->client, shared.czero);
        if (dbDelete(handler->client->db, handler->dstkey)) {
            signalModifiedKey(handler->client, handler->client->db, handler->dstkey);
            notifyKeyspaceEvent(NOTIFY_GENERIC, "del", handler->dstkey, handler->client->db->id);
            server.dirty++;
        }
    }
    decrRefCount(handler->dstobj);
}
```

```c
static void zrangeResultEmitCBufferForStore(zrange_result_handler *handler,
    const void *value, size_t value_length_in_bytes, double score)
{
    double newscore;
    int retflags = 0;
    sds ele = sdsnewlen(value, value_length_in_bytes);
    int retval = zsetAdd(handler->dstobj, score, ele, ZADD_IN_NONE, &retflags, &newscore);
    sdsfree(ele);
    serverAssert(retval);
}
```

```c
static void zrangeResultEmitLongLongForStore(zrange_result_handler *handler,
    long long value, double score)
{
    double newscore;
    int retflags = 0;
    sds ele = sdsfromlonglong(value);
    int retval = zsetAdd(handler->dstobj, score, ele, ZADD_IN_NONE, &retflags, &newscore);
    sdsfree(ele);
    serverAssert(retval);
}
```

# Example 2

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/gcc-clang-build/build-x86_64-pc-linux-gnu/libcpp/../../../gcc-13.2.0/libcpp/directives.cc:2611:5*

fnptr: *pfile->cb.before_define*

targets: dump_queued_macros

## Related Code Snippets

```c
static void
cpp_pop_definition (cpp_reader *pfile, struct def_pragma_macro *c)
{
  cpp_hashnode *node = _cpp_lex_identifier (pfile, c->name);
  if (node == NULL)
    return;

  if (pfile->cb.before_define)
    pfile->cb.before_define (pfile);
  ...
}
```

```c
if (flag_dump_macros == 'U')
  {
    cb->before_define = dump_queued_macros;
    cb->used_define = cb_used_define;
    cb->used_undef = cb_used_undef;
  }
```

```c
if (gfc_cpp_option.dump_macros == 'U')
  {
    cb->before_define = dump_queued_macros;
  ...
   
  }
```

# Example 3

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/ffmpeg-6.1.1/libavcodec/aaccoder.c:671:5*

fnptr: *s->abs_pow34*

targets: ff_abs_pow34_sse, abs_pow34_v

## Related Code Snippets

```c
av_cold void ff_aac_dsp_init_x86(AACEncContext *s)
{
    int cpu_flags = av_get_cpu_flags();

    if (EXTERNAL_SSE(cpu_flags))
        s->abs_pow34   = ff_abs_pow34_sse;

    if (EXTERNAL_SSE2(cpu_flags))
        s->quant_bands = ff_aac_quantize_bands_sse2;
}
```

```c
static av_cold int aac_encode_init(AVCodecContext *avctx)
{
    AACEncContext *s = avctx->priv_data;
    ...
    s->random_state = 0x1f2e3d4c;
    
    s->abs_pow34   = abs_pow34_v;
    s->quant_bands = quantize_bands;
    ...
}
```

```c
static void search_for_quantizers_fast(AVCodecContext *avctx, AACEncContext *s,
                                       SingleChannelElement *sce,
                                       const float lambda)
{
    int start = 0, i, w, w2, g;
    ...
    if (!allz)
        return;
    s->abs_pow34(s->scoefs, sce->coeffs, 1024);
    ff_quantize_band_cost_cache_init(s);
    ...
}
```

# Example 4

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/wrk-4.2.0/src/ae.c:322:22*

fnptr: *te->timeProc*

targets: record_rate

## Related Code Snippets

```c
/* Process time events */
static int processTimeEvents(aeEventLoop *eventLoop) {
    int processed = 0;
    ...
    while(te) {
        ...
        aeGetTime(&now_sec, &now_ms);
        if (now_sec > te->when_sec ||
            (now_sec == te->when_sec && now_ms >= te->when_ms))
        {
            ...
            retval = te->timeProc(eventLoop, id, te->clientData);
            ...
        }
        return processed;
    }
}
```

```c
void *thread_main(void *arg) {
    thread *thread = arg;
    ...
    aeEventLoop *loop = thread->loop;
    aeCreateTimeEvent(loop, RECORD_INTERVAL_MS, record_rate, thread, NULL);

    ...
    aeMain(loop);
    ...
    return NULL;
}
```

```c
long long aeCreateTimeEvent(aeEventLoop *eventLoop, long long milliseconds,
        aeTimeProc *proc, void *clientData,
        aeEventFinalizerProc *finalizerProc)
{
    ...
    te->timeProc = proc;
    ...
    return id;
}
```

```c
void aeMain(aeEventLoop *eventLoop) {
    eventLoop->stop = 0;
    while (!eventLoop->stop) {
        if (eventLoop->beforesleep != NULL)
            eventLoop->beforesleep(eventLoop);
        aeProcessEvents(eventLoop, AE_ALL_EVENTS);
    }
}
```

```c
int aeProcessEvents(aeEventLoop *eventLoop, int flags)
{
    ...
    /* Check time events */
    if (flags & AE_TIME_EVENTS)
        processed += processTimeEvents(eventLoop);

    return processed; /* return the number of processed file/time events */
}
```

# Example 5

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/cmd/zdb/zdb.c:442:10*

fnptr: *uic->uic_cb*

targets: spacemap_check_sm_log_cb, load_unflushed_cb, load_unflushed_svr_segs_cb, count_unflushed_space_cb, log_spacemap_obsolete_stats_cb

## Related Code Snippets

```c
static int iterate_through_spacemap_logs_cb(space_map_entry_t *sme, void *arg)
{
	unflushed_iter_cb_arg_t *uic = arg;
	return (uic->uic_cb(uic->uic_spa, sme, uic->uic_txg, uic->uic_arg));
}
```

```c
static void iterate_through_spacemap_logs(spa_t *spa, zdb_log_sm_cb_t cb, void *arg)
{
	if (!spa_feature_is_active(spa, SPA_FEATURE_LOG_SPACEMAP))
		return;

	spa_config_enter(spa, SCL_CONFIG, FTAG, RW_READER);
	for (spa_log_sm_t *sls = avl_first(&spa->spa_sm_logs_by_txg);
	    sls; sls = AVL_NEXT(&spa->spa_sm_logs_by_txg, sls)) {
		...

		unflushed_iter_cb_arg_t uic = {
			.uic_spa = spa,
			.uic_txg = sls->sls_txg,
			.uic_arg = arg,
			.uic_cb = cb
		};
		VERIFY0(space_map_iterate(sm, space_map_length(sm),
		    iterate_through_spacemap_logs_cb, &uic));
		space_map_close(sm);
	}
	spa_config_exit(spa, SCL_CONFIG, FTAG);
}
```

```c
int space_map_iterate(space_map_t *sm, uint64_t end, sm_cb_t callback, void *arg)
{
	uint64_t blksz = sm->sm_blksz;

	...
	for (uint64_t block_base = 0; block_base < end && error == 0;
	    block_base += blksz) {
		...

		for (uint64_t *block_cursor = block_start;
		    block_cursor < block_end && error == 0; block_cursor++) {
			uint64_t e = *block_cursor;

			...
			error = callback(&sme, arg);
		}
		dmu_buf_rele(db, FTAG);
	}
	return (error);
}
```

```c
static void spacemap_check_sm_log(spa_t *spa, metaslab_verify_t *mv)
{
	iterate_through_spacemap_logs(spa, spacemap_check_sm_log_cb, mv);
}
```

```c
static void load_unflushed_to_ms_allocatables(spa_t *spa, maptype_t maptype)
{
	iterate_through_spacemap_logs(spa, load_unflushed_cb, &maptype);
}
```

```c
static void zdb_claim_removing(spa_t *spa, zdb_cb_t *zcb)
{
	...
	iterate_through_spacemap_logs(spa, load_unflushed_svr_segs_cb, svr);
        ...
}
```

```c
static int64_t get_unflushed_alloc_space(spa_t *spa)
{
	if (dump_opt['L'])
		return (0);

	int64_t ualloc_space = 0;
	iterate_through_spacemap_logs(spa, count_unflushed_space_cb,
	    &ualloc_space);
	return (ualloc_space);
}
```

```c
static void dump_log_spacemap_obsolete_stats(spa_t *spa)
{
	...
	iterate_through_spacemap_logs(spa,
	    log_spacemap_obsolete_stats_cb, &lsos);
    ...
}
```

# Example 6

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/src/dict.c:1143:29*

fnptr: *defragalloc*

targets: activeDefragAlloc

## Related Code Snippets

```c
static void dictDefragBucket(dict *d, dictEntry **bucketref, dictDefragFunctions *defragfns) {
    dictDefragAllocFunction *defragalloc = defragfns->defragAlloc;
    dictDefragAllocFunction *defragkey = defragfns->defragKey;
    dictDefragAllocFunction *defragval = defragfns->defragVal;
    while (bucketref && *bucketref) {
        dictEntry *de = *bucketref, *newde = NULL;
        void *newkey = defragkey ? defragkey(dictGetKey(de)) : NULL;
        void *newval = defragval ? defragval(dictGetVal(de)) : NULL;
        if (entryIsKey(de)) {
            if (newkey) *bucketref = newkey;
            assert(entryIsKey(*bucketref));
        } else if (entryIsNoValue(de)) {
            dictEntryNoValue *entry = decodeEntryNoValue(de), *newentry;
            if ((newentry = defragalloc(entry))) {
                newde = encodeMaskedPtr(newentry, ENTRY_PTR_NO_VALUE);
                entry = newentry;
            }
        }
    }
}
```

```c
unsigned long dictScanDefrag(dict *d,
                             unsigned long v,
                             dictScanFunction *fn,
                             dictDefragFunctions *defragfns,
                             void *privdata)
{
    ...
    if (!dictIsRehashing(d)) {
        ...

        /* Emit entries at cursor */
        if (defragfns) {
            dictDefragBucket(d, &d->ht_table[htidx0][v & m0], defragfns);
        }
        ...
    } else {
        ...
        if (defragfns) {
            dictDefragBucket(d, &d->ht_table[htidx0][v & m0], defragfns);
        }
        ...
        do {
            if (defragfns) {
                dictDefragBucket(d, &d->ht_table[htidx1][v & m1], defragfns);
            }
            ...
        } while (v & (m0 ^ m1));
    }
    return v;
}
```

```c
void activeDefragCycle(void) {
    ...

    dictDefragFunctions defragfns = {.defragAlloc = activeDefragAlloc};
    do {
        do {
            ...

            /* Scan the keyspace dict unless we're scanning the expire dict. */
            if (!expires_cursor)
                cursor = dictScanDefrag(db->dict, cursor, defragScanCallback,
                                        &defragfns, db);

            /* When done scanning the keyspace dict, we scan the expire dict. */
            if (!cursor)
                expires_cursor = dictScanDefrag(db->expires, expires_cursor,
                                                scanCallbackCountScanned,
                                                &defragfns, NULL);
            ...
        }
    }
}
```

```c
void scanLaterZset(robj *ob, unsigned long *cursor) {
    if (ob->type != OBJ_ZSET || ob->encoding != OBJ_ENCODING_SKIPLIST)
        return;
    zset *zs = (zset*)ob->ptr;
    dict *d = zs->dict;
    scanLaterZsetData data = {zs};
    dictDefragFunctions defragfns = {.defragAlloc = activeDefragAlloc};
    *cursor = dictScanDefrag(d, *cursor, scanLaterZsetCallback, &defragfns, &data);
}
```

```c
void scanLaterSet(robj *ob, unsigned long *cursor) {
    if (ob->type != OBJ_SET || ob->encoding != OBJ_ENCODING_HT)
        return;
    dict *d = ob->ptr;
    dictDefragFunctions defragfns = {
        .defragAlloc = activeDefragAlloc,
        .defragKey = (dictDefragAllocFunction *)activeDefragSds
    };
    *cursor = dictScanDefrag(d, *cursor, scanCallbackCountScanned, &defragfns, NULL);
}
```

```c
void scanLaterHash(robj *ob, unsigned long *cursor) {
    if (ob->type != OBJ_HASH || ob->encoding != OBJ_ENCODING_HT)
        return;
    dict *d = ob->ptr;
    dictDefragFunctions defragfns = {
        .defragAlloc = activeDefragAlloc,
        .defragKey = (dictDefragAllocFunction *)activeDefragSds,
        .defragVal = (dictDefragAllocFunction *)activeDefragSds
    };
    *cursor = dictScanDefrag(d, *cursor, scanCallbackCountScanned, &defragfns, NULL);
}
```

```c
unsigned long dictScan(dict *d,
                       unsigned long v,
                       dictScanFunction *fn,
                       void *privdata)
{
    return dictScanDefrag(d, v, fn, NULL, privdata);
}
```

# Example 7

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/src/functions.c:428:13*

fnptr: *engine->get_engine_memory_overhead*

targets: luaEngineMemoryOverhead

## Related Code Snippets

```c
int functionsRegisterEngine(const char *engine_name, engine *engine) {
    sds engine_name_sds = sdsnew(engine_name);
    if (dictFetchValue(engines, engine_name_sds)) {
        serverLog(LL_WARNING, "Same engine was registered twice");
        sdsfree(engine_name_sds);
        return C_ERR;
    }

    client *c = createClient(NULL);
    c->flags |= (CLIENT_DENY_BLOCKING | CLIENT_SCRIPT);
    engineInfo *ei = zmalloc(sizeof(*ei));
    *ei = (engineInfo ) { .name = engine_name_sds, .engine = engine, .c = c,};

    dictAdd(engines, engine_name_sds, ei);

    engine_cache_memory += zmalloc_size(ei) + sdsZmallocSize(ei->name) +
            zmalloc_size(engine) +
            engine->get_engine_memory_overhead(engine->engine_ctx);

    return C_OK;
}
```

```c
int luaEngineInitEngine(void) {
    luaEngineCtx *lua_engine_ctx = zmalloc(sizeof(*lua_engine_ctx));
    lua_engine_ctx->lua = lua_open();

    ...


    engine *lua_engine = zmalloc(sizeof(*lua_engine));
    *lua_engine = (engine) {
        .engine_ctx = lua_engine_ctx,
        .create = luaEngineCreate,
        .call = luaEngineCall,
        .get_used_memory = luaEngineGetUsedMemoy,
        .get_function_memory_overhead = luaEngineFunctionMemoryOverhead,
        .get_engine_memory_overhead = luaEngineMemoryOverhead,
        .free_function = luaEngineFreeFunction,
    };
    return functionsRegisterEngine(LUA_ENGINE_NAME, lua_engine);
}
```

# Example 8

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/wrk-4.2.0/obj/openssl-1.1.1i/crypto/evp/p_lib.c:42:12*

fnptr: *pkey->ameth->pkey_security_bits*

targets: NULL

## Related Code Snippets

```c
int EVP_PKEY_security_bits(const EVP_PKEY *pkey)
{
    if (pkey == NULL)
        return 0;
    if (!pkey->ameth || !pkey->ameth->pkey_security_bits)
        return -2;
    return pkey->ameth->pkey_security_bits(pkey);
}
```

```c
void EVP_PKEY_asn1_set_security_bits(EVP_PKEY_ASN1_METHOD *ameth,
                                     int (*pkey_security_bits) (const EVP_PKEY
                                                                *pk))
{
    ameth->pkey_security_bits = pkey_security_bits;
}
```

# Example 9

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/wrk-4.2.0/obj/openssl-1.1.1i/apps/s_cb.c:1356:10*

fnptr: *sdb->old_cb*

targets: ssl_security_default_callback

## Related Code Snippets

```c
static int security_callback_debug(const SSL *s, const SSL_CTX *ctx,
                                   int op, int bits, int nid,
                                   void *other, void *ex)
{
    security_debug_ex *sdb = ex;
    int rv, show_bits = 1, cert_md = 0;
    const char *nm;
    int show_nm;
    rv = sdb->old_cb(s, ctx, op, bits, nid, other, ex);
}
```

```c
void ssl_ctx_security_debug(SSL_CTX *ctx, int verbose)
{
    static security_debug_ex sdb;

    sdb.out = bio_err;
    sdb.verbose = verbose;
    sdb.old_cb = SSL_CTX_get_security_callback(ctx);
    SSL_CTX_set_security_callback(ctx, security_callback_debug);
    SSL_CTX_set0_security_ex_data(ctx, &sdb);
}
```

```c
void SSL_CTX_set_security_callback(SSL_CTX *ctx,
                                   int (*cb) (const SSL *s, const SSL_CTX *ctx,
                                              int op, int bits, int nid,
                                              void *other, void *ex))
{
    ctx->cert->sec_cb = cb;
}

int (*SSL_CTX_get_security_callback(const SSL_CTX *ctx)) (const SSL *s,
                                                          const SSL_CTX *ctx,
                                                          int op, int bits,
                                                          int nid,
                                                          void *other,
                                                          void *ex) {
    return ctx->cert->sec_cb;
}
```

```c
int ssl_security(const SSL *s, int op, int bits, int nid, void *other)
{
    return s->cert->sec_cb(s, NULL, op, bits, nid, other, s->cert->sec_ex);
}

int ssl_ctx_security(const SSL_CTX *ctx, int op, int bits, int nid, void *other)
{
    return ctx->cert->sec_cb(NULL, ctx, op, bits, nid, other,
                             ctx->cert->sec_ex);
}
```

```c
int s_client_main(int argc, char **argv)
{
    ctx = SSL_CTX_new(meth);
    if (ctx == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }
    if (srp_arg.srplogin) {
        if (!srp_lateuser && !SSL_CTX_set_srp_username(ctx, srp_arg.srplogin)) {
            BIO_printf(bio_err, "Unable to set SRP username\n");
            goto end;
        }
        srp_arg.msg = c_msg;
        srp_arg.debug = c_debug;
        SSL_CTX_set_srp_cb_arg(ctx, &srp_arg);
        SSL_CTX_set_srp_client_pwd_callback(ctx, ssl_give_srp_client_pwd_cb);
        SSL_CTX_set_srp_strength(ctx, srp_arg.strength);
        if (c_msg || c_debug || srp_arg.amp == 0)
            SSL_CTX_set_srp_verify_param_callback(ctx,
                                                  ssl_srp_verify_param_cb);
    }
}
```

```c
# define tls1_ctx_ctrl ssl3_ctx_ctrl

int SSL_CTX_set_srp_username(SSL_CTX *ctx, char *name)
{
    return tls1_ctx_ctrl(ctx, SSL_CTRL_SET_TLS_EXT_SRP_USERNAME, 0, name);
}
```

```c
long ssl3_ctx_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
{
    DH *dh = (DH *)parg;
    EVP_PKEY *pkdh = NULL;
    if (dh == NULL) {
        SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    pkdh = ssl_dh_to_pkey(dh);
    if (pkdh == NULL) {
        SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!ssl_ctx_security(ctx, SSL_SECOP_TMP_DH,
                            EVP_PKEY_security_bits(pkdh), 0, pkdh)) {
        SSLerr(SSL_F_SSL3_CTX_CTRL, SSL_R_DH_KEY_TOO_SMALL);
        EVP_PKEY_free(pkdh);
        return 0;
    }
    EVP_PKEY_free(ctx->cert->dh_tmp);
    ctx->cert->dh_tmp = pkdh;
    return 1;
}
```

```c
SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth)
{
    if ((ret->cert = ssl_cert_new()) == NULL)
        goto err;
}
```

```c
CERT *ssl_cert_new(void)
{
    CERT *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        SSLerr(SSL_F_SSL_CERT_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->key = &(ret->pkeys[SSL_PKEY_RSA]);
    ret->references = 1;
    ret->sec_cb = ssl_security_default_callback;
    ret->sec_level = OPENSSL_TLS_SECURITY_LEVEL;
    ret->sec_ex = NULL;
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        SSLerr(SSL_F_SSL_CERT_NEW, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ret);
        return NULL;
    }

    return ret;
}
```

```c
static int ssl_security_default_callback(const SSL *s, const SSL_CTX *ctx,
                                         int op, int bits, int nid, void *other,
                                         void *ex)
{
    int level, minbits;
    static const int minbits_table[5] = { 80, 112, 128, 192, 256 };
    if (ctx)
        level = SSL_CTX_get_security_level(ctx);
    else
        level = SSL_get_security_level(s);

    if (level <= 0) {
        /*
         * No EDH keys weaker than 1024-bits even at level 0, otherwise,
         * anything goes.
         */
        if (op == SSL_SECOP_TMP_DH && bits < 80)
            return 0;
        return 1;
    }
    if (level > 5)
        level = 5;
    minbits = minbits_table[level - 1];
    switch (op) {
    case SSL_SECOP_CIPHER_SUPPORTED:
    case SSL_SECOP_CIPHER_SHARED:
    case SSL_SECOP_CIPHER_CHECK:
        {
            const SSL_CIPHER *c = other;
            /* No ciphers below security level */
            if (bits < minbits)
                return 0;
            /* No unauthenticated ciphersuites */
            if (c->algorithm_auth & SSL_aNULL)
                return 0;
            /* No MD5 mac ciphersuites */
            if (c->algorithm_mac & SSL_MD5)
                return 0;
            /* SHA1 HMAC is 160 bits of security */
            if (minbits > 160 && c->algorithm_mac & SSL_SHA1)
                return 0;
            /* Level 2: no RC4 */
            if (level >= 2 && c->algorithm_enc == SSL_RC4)
                return 0;
            /* Level 3: forward secure ciphersuites only */
            if (level >= 3 && c->min_tls != TLS1_3_VERSION &&
                               !(c->algorithm_mkey & (SSL_kEDH | SSL_kEECDH)))
                return 0;
            break;
        }
    case SSL_SECOP_VERSION:
        if (!SSL_IS_DTLS(s)) {
            /* SSLv3 not allowed at level 2 */
            if (nid <= SSL3_VERSION && level >= 2)
                return 0;
            /* TLS v1.1 and above only for level 3 */
            if (nid <= TLS1_VERSION && level >= 3)
                return 0;
            /* TLS v1.2 only for level 4 and above */
            if (nid <= TLS1_1_VERSION && level >= 4)
                return 0;
        } else {
            /* DTLS v1.2 only for level 4 and above */
            if (DTLS_VERSION_LT(nid, DTLS1_2_VERSION) && level >= 4)
                return 0;
        }
        break;

    case SSL_SECOP_COMPRESSION:
        if (level >= 2)
            return 0;
        break;
    case SSL_SECOP_TICKET:
        if (level >= 3)
            return 0;
        break;
    default:
        if (bits < minbits)
            return 0;
    }
    return 1;
}
```

# Example 10

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/wrk-4.2.0/obj/openssl-1.1.1i/crypto/dsa/dsa_ossl.c:270:18*

fnptr: *dsa->meth->bn_mod_exp*

targets: NULL

## Related Code Snippets

```c
static int dsa_sign_setup(DSA *dsa, BN_CTX *ctx_in,
                          BIGNUM **kinvp, BIGNUM **rp,
                          const unsigned char *dgst, int dlen)
{
    if ((dsa)->meth->bn_mod_exp != NULL) {
            if (!dsa->meth->bn_mod_exp(dsa, r, dsa->g, k, dsa->p, ctx,
                                       dsa->method_mont_p))
                goto err;
    } else {
            if (!BN_mod_exp_mont(r, dsa->g, k, dsa->p, ctx, dsa->method_mont_p))
                goto err;
    }
}
```

```c
int DSA_meth_set_bn_mod_exp(DSA_METHOD *dsam,
    int (*bn_mod_exp) (DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *,
                       const BIGNUM *, BN_CTX *, BN_MONT_CTX *))
{
    dsam->bn_mod_exp = bn_mod_exp;
    return 1;
}
```

```c
static int capi_init(ENGINE *e)
{
    /* Setup DSA Method */
    dsa_capi_idx = DSA_get_ex_new_index(0, NULL, NULL, NULL, 0);
    ossl_dsa_meth = DSA_OpenSSL();
    if (   !DSA_meth_set_sign(capi_dsa_method, capi_dsa_do_sign)
        || !DSA_meth_set_verify(capi_dsa_method,
                                DSA_meth_get_verify(ossl_dsa_meth))
        || !DSA_meth_set_finish(capi_dsa_method, capi_dsa_free)
        || !DSA_meth_set_mod_exp(capi_dsa_method,
                                    DSA_meth_get_mod_exp(ossl_dsa_meth))
        || !DSA_meth_set_bn_mod_exp(capi_dsa_method,
                                DSA_meth_get_bn_mod_exp(ossl_dsa_meth))) {
        goto memerr;
    }
}
```

```c
int (*DSA_meth_get_bn_mod_exp(const DSA_METHOD *dsam))
    (DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *,
     BN_MONT_CTX *)
{
    return dsam->bn_mod_exp;
}
```

```c
const DSA_METHOD *DSA_OpenSSL(void)
{
    return &openssl_dsa_meth;
}
```

```c
static DSA_METHOD openssl_dsa_meth = {
    "OpenSSL DSA method",
    dsa_do_sign,
    dsa_sign_setup_no_digest,
    dsa_do_verify,
    NULL,                       /* dsa_mod_exp, */
    NULL,                       /* dsa_bn_mod_exp, */
    dsa_init,
    dsa_finish,
    DSA_FLAG_FIPS_METHOD,
    NULL,
    NULL,
    NULL
};
```

```c
int (*DSA_meth_get_mod_exp(const DSA_METHOD *dsam))
        (DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *,
         const BIGNUM *, const BIGNUM *, BN_CTX *, BN_MONT_CTX *)
{
    return dsam->dsa_mod_exp;
}

int DSA_meth_set_mod_exp(DSA_METHOD *dsam,
    int (*mod_exp) (DSA *, BIGNUM *, const BIGNUM *, const BIGNUM *,
                    const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *,
                    BN_MONT_CTX *))
{
    dsam->dsa_mod_exp = mod_exp;
    return 1;
}
```

# Example 11

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/wrk-4.2.0/obj/openssl-1.1.1i/ssl/statem/statem_clnt.c:3773:14*

fnptr: *s->method->put_cipher_by_char*

targets: ssl3_put_cipher_by_char

## Related Code Snippets

```c
int ssl_cipher_list_to_bytes(SSL *s, STACK_OF(SSL_CIPHER) *sk, WPACKET *pkt)
{
    if (!s->method->put_cipher_by_char(c, pkt, &len)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_CIPHER_LIST_TO_BYTES,
                    ERR_R_INTERNAL_ERROR);
        return 0;
    }
}
```

```c
# define IMPLEMENT_tls_meth_func(version, flags, mask, func_name, s_accept, \
                                 s_connect, enc_data) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                version, \
                flags, \
                mask, \
                tls1_new, \
                tls1_clear, \
                tls1_free, \
                s_accept, \
                s_connect, \
                ssl3_read, \
                ssl3_peek, \
                ssl3_write, \
                ssl3_shutdown, \
                ssl3_renegotiate, \
                ssl3_renegotiate_check, \
                ssl3_read_bytes, \
                ssl3_write_bytes, \
                ssl3_dispatch_alert, \
                ssl3_ctrl, \
                ssl3_ctx_ctrl, \
                ssl3_get_cipher_by_char, \
                ssl3_put_cipher_by_char, \
                ssl3_pending, \
                ssl3_num_ciphers, \
                ssl3_get_cipher, \
                tls1_default_timeout, \
                &enc_data, \
                ssl_undefined_void_function, \
                ssl3_callback_ctrl, \
                ssl3_ctx_callback_ctrl, \
        }; \
        return &func_name##_data; \
        }
```

```c
struct ssl_method_st {
    int version;
    unsigned flags;
    unsigned long mask;
    int (*ssl_new) (SSL *s);
    int (*ssl_clear) (SSL *s);
    void (*ssl_free) (SSL *s);
    int (*ssl_accept) (SSL *s);
    int (*ssl_connect) (SSL *s);
    int (*ssl_read) (SSL *s, void *buf, size_t len, size_t *readbytes);
    int (*ssl_peek) (SSL *s, void *buf, size_t len, size_t *readbytes);
    int (*ssl_write) (SSL *s, const void *buf, size_t len, size_t *written);
    int (*ssl_shutdown) (SSL *s);
    int (*ssl_renegotiate) (SSL *s);
    int (*ssl_renegotiate_check) (SSL *s, int);
    int (*ssl_read_bytes) (SSL *s, int type, int *recvd_type,
                           unsigned char *buf, size_t len, int peek,
                           size_t *readbytes);
    int (*ssl_write_bytes) (SSL *s, int type, const void *buf_, size_t len,
                            size_t *written);
    int (*ssl_dispatch_alert) (SSL *s);
    long (*ssl_ctrl) (SSL *s, int cmd, long larg, void *parg);
    long (*ssl_ctx_ctrl) (SSL_CTX *ctx, int cmd, long larg, void *parg);
    const SSL_CIPHER *(*get_cipher_by_char) (const unsigned char *ptr);
    int (*put_cipher_by_char) (const SSL_CIPHER *cipher, WPACKET *pkt,
                               size_t *len);
    size_t (*ssl_pending) (const SSL *s);
    int (*num_ciphers) (void);
    const SSL_CIPHER *(*get_cipher) (unsigned ncipher);
    long (*get_timeout) (void);
    const struct ssl3_enc_method *ssl3_enc; /* Extra SSLv3/TLS stuff */
    int (*ssl_version) (void);
    long (*ssl_callback_ctrl) (SSL *s, int cb_id, void (*fp) (void));
    long (*ssl_ctx_callback_ctrl) (SSL_CTX *s, int cb_id, void (*fp) (void));
};
```

```c
int ssl3_put_cipher_by_char(const SSL_CIPHER *c, WPACKET *pkt, size_t *len)
{
    if ((c->id & 0xff000000) != SSL3_CK_CIPHERSUITE_FLAG) {
        *len = 0;
        return 1;
    }

    if (!WPACKET_put_bytes_u16(pkt, c->id & 0xffff))
        return 0;

    *len = 2;
    return 1;
}
```

# Example 12

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/wrk-4.2.0/obj/openssl-1.1.1i/ssl/statem/statem_srvr.c:2172:17*

fnptr: *s->ctx->ext.alpn_select_cb*

targets: alpn_cb

## Related Code Snippets

```c
int tls_handle_alpn(SSL *s)
{
    if (s->ctx->ext.alpn_select_cb != NULL && s->s3->alpn_proposed != NULL) {
        int r = s->ctx->ext.alpn_select_cb(s, &selected, &selected_len,
                                           s->s3->alpn_proposed,
                                           (unsigned int)s->s3->alpn_proposed_len,
                                           s->ctx->ext.alpn_select_cb_arg);
    }
    return 1;
}
```

```c
void SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx,
                                SSL_CTX_alpn_select_cb_func cb,
                                void *arg)
{
    ctx->ext.alpn_select_cb = cb;
    ctx->ext.alpn_select_cb_arg = arg;
}
```

```c
int s_server_main(int argc, char *argv[])
{
    if (alpn_ctx.data)
        SSL_CTX_set_alpn_select_cb(ctx, alpn_cb, &alpn_ctx);
}
```

```c
static int alpn_cb(SSL *s, const unsigned char **out, unsigned char *outlen,
                   const unsigned char *in, unsigned int inlen, void *arg)
{
    tlsextalpnctx *alpn_ctx = arg;

    if (!s_quiet) {
        /* We can assume that |in| is syntactically valid. */
        unsigned int i;
        BIO_printf(bio_s_out, "ALPN protocols advertised by the client: ");
        for (i = 0; i < inlen;) {
            if (i)
                BIO_write(bio_s_out, ", ", 2);
            BIO_write(bio_s_out, &in[i + 1], in[i]);
            i += in[i] + 1;
        }
        BIO_write(bio_s_out, "\n", 1);
    }

    if (SSL_select_next_proto
        ((unsigned char **)out, outlen, alpn_ctx->data, alpn_ctx->len, in,
         inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (!s_quiet) {
        BIO_printf(bio_s_out, "ALPN protocols selected: ");
        BIO_write(bio_s_out, *out, *outlen);
        BIO_write(bio_s_out, "\n", 1);
    }

    return SSL_TLSEXT_ERR_OK;
}
```

# Example 13

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/wrk-4.2.0/obj/openssl-1.1.1i/crypto/modes/gcm128.c:1092:21*

fnptr: *block*

targets: aesni_encrypt

## Related Code Snippets

```c
int CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx,
                          const unsigned char *in, unsigned char *out,
                          size_t len)
{
    block128_f block = ctx->block;
    (*block) (ctx->Yi.c, ctx->EKi.c, key);
}
```

```c
static int aes_gcm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len)
{
    EVP_AES_GCM_CTX *gctx = EVP_C_DATA(EVP_AES_GCM_CTX,ctx);
    int rv = -1;
    /* Encrypt/decrypt must be performed in place */
    if (out != in
        || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN))
        return -1;
    /*
     * Set IV from start of buffer or generate IV and write to start of
     * buffer.
     */
    if (EVP_CIPHER_CTX_ctrl(ctx, ctx->encrypt ? EVP_CTRL_GCM_IV_GEN
                                              : EVP_CTRL_GCM_SET_IV_INV,
                            EVP_GCM_TLS_EXPLICIT_IV_LEN, out) <= 0)
        goto err;
    /* Use saved AAD */
    if (CRYPTO_gcm128_aad(&gctx->gcm, ctx->buf, gctx->tls_aad_len))
        goto err;
    /* Fix buffer and length to point to payload */
    in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    if (ctx->encrypt) {
        /* Encrypt payload */
        if (gctx->ctr) {
            size_t bulk = 0;
#if defined(AES_GCM_ASM)
            if (len >= 32 && AES_GCM_ASM(gctx)) {
                if (CRYPTO_gcm128_encrypt(&gctx->gcm, NULL, NULL, 0))
                    return -1;

                bulk = AES_gcm_encrypt(in, out, len,
                                       gctx->gcm.key,
                                       gctx->gcm.Yi.c, gctx->gcm.Xi.u);
                gctx->gcm.len.u[1] += bulk;
            }
#endif
        }
    }
}
```

```c
void CRYPTO_gcm128_init(GCM128_CONTEXT *ctx, void *key, block128_f block)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };

    memset(ctx, 0, sizeof(*ctx));
    ctx->block = block;
    ctx->key = key;
}
```

```c
static int aesni_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                              const unsigned char *iv, int enc)
{
    EVP_AES_GCM_CTX *gctx = EVP_C_DATA(EVP_AES_GCM_CTX,ctx);
    if (!iv && !key)
        return 1;
    if (key) {
        aesni_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                              &gctx->ks.ks);
        CRYPTO_gcm128_init(&gctx->gcm, &gctx->ks, (block128_f) aesni_encrypt);
        gctx->ctr = (ctr128_f) aesni_ctr32_encrypt_blocks;
        /*
         * If we have an iv can set it directly, otherwise use saved IV.
         */
        if (iv == NULL && gctx->iv_set)
            iv = gctx->iv;
        if (iv) {
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
            gctx->iv_set = 1;
        }
        gctx->key_set = 1;
    }
}
```

```c
void aesni_encrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);
```

# Example 14

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/wrk-4.2.0/obj/openssl-1.1.1i/ssl/record/rec_layer_s3.c:390:13*

fnptr: *s->handshake_func*

targets: ossl_statem_accept, ossl_statem_connect

## Related Code Snippets

```c
int ssl3_write_bytes(SSL *s, int type, const void *buf_, size_t len,
                     size_t *written)
{
    if (SSL_in_init(s) && !ossl_statem_get_in_handshake(s)
            && s->early_data_state != SSL_EARLY_DATA_UNAUTH_WRITING) {
        i = s->handshake_func(s);
        /* SSLfatal() already called */
        if (i < 0)
            return i;
        if (i == 0) {
            return -1;
        }
    }
}
```

```c
WORK_STATE tls_finish_handshake(SSL *s, WORK_STATE wst, int clearbufs, int stop)
{
    void (*cb) (const SSL *ssl, int type, int val) = NULL;
    int cleanuphand = s->statem.cleanuphand;

    if (clearbufs) {
        if (!SSL_IS_DTLS(s)
#ifndef OPENSSL_NO_SCTP
            /*
             * RFC6083: SCTP provides a reliable and in-sequence transport service for DTLS
             * messages that require it. Therefore, DTLS procedures for retransmissions
             * MUST NOT be used.
             * Hence the init_buf can be cleared when DTLS over SCTP as transport is used.
             */
            || BIO_dgram_is_sctp(SSL_get_wbio(s))
#endif
            ) {
            /*
             * We don't do this in DTLS over UDP because we may still need the init_buf
             * in case there are any unexpected retransmits
             */
            BUF_MEM_free(s->init_buf);
            s->init_buf = NULL;
        }

        if (!ssl_free_wbio_buffer(s)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_FINISH_HANDSHAKE,
                     ERR_R_INTERNAL_ERROR);
            return WORK_ERROR;
        }
        s->init_num = 0;
    }

    if (SSL_IS_TLS13(s) && !s->server
            && s->post_handshake_auth == SSL_PHA_REQUESTED)
        s->post_handshake_auth = SSL_PHA_EXT_SENT;

    /*
     * Only set if there was a Finished message and this isn't after a TLSv1.3
     * post handshake exchange
     */
    if (cleanuphand) {
        /* skipped if we just sent a HelloRequest */
        s->renegotiate = 0;
        s->new_session = 0;
        s->statem.cleanuphand = 0;
        s->ext.ticket_expected = 0;

        ssl3_cleanup_key_block(s);

        if (s->server) {
            /*
             * In TLSv1.3 we update the cache as part of constructing the
             * NewSessionTicket
             */
            if (!SSL_IS_TLS13(s))
                ssl_update_cache(s, SSL_SESS_CACHE_SERVER);

            /* N.B. s->ctx may not equal s->session_ctx */
            tsan_counter(&s->ctx->stats.sess_accept_good);
            s->handshake_func = ossl_statem_accept;
        } else {
            if (SSL_IS_TLS13(s)) {
                /*
                 * We encourage applications to only use TLSv1.3 tickets once,
                 * so we remove this one from the cache.
                 */
                if ((s->session_ctx->session_cache_mode
                     & SSL_SESS_CACHE_CLIENT) != 0)
                    SSL_CTX_remove_session(s->session_ctx, s->session);
            } else {
                /*
                 * In TLSv1.3 we update the cache as part of processing the
                 * NewSessionTicket
                 */
                ssl_update_cache(s, SSL_SESS_CACHE_CLIENT);
            }
            if (s->hit)
                tsan_counter(&s->session_ctx->stats.sess_hit);

            s->handshake_func = ossl_statem_connect;
            tsan_counter(&s->session_ctx->stats.sess_connect_good);
        }

        if (SSL_IS_DTLS(s)) {
            /* done with handshaking */
            s->d1->handshake_read_seq = 0;
            s->d1->handshake_write_seq = 0;
            s->d1->next_handshake_write_seq = 0;
            dtls1_clear_received_buffer(s);
        }
    }

    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (s->ctx->info_callback != NULL)
        cb = s->ctx->info_callback;

    /* The callback may expect us to not be in init at handshake done */
    ossl_statem_set_in_init(s, 0);

    if (cb != NULL) {
        if (cleanuphand
                || !SSL_IS_TLS13(s)
                || SSL_IS_FIRST_HANDSHAKE(s))
            cb(s, SSL_CB_HANDSHAKE_DONE, 1);
    }

    if (!stop) {
        /* If we've got more work to do we go back into init */
        ossl_statem_set_in_init(s, 1);
        return WORK_FINISHED_CONTINUE;
    }

    return WORK_FINISHED_STOP;
}
```