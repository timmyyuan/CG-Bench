# Example 1

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/src/redis-cli.c:8417:12*

fnptr: *c->funcs->read*

targets: redisNetRead

## Related Code Snippets

```c
/* Read raw bytes through a redisContext. The read operation is not greedy
 * and may not fill the buffer entirely.
 */
static ssize_t readConn(redisContext *c, char *buf, size_t len)
{
    return c->funcs->read(c, buf, len);
}
```

```c
static redisContext *context;
```

```c
static int cliConnect(int flags) {
    if (context == NULL || flags & CC_FORCE) {
        if (context != NULL) {
            redisFree(context);
            config.dbnum = 0;
            config.in_multi = 0;
            config.pubsub_mode = 0;
            cliRefreshPrompt();
        }

        /* Do not use hostsocket when we got redirected in cluster mode */
        if (config.hostsocket == NULL ||
            (config.cluster_mode && config.cluster_reissue_command)) {
            context = redisConnect(config.conn_info.hostip,config.conn_info.hostport);
        } else {
            context = redisConnectUnix(config.hostsocket);
        }
    }
}
```

```c
/* Connect to a Redis instance. On error the field error in the returned
 * context will be set to the return value of the error function.
 * When no set of reply functions is given, the default set will be used. */
redisContext *redisConnect(const char *ip, int port) {
    redisOptions options = {0};
    REDIS_OPTIONS_SET_TCP(&options, ip, port);
    return redisConnectWithOptions(&options);
}
```

```c
redisContext *redisConnectWithOptions(const redisOptions *options) {
    redisContext *c = redisContextInit();
    if (c == NULL) {
        return NULL;
    }
}
```

```c
static redisContext *redisContextInit(void) {
    redisContext *c;

    c = hi_calloc(1, sizeof(*c));
    if (c == NULL)
        return NULL;

    c->funcs = &redisContextDefaultFuncs;

    c->obuf = hi_sdsempty();
    c->reader = redisReaderCreate();
    c->fd = REDIS_INVALID_FD;

    if (c->obuf == NULL || c->reader == NULL) {
        redisFree(c);
        return NULL;
    }

    return c;
}
```

```c
static redisContextFuncs redisContextDefaultFuncs = {
    .close = redisNetClose,
    .free_privctx = NULL,
    .async_read = redisAsyncRead,
    .async_write = redisAsyncWrite,
    .read = redisNetRead,
    .write = redisNetWrite
};
```

# Example 2

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/wrk-4.2.0/obj/LuaJIT-2.1/src/./lj_gc.h:122:3*

fnptr: *g->allocf*

targets: l_alloc, lj_alloc_f

## Related Code Snippets

```c
#define setmref(r, p)	((r).ptr64 = (uint64_t)(void *)(p))
#define mref(r, t)	((t *)(void *)(r).ptr64)
#define G(L)			(mref(L->glref, global_State))
```

```c
static LJ_AINLINE void lj_mem_free(global_State *g, void *p, size_t osize) {
  g->gc.total -= (GCSize)osize;
  g->allocf(g->allocd, p, osize, 0);
}
```

```c
#if LJ_64 && !LJ_GC64 && !(defined(LUAJIT_USE_VALGRIND) && defined(LUAJIT_USE_SYSMALLOC))
lua_State *lj_state_newstate(lua_Alloc allocf, void *allocd)
#else
LUA_API lua_State *lua_newstate(lua_Alloc allocf, void *allocd)
#endif
{
  lua_State *L;
  global_State *g;
  ...
#ifndef LUAJIT_USE_SYSMALLOC
  if (allocf == LJ_ALLOCF_INTERNAL) {
    allocd = lj_alloc_create(&prng);
    if (!allocd) return NULL;
    allocf = lj_alloc_f;
  }
#endif
  GG = (GG_State *)allocf(allocd, NULL, 0, sizeof(GG_State));
  L = &GG->L;
  g = &GG->g;
  setmref(L->glref, g);
  g->allocf = allocf;
  g->allocd = allocd;

#ifndef LUAJIT_USE_SYSMALLOC
  if (allocf == lj_alloc_f) {
    lj_alloc_setprng(allocd, &g->prng);
  }
#endif
  if (lj_vm_cpcall(L, NULL, NULL, cpluaopen) != 0) {
    close_state(L);
    return NULL;
  }
  return L;
}
```

```c
static lua_State *luaL_newstate(void)
{
    lua_State *L = lua_newstate(l_alloc, NULL);
    if (L)
        lua_atpanic(L, &panic);
    return L;
}
```

```c
static void close_state(lua_State *L)
{
  global_State *g = G(L);
  lj_buf_free(g, &g->tmpbuf);
#ifndef LUAJIT_USE_SYSMALLOC
  if (g->allocf == lj_alloc_f)
    lj_alloc_destroy(g->allocd);
  else
#endif
  g->allocf(g->allocd, G2GG(g), sizeof(GG_State), 0);
}
```

```c
static LJ_AINLINE void lj_buf_free(global_State *g, SBuf *sb)
{
  lj_mem_free(g, sbufB(sb), sbufsz(sb));
}
```

```c
void lj_alloc_destroy(void *msp)
{
  mstate ms = (mstate)msp;
  msegmentptr sp = &ms->seg;
  while (sp != 0) {
    char *base = sp->base;
    size_t size = sp->size;
    sp = sp->next;
    CALL_MUNMAP(base, size);
  }
}
```

```c
LJ_ASMF int lj_vm_cpcall(lua_State *L, lua_CFunction func, void *ud,
			 lua_CPFunction cp);
```

```c
void *lj_alloc_create(PRNGState *rs)
{
  size_t tsize = DEFAULT_GRANULARITY;
  char *tbase;
  INIT_MMAP();
  UNUSED(rs);
  tbase = (char *)(CALL_MMAP(rs, tsize));
  if (tbase != CMFAIL) {
    size_t msize = pad_request(sizeof(struct malloc_state));
    mchunkptr mn;
    mchunkptr msp = align_as_chunk(tbase);
    mstate m = (mstate)(chunk2mem(msp));
    memset(m, 0, msize);
    msp->head = (msize|PINUSE_BIT|CINUSE_BIT);
    m->seg.base = tbase;
    m->seg.size = tsize;
    m->release_checks = MAX_RELEASE_CHECK_RATE;
    init_bins(m);
    mn = next_chunk(mem2chunk(m));
    init_top(m, mn, (size_t)((tbase + tsize) - (char *)mn) - TOP_FOOT_SIZE);
    return m;
  }
  return NULL;
}
```

# Example 3

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/wrk-4.2.0/src/wrk.c:431:17*

fnptr: *sock.read*

targets: ssl_read, sock_read

## Related Code Snippets

```c
static void socket_readable(aeEventLoop *loop, int fd, void *data, int mask) {
connection *c = data;
    size_t n;

    do {
        switch (sock.read(c, &n)) {
            case OK:    break;
            case ERROR: goto error;
            case RETRY: return;
        }

        if (http_parser_execute(&c->parser, &parser_settings, c->buf, n) != n) goto error;
        if (n == 0 && !http_body_is_final(&c->parser)) goto error;
    }
}
```

```c
int main(int argc, char **argv) {
    char *url, **headers = zmalloc(argc * sizeof(char *));
    struct http_parser_url parts = {};

    ...

    if (!strncmp("https", schema, 5)) {
        if ((cfg.ctx = ssl_init()) == NULL) {
            fprintf(stderr, "unable to initialize SSL\n");
            ERR_print_errors_fp(stderr);
            exit(1);
        }
        sock.connect  = ssl_connect;
        sock.close    = ssl_close;
        sock.read     = ssl_read;
        sock.write    = ssl_write;
        sock.readable = ssl_readable;
    }
}
...
```

```c
static struct sock sock = {
.connect  = sock_connect,
    .close    = sock_close,
    .read     = sock_read,
    .write    = sock_write,
    .readable = sock_readable
};
```

# Example 4

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/openssh-build/../openssh-9.6p1/channels.c:2139:7*

fnptr: *c->input_filter*

targets: client_simple_escape_filter, sys_tun_infilter

## Related Code Snippets

```c
static int channel_handle_rfd(struct ssh *ssh, Channel *c)
{
	...
	if (c->input_filter != NULL) {
		if (c->input_filter(ssh, c, buf, len) == -1) {
			debug2("channel %d: filter stops", c->self);
			chan_read_failed(ssh, c);
		}
        ...
    }
    ...
}
```

```c
void channel_register_filter(struct ssh *ssh, int id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, void *ctx)
{
	...
	c->input_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}
```

```c
static int mux_master_process_new_session(struct ssh *ssh, u_int rid,
    Channel *c, struct sshbuf *m, struct sshbuf *reply)
{
	...
	if (cctx->want_tty && escape_char != 0xffffffff) {
		channel_register_filter(ssh, nc->self,
		    client_simple_escape_filter, NULL,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((int)escape_char));
	}
    ...
}
```

```c
char *
client_request_tun_fwd(struct ssh *ssh, int tun_mode,
    int local_tun, int remote_tun, channel_open_fn *cb, void *cbctx)
{
    ...

#if defined(SSH_TUN_FILTER)
	if (options.tun_open == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, NULL, NULL);
#endif
    ...
}
```

# Example 5

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/ffmpeg-6.1.1/libavcodec/h263dec.c:248:19*

fnptr: *s->decode_mb*

targets: ff_h263_decode_mb

## Related Code Snippets

```c
av_cold int ff_h263_decode_init(AVCodecContext *avctx)
{
    MpegEncContext *s = avctx->priv_data;
    int ret;

    s->out_format      = FMT_H263;

    // set defaults
    ff_mpv_decode_init(s, avctx);

    s->quant_precision = 5;
    s->decode_mb       = ff_h263_decode_mb;
    s->low_delay       = 1;
    ...
}
```

```c
static int decode_slice(MpegEncContext *s)
{
    const int part_mask = s->partitioned_frame
                          ? (ER_AC_END | ER_AC_ERROR) : 0x7F;
    const int mb_size   = 16 >> s->avctx->lowres;
    int ret;

...

        ff_init_block_index(s);
        for (; s->mb_x < s->mb_width; s->mb_x++) {
            int ret;

            ...
            ret = s->decode_mb(s, s->block);
        }
}
```

```c
int ff_h263_decode_frame(AVCodecContext *avctx, AVFrame *pict,
                         int *got_frame, AVPacket *avpkt)
{
    const uint8_t *buf = avpkt->data;
    int buf_size       = avpkt->size;
    MpegEncContext *s  = avctx->priv_data;
    int ret;
    int slice_ret = 0;

    ...

    /* decode each macroblock */
    s->mb_x = 0;
    s->mb_y = 0;

    slice_ret = decode_slice(s);
    ...
}
```

```c
const FFCodec ff_h263_decoder = {
    .p.name         = "h263",
    CODEC_LONG_NAME("H.263 / H.263-1996, H.263+ / H.263-1998 / H.263 version 2"),
    .p.type         = AVMEDIA_TYPE_VIDEO,
    .p.id           = AV_CODEC_ID_H263,
    .priv_data_size = sizeof(MpegEncContext),
    .init           = ff_h263_decode_init,
    .close          = ff_h263_decode_end,
    FF_CODEC_DECODE_CB(ff_h263_decode_frame),
    .p.capabilities = AV_CODEC_CAP_DRAW_HORIZ_BAND | AV_CODEC_CAP_DR1 |
                      AV_CODEC_CAP_DELAY,
    .caps_internal  = FF_CODEC_CAP_SKIP_FRAME_FILL_PARAM,
    .flush          = ff_mpeg_flush,
    .p.max_lowres   = 3,
    .p.pix_fmts     = ff_h263_hwaccel_pixfmt_list_420,
    .hw_configs     = h263_hw_config_list,
};
```


# Example 6

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/src/module.c:11785:16*

fnptr: *mt->mem_usage2*

targets: NULL

## Related Code Snippets

```c
size_t moduleGetMemUsage(robj *key, robj *val, size_t sample_size, int dbid) {
    moduleValue *mv = val->ptr;
    moduleType *mt = mv->type;
    size_t size = 0;
    /* We prefer to use the enhanced version. */
    if (mt->mem_usage2 != NULL) {
        RedisModuleKeyOptCtx ctx = {key, NULL, dbid, -1};
        size = mt->mem_usage2(&ctx, mv->value, sample_size);
    } else if (mt->mem_usage != NULL) {
        size = mt->mem_usage(mv->value);
    } 

    return size;
}
```

```c
size_t objectComputeSize(robj *key, robj *o, size_t sample_size, int dbid) {
    sds ele, ele2;
    dict *d;
    dictIterator *di;
    struct dictEntry *de;
    size_t asize = 0, elesize = 0, samples = 0;

    if (o->type == OBJ_STRING) {
        ...
    } else if (o->type == OBJ_HASH) {
        ...
    } else if (o->type == OBJ_STREAM) {
        ...
    } else if (o->type == OBJ_MODULE) {
        asize = moduleGetMemUsage(key, o, sample_size, dbid);
    } else {
        serverPanic("Unknown object type");
    }
    return asize;
}
```

```c
void memoryCommand(client *c) {
    if (!strcasecmp(c->argv[1]->ptr,"help") && c->argc == 2) {
        ...
    } else if (!strcasecmp(c->argv[1]->ptr,"usage") && c->argc >= 3) {
        dictEntry *de;
        ...
        size_t usage = objectComputeSize(c->argv[2],dictGetVal(de),samples,c->db->id);
        usage += sdsZmallocSize(dictGetKey(de));
        usage += dictEntryMemUsage();
        usage += dictMetadataSize(c->db->dict);
        addReplyLongLong(c,usage);
    } else if (!strcasecmp(c->argv[1]->ptr,"stats") && c->argc == 2) {
        ...
    }
}
```

# Example 7

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/src/./connection.h:243:12*

fnptr: *conn->type->set_write_handler*

targets: connSocketSetWriteHandler, connTLSSetWriteHandler, connUnixSetWriteHandler

## Related Code Snippets

```c
static inline int connSetWriteHandlerWithBarrier(connection *conn, ConnectionCallbackFunc func, int barrier) {
    return conn->type->set_write_handler(conn, func, barrier);
}
```

```c
static ConnectionType CT_Socket = {
    ...
    .write = connSocketWrite,
    .writev = connSocketWritev,
    .read = connSocketRead,
    .set_write_handler = connSocketSetWriteHandler,
    .set_read_handler = connSocketSetReadHandler,
    .get_last_error = connSocketGetLastError,
    .sync_write = connSocketSyncWrite,
    .sync_read = connSocketSyncRead,
    .sync_readline = connSocketSyncReadLine,
    ...
};
```

```c
static ConnectionType CT_TLS = {
    ...
    .read = connTLSRead,
    .write = connTLSWrite,
    .writev = connTLSWritev,
    .set_write_handler = connTLSSetWriteHandler,
    .set_read_handler = connTLSSetReadHandler,
    .get_last_error = connTLSGetLastError,
    .sync_write = connTLSSyncWrite,
    .sync_read = connTLSSyncRead,
    .sync_readline = connTLSSyncReadLine,
    ...
};
```

```c
static ConnectionType CT_Unix = {
    ...
    .write = connUnixWrite,
    .writev = connUnixWritev,
    .read = connUnixRead,
    .set_write_handler = connUnixSetWriteHandler,
    .set_read_handler = connUnixSetReadHandler,
    .get_last_error = connUnixGetLastError,
    .sync_write = connUnixSyncWrite,
    .sync_read = connUnixSyncRead,
    .sync_readline = connUnixSyncReadLine,
    ...
};
```

# Example 8

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/curl-build/lib/../../curl-8.5.0/lib/cfilters.c:466:5*

fnptr: *cf->cft->get_host*

targets: cf_socket_get_host

## Related Code Snippets

```c
void Curl_conn_get_host(struct Curl_easy *data, int sockindex,
                        const char **phost, const char **pdisplay_host,
                        int *pport)
{
  struct Curl_cfilter *cf;

  DEBUGASSERT(data->conn);
  cf = data->conn->cfilter[sockindex];
  if(cf) {
    cf->cft->get_host(cf, data, phost, pdisplay_host, pport);
  }
  ...
}
```

```c
struct Curl_cftype Curl_cft_tcp = {
  "TCP",
  CF_TYPE_IP_CONNECT,
  CURL_LOG_LVL_NONE,
  cf_socket_destroy,
  cf_tcp_connect,
  cf_socket_close,
  cf_socket_get_host,
  cf_socket_adjust_pollset,
  cf_socket_data_pending,
  cf_socket_send,
  cf_socket_recv,
  cf_socket_cntrl,
  cf_socket_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_socket_query,
};
```

```c
struct Curl_cftype {
  const char *name;                       /* name of the filter type */
  int flags;                              /* flags of filter type */
  int log_level;                          /* log level for such filters */
  Curl_cft_destroy_this *destroy;         /* destroy resources of this cf */
  Curl_cft_connect *do_connect;           /* establish connection */
  Curl_cft_close *do_close;               /* close conn */
  Curl_cft_get_host *get_host;            /* host filter talks to */
  Curl_cft_adjust_pollset *adjust_pollset; /* adjust transfer poll set */
  Curl_cft_data_pending *has_data_pending;/* conn has data pending */
  Curl_cft_send *do_send;                 /* send data */
  Curl_cft_recv *do_recv;                 /* receive data */
  Curl_cft_cntrl *cntrl;                  /* events/control */
  Curl_cft_conn_is_alive *is_alive;       /* FALSE if conn is dead, Jim! */
  Curl_cft_conn_keep_alive *keep_alive;   /* try to keep it alive */
  Curl_cft_query *query;                  /* query filter chain */
};
```

```c
void Curl_conn_cf_add(struct Curl_easy *data,
                      struct connectdata *conn,
                      int index,
                      struct Curl_cfilter *cf)
{
  (void)data;
  DEBUGASSERT(conn);
  DEBUGASSERT(!cf->conn);
  DEBUGASSERT(!cf->next);

  cf->next = conn->cfilter[index];
  cf->conn = conn;
  cf->sockindex = index;
  conn->cfilter[index] = cf;
  CURL_TRC_CF(data, cf, "added");
}
```

```c
CURLcode Curl_conn_tcp_listen_set(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  int sockindex, curl_socket_t *s)
{
  CURLcode result;
  struct Curl_cfilter *cf = NULL;
  struct cf_socket_ctx *ctx = NULL;

  /* replace any existing */
  Curl_conn_cf_discard_all(data, conn, sockindex);
  DEBUGASSERT(conn->sock[sockindex] == CURL_SOCKET_BAD);

  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  ctx->transport = conn->transport;
  ctx->sock = *s;
  ctx->accepted = FALSE;
  result = Curl_cf_create(&cf, &Curl_cft_tcp_accept, ctx);
  if(result)
    goto out;
  Curl_conn_cf_add(data, conn, sockindex, cf);
  ...
}
```

# Example 9

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/curl-build/lib/../../curl-8.5.0/lib/llist.c:130:5*

fnptr: *list->dtor*

targets: fileinfo_dtor, hash_element_dtor, free_bundle_hash_entry, freednsentry, trhash_dtor, sh_freeentry, curl_free, gsasl_free

## Related Code Snippets

```c
void
Curl_llist_remove(struct Curl_llist *list, struct Curl_llist_element *e,
                  void *user)
{
  void *ptr;
  if(!e || list->size == 0)
    return;

  ...
  --list->size;

  /* call the dtor() last for when it actually frees the 'e' memory itself */
  if(list->dtor)
    list->dtor(user, ptr);
}
```

```c
void Curl_bufref_set(struct bufref *br, const void *ptr, size_t len,
                     void (*dtor)(void *))
{
  DEBUGASSERT(ptr || !len);
  DEBUGASSERT(len <= CURL_MAX_INPUT_LENGTH);

  Curl_bufref_free(br);
  br->ptr = (const unsigned char *) ptr;
  br->len = len;
  br->dtor = dtor;
}
```

```c
static CURLcode init_wc_data(struct Curl_easy *data)
{
    ...
    wildcard->ftpwc = ftpwc; /* put it to the WildcardData tmp pointer */
    wildcard->dtor = wc_data_dtor;

    ...

fail:
    if(ftpwc) {
        Curl_ftp_parselist_data_free(&ftpwc->parser);
        free(ftpwc);
    }
    Curl_safefree(wildcard->pattern);
    wildcard->dtor = ZERO_NULL;
    wildcard->ftpwc = NULL;
    return result;
}
```

```c
#define ZERO_NULL 0
```

```c
void
Curl_hash_init(struct Curl_hash *h,
               int slots,
               hash_function hfunc,
               comp_function comparator,
               Curl_hash_dtor dtor)
{
  DEBUGASSERT(h);
  DEBUGASSERT(slots);
  DEBUGASSERT(hfunc);
  DEBUGASSERT(comparator);
  DEBUGASSERT(dtor);

  h->table = NULL;
  h->hash_func = hfunc;
  h->comp_func = comparator;
  h->dtor = dtor;
  h->size = 0;
  h->slots = slots;
}
```

```c
void
Curl_llist_init(struct Curl_llist *l, Curl_llist_dtor dtor)
{
  l->size = 0;
  l->dtor = dtor;
  l->head = NULL;
  l->tail = NULL;
}
```

```c
CURLcode Curl_wildcard_init(struct WildcardData *wc)
{
  Curl_llist_init(&wc->filelist, fileinfo_dtor);
  wc->state = CURLWC_INIT;

  return CURLE_OK;
}
```

```c
void *
Curl_hash_add(struct Curl_hash *h, void *key, size_t key_len, void *p)
{
  struct Curl_hash_element  *he;
  struct Curl_llist_element *le;
  struct Curl_llist *l;

  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  if(!h->table) {
    int i;
    h->table = malloc(h->slots * sizeof(struct Curl_llist));
    if(!h->table)
      return NULL; /* OOM */
    for(i = 0; i < h->slots; ++i)
      Curl_llist_init(&h->table[i], hash_element_dtor);
  }
  ...
}
```

```c
int Curl_conncache_init(struct conncache *connc, int size)
{
  /* allocate a new easy handle to use when closing cached connections */
  connc->closure_handle = curl_easy_init();
  if(!connc->closure_handle)
    return 1; /* bad */
  connc->closure_handle->state.internal = true;

  Curl_hash_init(&connc->hash, size, Curl_hash_str,
                 Curl_str_key_compare, free_bundle_hash_entry);
  connc->closure_handle->state.conn_cache = connc;

  return 0; /* good */
}
```

```c
void Curl_init_dnscache(struct Curl_hash *hash, int size)
{
  Curl_hash_init(hash, size, Curl_hash_str, Curl_str_key_compare,
                 freednsentry);
}
```

```c
static struct Curl_sh_entry *sh_addentry(struct Curl_hash *sh,
                                         curl_socket_t s)
{
  struct Curl_sh_entry *there = sh_getentry(sh, s);
  struct Curl_sh_entry *check;

  if(there) {
    /* it is present, return fine */
    return there;
  }

  /* not present, add it */
  check = calloc(1, sizeof(struct Curl_sh_entry));
  if(!check)
    return NULL; /* major failure */

  Curl_hash_init(&check->transfers, TRHASH_SIZE, trhash, trhash_compare,
                 trhash_dtor);

  /* make/add new hash entry */
  if(!Curl_hash_add(sh, (char *)&s, sizeof(curl_socket_t), check)) {
    Curl_hash_destroy(&check->transfers);
    free(check);
    return NULL; /* major failure */
  }

  return check; /* things are good in sockhash land */
}

static void sh_init(struct Curl_hash *hash, int hashsize)
{
  Curl_hash_init(hash, hashsize, hash_fd, fd_key_compare,
                 sh_freeentry);
}

```

```c
static CURLcode get_server_message(struct SASL *sasl, struct Curl_easy *data,
                                   struct bufref *out)
{
  CURLcode result = CURLE_OK;

  result = sasl->params->getmessage(data, out);
  if(!result && (sasl->params->flags & SASL_FLAG_BASE64)) {
    unsigned char *msg;
    size_t msglen;
    const char *serverdata = (const char *) Curl_bufref_ptr(out);

    if(!*serverdata || *serverdata == '=')
      Curl_bufref_set(out, NULL, 0, NULL);
    else {
      result = Curl_base64_decode(serverdata, &msg, &msglen);
      if(!result)
        Curl_bufref_set(out, msg, msglen, curl_free);
    }
  }
  return result;
}
```

```c
CURLcode Curl_auth_gsasl_token(struct Curl_easy *data,
                               const struct bufref *chlg,
                               struct gsasldata *gsasl,
                               struct bufref *out)
{
  int res;
  char *response;
  size_t outlen;

  res = gsasl_step(gsasl->client,
                   (const char *) Curl_bufref_ptr(chlg), Curl_bufref_len(chlg),
                   &response, &outlen);
  if(res != GSASL_OK && res != GSASL_NEEDS_MORE) {
    failf(data, "GSASL step: %s\n", gsasl_strerror(res));
    return CURLE_BAD_CONTENT_ENCODING;
  }

  Curl_bufref_set(out, response, outlen, gsasl_free);
  return CURLE_OK;
}
```

# Example 10

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/wrk-4.2.0/obj/openssl-1.1.1i/crypto/x509/x509_vfy.c:1489:13*

fnptr: *ctx->lookup_crls*

targets: crls_http_cb, X509_STORE_CTX_get1_crls

## Related Code Snippets

```c
static int get_crl_delta(X509_STORE_CTX *ctx,
                         X509_CRL **pcrl, X509_CRL **pdcrl, X509 *x)
{
  skcrl = ctx->lookup_crls(ctx, nm);
}
```

```c
void X509_STORE_set_lookup_crls(X509_STORE *ctx,
                                X509_STORE_CTX_lookup_crls_fn lookup_crls)
{
    ctx->lookup_crls = lookup_crls;
}
```

```c
void store_setup_crl_download(X509_STORE *st)
{
    X509_STORE_set_lookup_crls_cb(st, crls_http_cb);
}
```

```c
#define X509_STORE_set_lookup_crls_cb(ctx, func) \
    X509_STORE_set_lookup_crls((ctx), (func))
```

```c
int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509,
                        STACK_OF(X509) *chain)
{
  if (store && store->lookup_crls)
      ctx->lookup_crls = store->lookup_crls;
  else
      ctx->lookup_crls = X509_STORE_CTX_get1_crls;
  return 0;
}
```

```c
STACK_OF(X509_CRL) *X509_STORE_CTX_get1_crls(X509_STORE_CTX *ctx, X509_NAME *nm)
{
    int i, idx, cnt;
    STACK_OF(X509_CRL) *sk = sk_X509_CRL_new_null();
    X509_CRL *x;
    X509_OBJECT *obj, *xobj = X509_OBJECT_new();
    X509_STORE *store = ctx->ctx;

    /* Always do lookup to possibly add new CRLs to cache */
    if (sk == NULL
            || xobj == NULL
            || store == NULL
            || !X509_STORE_CTX_get_by_subject(ctx, X509_LU_CRL, nm, xobj)) {
        X509_OBJECT_free(xobj);
        sk_X509_CRL_free(sk);
        return NULL;
    }
    X509_OBJECT_free(xobj);
    X509_STORE_lock(store);
    idx = x509_object_idx_cnt(store->objs, X509_LU_CRL, nm, &cnt);
    if (idx < 0) {
        X509_STORE_unlock(store);
        sk_X509_CRL_free(sk);
        return NULL;
    }

    for (i = 0; i < cnt; i++, idx++) {
        obj = sk_X509_OBJECT_value(store->objs, idx);
        x = obj->data.crl;
        if (!X509_CRL_up_ref(x)) {
            X509_STORE_unlock(store);
            sk_X509_CRL_pop_free(sk, X509_CRL_free);
            return NULL;
        }
        if (!sk_X509_CRL_push(sk, x)) {
            X509_STORE_unlock(store);
            X509_CRL_free(x);
            sk_X509_CRL_pop_free(sk, X509_CRL_free);
            return NULL;
        }
    }
    X509_STORE_unlock(store);
    return sk;
}
```

```c
static STACK_OF(X509_CRL) *crls_http_cb(X509_STORE_CTX *ctx, X509_NAME *nm)
{
    X509 *x;
    STACK_OF(X509_CRL) *crls = NULL;
    X509_CRL *crl;
    STACK_OF(DIST_POINT) *crldp;

    crls = sk_X509_CRL_new_null();
    if (!crls)
        return NULL;
    x = X509_STORE_CTX_get_current_cert(ctx);
    crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
    crl = load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (!crl) {
        sk_X509_CRL_free(crls);
        return NULL;
    }
    sk_X509_CRL_push(crls, crl);
    /* Try to download delta CRL */
    crldp = X509_get_ext_d2i(x, NID_freshest_crl, NULL, NULL);
    crl = load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (crl)
        sk_X509_CRL_push(crls, crl);
    return crls;
}
```

# Example 11

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/ffmpeg-6.1.1/libavcodec/dcadsp.c:139:9*

fnptr: *synth->synth_filter_float*

targets: synth_filter_sse2, synth_filter_avx, synth_filter_fma3

## Related Code Snippets

```c
static void sub_qmf32_float_c(SynthFilterContext *synth,
                              AVTXContext *imdct,
                              av_tx_fn imdct_fn,
                              float *pcm_samples,
                              int32_t **subband_samples_lo,
                              int32_t **subband_samples_hi,
                              float *hist1, int *offset, float *hist2,
                              const float *filter_coeff, ptrdiff_t npcmblocks,
                              float scale)
{
    LOCAL_ALIGNED_32(float, input, [32]);
    int i, j;

    for (j = 0; j < npcmblocks; j++) {
        // Load in one sample from each subband
        for (i = 0; i < 32; i++) {
            if ((i - 1) & 2)
                input[i] = -subband_samples_lo[i][j];
            else
                input[i] =  subband_samples_lo[i][j];
        }

        // One subband sample generates 32 interpolated ones
        synth->synth_filter_float(imdct, hist1, offset,
                                  hist2, filter_coeff,
                                  pcm_samples, input, scale, imdct_fn);
        pcm_samples += 32;
    }
}
```

```c
av_cold void ff_synth_filter_init_x86(SynthFilterContext *s)
{
#if HAVE_X86ASM
    int cpu_flags = av_get_cpu_flags();

    if (EXTERNAL_SSE2(cpu_flags)) {
        s->synth_filter_float = synth_filter_sse2;
    }
    if (EXTERNAL_AVX_FAST(cpu_flags)) {
        s->synth_filter_float = synth_filter_avx;
    }
    if (EXTERNAL_FMA3_FAST(cpu_flags)) {
        s->synth_filter_float = synth_filter_fma3;
    }
#endif /* HAVE_X86ASM */
}
```

```c
av_cold void ff_synth_filter_init(SynthFilterContext *c)
{
    c->synth_filter_float    = synth_filter_float;
    c->synth_filter_float_64 = synth_filter_float_64;
    c->synth_filter_fixed    = synth_filter_fixed;
    c->synth_filter_fixed_64 = synth_filter_fixed_64;

#if ARCH_AARCH64
    ff_synth_filter_init_aarch64(c);
#elif ARCH_ARM
    ff_synth_filter_init_arm(c);
#elif ARCH_X86
    ff_synth_filter_init_x86(c);
#endif
}
```

```c
av_cold int ff_dca_core_init(DCACoreDecoder *s)
{
    int ret;
    float scale = 1.0f;

    if (!(s->float_dsp = avpriv_float_dsp_alloc(0)))
        return -1;
    if (!(s->fixed_dsp = avpriv_alloc_fixed_dsp(0)))
        return -1;

    ff_dcadct_init(&s->dcadct);

    if ((ret = av_tx_init(&s->imdct[0], &s->imdct_fn[0], AV_TX_FLOAT_MDCT,
                          1, 32, &scale, 0)) < 0)
        return ret;

    if ((ret = av_tx_init(&s->imdct[1], &s->imdct_fn[1], AV_TX_FLOAT_MDCT,
                          1, 64, &scale, 0)) < 0)
        return ret;

    ff_synth_filter_init(&s->synth);

    s->x96_rand = 1;
    return 0;
}
```

```c
av_cold void ff_dcadsp_init(DCADSPContext *s)
{
    s->decode_hf     = decode_hf_c;
    s->decode_joint  = decode_joint_c;

    s->lfe_fir_float[0] = lfe_fir0_float_c;
    s->lfe_fir_float[1] = lfe_fir1_float_c;
    s->lfe_x96_float    = lfe_x96_float_c;
    s->sub_qmf_float[0] = sub_qmf32_float_c;
    s->sub_qmf_float[1] = sub_qmf64_float_c;

    s->lfe_fir_fixed    = lfe_fir_fixed_c;
    s->lfe_x96_fixed    = lfe_x96_fixed_c;
    s->sub_qmf_fixed[0] = sub_qmf32_fixed_c;
    s->sub_qmf_fixed[1] = sub_qmf64_fixed_c;

    s->decor   = decor_c;

    s->dmix_sub_xch   = dmix_sub_xch_c;
    s->dmix_sub       = dmix_sub_c;
    s->dmix_add       = dmix_add_c;
    s->dmix_scale     = dmix_scale_c;
    s->dmix_scale_inv = dmix_scale_inv_c;

    s->assemble_freq_bands = assemble_freq_bands_c;

    s->lbr_bank = lbr_bank_c;
    s->lfe_iir = lfe_iir_c;

#if ARCH_X86
    ff_dcadsp_init_x86(s);
#endif
}
```

```c
tatic int filter_frame_float(DCACoreDecoder *s, AVFrame *frame)
{
    AVCodecContext *avctx = s->avctx;
    int x96_nchannels = 0, x96_synth = 0;
    int i, n, ch, ret, spkr, nsamples, nchannels;
    float *output_samples[DCA_SPEAKER_COUNT] = { NULL }, *ptr;
    const float *filter_coeff;

    if (s->ext_audio_mask & (DCA_CSS_X96 | DCA_EXSS_X96)) {
        x96_nchannels = s->x96_nchannels;
        x96_synth = 1;
    }

    // Filter primary channels
    for (ch = 0; ch < s->nchannels; ch++) {
        // Map this primary channel to speaker
        spkr = map_prm_ch_to_spkr(s, ch);
        if (spkr < 0)
            return AVERROR(EINVAL);

        // Filter bank reconstruction
        s->dcadsp->sub_qmf_float[x96_synth](
            &s->synth,
            s->imdct[x96_synth],
            s->imdct_fn[x96_synth],
            output_samples[spkr],
            s->subband_samples[ch],
            ch < x96_nchannels ? s->x96_subband_samples[ch] : NULL,
            s->dcadsp_data[ch].u.flt.hist1,
            &s->dcadsp_data[ch].offset,
            s->dcadsp_data[ch].u.flt.hist2,
            filter_coeff,
            s->npcmblocks,
            1.0f / (1 << (17 - x96_synth)));
    }
}
```

# Example 12

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/ffmpeg-6.1.1/libavfilter/vf_vectorscope.c:1473:5*

fnptr: *s->vectorscope*

targets: vectorscope8, vectorscope16

## Related Code Snippets

```c
static int config_input(AVFilterLink *inlink)
{
    const AVPixFmtDescriptor *desc = av_pix_fmt_desc_get(inlink->format);
    AVFilterContext *ctx = inlink->dst;
    VectorscopeContext *s = ctx->priv;

    if (s->size == 256)
        s->vectorscope = vectorscope8;
    else
        s->vectorscope = vectorscope16;

    return 0;
}
```

```c
static int filter_frame(AVFilterLink *inlink, AVFrame *in)
{
    AVFilterContext *ctx  = inlink->dst;
    VectorscopeContext *s = ctx->priv;
    AVFilterLink *outlink = ctx->outputs[0];
    AVFrame *out;
    int plane;

    s->bg_color[3] = s->bgopacity * (s->size - 1);

    s->tint[0] = .5f * (s->ftint[0] + 1.f) * (s->size - 1);
    s->tint[1] = .5f * (s->ftint[1] + 1.f) * (s->size - 1);

    s->intensity = s->fintensity * (s->size - 1);

    if (s->colorspace) {
        s->cs = (s->depth - 8) * 2 + s->colorspace - 1;
    } else {
        switch (in->colorspace) {
        case AVCOL_SPC_SMPTE170M:
        case AVCOL_SPC_BT470BG:
            s->cs = (s->depth - 8) * 2 + 0;
            break;
        case AVCOL_SPC_BT709:
        default:
            s->cs = (s->depth - 8) * 2 + 1;
        }
    }

    out = ff_get_video_buffer(outlink, outlink->w, outlink->h);
    if (!out) {
        av_frame_free(&in);
        return AVERROR(ENOMEM);
    }
    av_frame_copy_props(out, in);

    s->vectorscope(s, in, out, s->pd);
    s->graticulef(s, out, s->x, s->y, s->pd, s->cs);

    for (plane = 0; plane < 4; plane++) {
        if (out->data[plane]) {
            out->data[plane]    += (s->size - 1) * out->linesize[plane];
            out->linesize[plane] = -out->linesize[plane];
        }
    }

    av_frame_free(&in);
    return ff_filter_frame(outlink, out);
}
```

```c
static void vectorscope8(VectorscopeContext *s, AVFrame *in, AVFrame *out, int pd);
static void vectorscope16(VectorscopeContext *s, AVFrame *in, AVFrame *out, int pd);
```

# Example 13

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/ffmpeg-6.1.1/libavfilter/vf_v360.c:4261:32*

fnptr: *s->out_transform*

targets: equirect_to_xyz, cube3x2_to_xyz, cube1x6_to_xyz, cube6x1_to_xyz, eac_to_xyz, flat_to_xyz, dfisheye_to_xyz, barrel_to_xyz, stereographic_to_xyz, mercator_to_xyz, ball_to_xyz, hammer_to_xyz, sinusoidal_to_xyz, fisheye_to_xyz, pannini_to_xyz, cylindrical_to_xyz, cylindricalea_to_xyz, perspective_to_xyz, tetrahedron_to_xyz, barrelsplit_to_xyz, tspyramid_to_xyz, hequirect_to_xyz, equisolid_to_xyz, orthographic_to_xyz, octahedron_to_xyz

## Related Code Snippets

```c
static int v360_slice(AVFilterContext *ctx, void *arg, int jobnr, int nb_jobs)
{
    V360Context *s = ctx->priv;

    if (s->out_transpose)
        out_mask = s->out_transform(s, j, i, height, width, vec);
    else
        out_mask = s->out_transform(s, i, j, width, height, vec);
}
```

```c
static int config_output(AVFilterLink *outlink)
{
    switch (s->out) {
    case EQUIRECTANGULAR:
        s->out_transform = equirect_to_xyz;
        prepare_out = prepare_equirect_out;
        w = lrintf(wf);
        h = lrintf(hf);
        break;
    case CUBEMAP_3_2:
        s->out_transform = cube3x2_to_xyz;
        prepare_out = prepare_cube_out;
        w = lrintf(wf / 4.f * 3.f);
        h = lrintf(hf);
        break;
    case CUBEMAP_1_6:
        s->out_transform = cube1x6_to_xyz;
        prepare_out = prepare_cube_out;
        w = lrintf(wf / 4.f);
        h = lrintf(hf * 3.f);
        break;
    case CUBEMAP_6_1:
        s->out_transform = cube6x1_to_xyz;
        prepare_out = prepare_cube_out;
        w = lrintf(wf / 2.f * 3.f);
        h = lrintf(hf / 2.f);
        break;
    case EQUIANGULAR:
        s->out_transform = eac_to_xyz;
        prepare_out = prepare_eac_out;
        w = lrintf(wf);
        h = lrintf(hf / 8.f * 9.f);
        break;
    case FLAT:
        s->out_transform = flat_to_xyz;
        prepare_out = prepare_flat_out;
        w = lrintf(wf);
        h = lrintf(hf);
        break;
    case DUAL_FISHEYE:
        s->out_transform = dfisheye_to_xyz;
        prepare_out = prepare_fisheye_out;
        w = lrintf(wf);
        h = lrintf(hf);
        break;
    case BARREL:
        s->out_transform = barrel_to_xyz;
        prepare_out = NULL;
        w = lrintf(wf / 4.f * 5.f);
        h = lrintf(hf);
        break;
    case STEREOGRAPHIC:
        s->out_transform = stereographic_to_xyz;
        prepare_out = prepare_stereographic_out;
        w = lrintf(wf);
        h = lrintf(hf * 2.f);
        break;
    case MERCATOR:
        s->out_transform = mercator_to_xyz;
        prepare_out = NULL;
        w = lrintf(wf);
        h = lrintf(hf * 2.f);
        break;
    case BALL:
        s->out_transform = ball_to_xyz;
        prepare_out = NULL;
        w = lrintf(wf);
        h = lrintf(hf * 2.f);
        break;
    case HAMMER:
        s->out_transform = hammer_to_xyz;
        prepare_out = NULL;
        w = lrintf(wf);
        h = lrintf(hf);
        break;
    case SINUSOIDAL:
        s->out_transform = sinusoidal_to_xyz;
        prepare_out = NULL;
        w = lrintf(wf);
        h = lrintf(hf);
        break;
    case FISHEYE:
        s->out_transform = fisheye_to_xyz;
        prepare_out = prepare_fisheye_out;
        w = lrintf(wf * 0.5f);
        h = lrintf(hf);
        break;
    case PANNINI:
        s->out_transform = pannini_to_xyz;
        prepare_out = NULL;
        w = lrintf(wf);
        h = lrintf(hf);
        break;
    case CYLINDRICAL:
        s->out_transform = cylindrical_to_xyz;
        prepare_out = prepare_cylindrical_out;
        w = lrintf(wf);
        h = lrintf(hf * 0.5f);
        break;
    case CYLINDRICALEA:
        s->out_transform = cylindricalea_to_xyz;
        prepare_out = prepare_cylindricalea_out;
        w = lrintf(wf);
        h = lrintf(hf);
        break;
    case PERSPECTIVE:
        s->out_transform = perspective_to_xyz;
        prepare_out = NULL;
        w = lrintf(wf / 2.f);
        h = lrintf(hf);
        break;
    case TETRAHEDRON:
        s->out_transform = tetrahedron_to_xyz;
        prepare_out = NULL;
        w = lrintf(wf);
        h = lrintf(hf);
        break;
    case BARREL_SPLIT:
        s->out_transform = barrelsplit_to_xyz;
        prepare_out = NULL;
        w = lrintf(wf / 4.f * 3.f);
        h = lrintf(hf);
        break;
    case TSPYRAMID:
        s->out_transform = tspyramid_to_xyz;
        prepare_out = NULL;
        w = lrintf(wf);
        h = lrintf(hf);
        break;
    case HEQUIRECTANGULAR:
        s->out_transform = hequirect_to_xyz;
        prepare_out = NULL;
        w = lrintf(wf / 2.f);
        h = lrintf(hf);
        break;
    case EQUISOLID:
        s->out_transform = equisolid_to_xyz;
        prepare_out = prepare_equisolid_out;
        w = lrintf(wf);
        h = lrintf(hf * 2.f);
        break;
    case ORTHOGRAPHIC:
        s->out_transform = orthographic_to_xyz;
        prepare_out = prepare_orthographic_out;
        w = lrintf(wf);
        h = lrintf(hf * 2.f);
        break;
    case OCTAHEDRON:
        s->out_transform = octahedron_to_xyz;
        prepare_out = NULL;
        w = lrintf(wf);
        h = lrintf(hf * 2.f);
        break;
    default:
        av_log(ctx, AV_LOG_ERROR, "Specified output format is not handled.\n");
        return AVERROR_BUG;
    }
}
```

# Example 14

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/ffmpeg-6.1.1/libavcodec/mss2.c:439:9*

fnptr: *ctx->dsp.upsample_plane*

targets: upsample_plane_c

## Related Code Snippets

```c
static int decode_wmv9(AVCodecContext *avctx, const uint8_t *buf, int buf_size,
                       int x, int y, int w, int h, int wmv9_mask)
{
    MSS2Context *ctx  = avctx->priv_data;
    if (v->respic == 3) {
        ctx->dsp.upsample_plane(f->data[0], f->linesize[0], w,      h);
        ctx->dsp.upsample_plane(f->data[1], f->linesize[1], w+1 >> 1, h+1 >> 1);
        ctx->dsp.upsample_plane(f->data[2], f->linesize[2], w+1 >> 1, h+1 >> 1);
    } else if (v->respic)
        avpriv_request_sample(v->s.avctx,
                              "Asymmetric WMV9 rectangle subsampling");
}
```

```c
av_cold void ff_mss2dsp_init(MSS2DSPContext* dsp)
{
    dsp->mss2_blit_wmv9        = mss2_blit_wmv9_c;
    dsp->mss2_blit_wmv9_masked = mss2_blit_wmv9_masked_c;
    dsp->mss2_gray_fill_masked = mss2_gray_fill_masked_c;
    dsp->upsample_plane        = upsample_plane_c;
}
```

```c
typedef struct MSS2Context {
    VC1Context     v;
    int            split_position;
    AVFrame       *last_pic;
    MSS12Context   c;
    MSS2DSPContext dsp;
    SliceContext   sc[2];
} MSS2Context;
```

# Example 15

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/ffmpeg-6.1.1/libavcodec/nellymoserenc.c:132:5*

fnptr: *s->fdsp->vector_fmul*

targets: vector_fmul_c, ff_vector_fmul_neon, ff_vector_fmul_vfp

## Related Code Snippets

```c
static void apply_mdct(NellyMoserEncodeContext *s)
{
    float *in0 = s->buf;
    float *in1 = s->buf + NELLY_BUF_LEN;
    float *in2 = s->buf + 2 * NELLY_BUF_LEN;

    s->fdsp->vector_fmul        (s->in_buff,                 in0, ff_sine_128, NELLY_BUF_LEN);
    s->fdsp->vector_fmul_reverse(s->in_buff + NELLY_BUF_LEN, in1, ff_sine_128, NELLY_BUF_LEN);
    s->mdct_fn(s->mdct_ctx, s->mdct_out, s->in_buff, sizeof(float));

    s->fdsp->vector_fmul        (s->in_buff,                 in1, ff_sine_128, NELLY_BUF_LEN);
    s->fdsp->vector_fmul_reverse(s->in_buff + NELLY_BUF_LEN, in2, ff_sine_128, NELLY_BUF_LEN);
    s->mdct_fn(s->mdct_ctx, s->mdct_out + NELLY_BUF_LEN, s->in_buff, sizeof(float));
}
```

```c
typedef struct NellyMoserEncodeContext {
    AVCodecContext  *avctx;
    int             last_frame;
    AVFloatDSPContext *fdsp;
    AVTXContext    *mdct_ctx;
    av_tx_fn        mdct_fn;
    AudioFrameQueue afq;
    DECLARE_ALIGNED(32, float, mdct_out)[NELLY_SAMPLES];
    DECLARE_ALIGNED(32, float, in_buff)[NELLY_SAMPLES];
    DECLARE_ALIGNED(32, float, buf)[3 * NELLY_BUF_LEN];     ///< sample buffer
    float           (*opt )[OPT_SIZE];
    uint8_t         (*path)[OPT_SIZE];
} NellyMoserEncodeContext;
```

```c
av_cold AVFloatDSPContext *avpriv_float_dsp_alloc(int bit_exact)
{
    AVFloatDSPContext *fdsp = av_mallocz(sizeof(AVFloatDSPContext));
    if (!fdsp)
        return NULL;

    fdsp->vector_fmul = vector_fmul_c;
    fdsp->vector_dmul = vector_dmul_c;
    fdsp->vector_fmac_scalar = vector_fmac_scalar_c;
    fdsp->vector_fmul_scalar = vector_fmul_scalar_c;
    fdsp->vector_dmac_scalar = vector_dmac_scalar_c;
    fdsp->vector_dmul_scalar = vector_dmul_scalar_c;
    fdsp->vector_fmul_window = vector_fmul_window_c;
    fdsp->vector_fmul_add = vector_fmul_add_c;
    fdsp->vector_fmul_reverse = vector_fmul_reverse_c;
    fdsp->butterflies_float = butterflies_float_c;
    fdsp->scalarproduct_float = avpriv_scalarproduct_float_c;

#if ARCH_AARCH64
    ff_float_dsp_init_aarch64(fdsp);
#elif ARCH_ARM
    ff_float_dsp_init_arm(fdsp);
#elif ARCH_PPC
    ff_float_dsp_init_ppc(fdsp, bit_exact);
#elif ARCH_RISCV
    ff_float_dsp_init_riscv(fdsp);
#elif ARCH_X86
    ff_float_dsp_init_x86(fdsp);
#elif ARCH_MIPS
    ff_float_dsp_init_mips(fdsp);
#endif
    return fdsp;
}
```

```c
av_cold void ff_float_dsp_init_neon(AVFloatDSPContext *fdsp)
{
    fdsp->vector_fmul = ff_vector_fmul_neon;
    fdsp->vector_fmac_scalar = ff_vector_fmac_scalar_neon;
    fdsp->vector_fmul_scalar = ff_vector_fmul_scalar_neon;
    fdsp->vector_fmul_window = ff_vector_fmul_window_neon;
    fdsp->vector_fmul_add    = ff_vector_fmul_add_neon;
    fdsp->vector_fmul_reverse = ff_vector_fmul_reverse_neon;
    fdsp->butterflies_float = ff_butterflies_float_neon;
    fdsp->scalarproduct_float = ff_scalarproduct_float_neon;
}
```

```c
av_cold void ff_float_dsp_init_vfp(AVFloatDSPContext *fdsp, int cpu_flags)
{
    if (have_vfp_vm(cpu_flags)) {
        fdsp->vector_fmul = ff_vector_fmul_vfp;
        fdsp->vector_fmul_window = ff_vector_fmul_window_vfp;
    }
    fdsp->vector_fmul_reverse = ff_vector_fmul_reverse_vfp;
    if (have_vfp_vm(cpu_flags))
        fdsp->butterflies_float = ff_butterflies_float_vfp;
}
```

```c
av_cold void ff_float_dsp_init_arm(AVFloatDSPContext *fdsp)
{
    int cpu_flags = av_get_cpu_flags();

    if (have_vfp(cpu_flags))
        ff_float_dsp_init_vfp(fdsp, cpu_flags);
    if (have_neon(cpu_flags))
        ff_float_dsp_init_neon(fdsp);
}
```

# Example 16

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/ffmpeg-6.1.1/libavcodec/rawdec.c:323:17*

fnptr: *context->bbdsp.bswap16_buf*

targets: bswap16_buf, ff_bswap16_buf_rvv

## Related Code Snippets

```c
static int raw_decode(AVCodecContext *avctx, AVFrame *frame,
                      int *got_frame, AVPacket *avpkt)
{
  if (packed && swap) {
    av_fast_padded_malloc(&context->bitstream_buf, &context->bitstream_buf_size, buf_size);
    if (!context->bitstream_buf)
        return AVERROR(ENOMEM);
    if (swap == 16)
        context->bbdsp.bswap16_buf(context->bitstream_buf, (const uint16_t*)buf, buf_size / 2);
    else if (swap == 32)
        context->bbdsp.bswap_buf(context->bitstream_buf, (const uint32_t*)buf, buf_size / 4);
    else
        return AVERROR_INVALIDDATA;
    buf = context->bitstream_buf;
  }
}
```

```c
av_cold void ff_bswapdsp_init(BswapDSPContext *c)
{
    c->bswap_buf   = bswap_buf;
    c->bswap16_buf = bswap16_buf;

#if ARCH_RISCV
    ff_bswapdsp_init_riscv(c);
#elif ARCH_X86
    ff_bswapdsp_init_x86(c);
#endif
}
```

```c
av_cold void ff_bswapdsp_init_riscv(BswapDSPContext *c)
{
    int flags = av_get_cpu_flags();

    if (flags & AV_CPU_FLAG_RVB_ADDR) {
#if (__riscv_xlen >= 64)
        if (flags & AV_CPU_FLAG_RVB_BASIC)
            c->bswap_buf = ff_bswap32_buf_rvb;
#endif
#if HAVE_RVV
        if (flags & AV_CPU_FLAG_RVV_I32)
            c->bswap16_buf = ff_bswap16_buf_rvv;
#endif
    }
}
```

# Example 17

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/ffmpeg-6.1.1/libavcodec/amrwbdec.c:808:5*

fnptr: *ctx->celpf_ctx.celp_lp_synthesis_filterf*

targets: ff_celp_lp_synthesis_filterf, ff_celp_lp_synthesis_filterf_mips

## Related Code Snippets

```c
static void synthesis(AMRWBContext *ctx, float *lpc, float *excitation,
                      float fixed_gain, const float *fixed_vector,
                      float *samples)
{
    ctx->acelpv_ctx.weighted_vector_sumf(excitation, ctx->pitch_vector, fixed_vector,
                            ctx->pitch_gain[0], fixed_gain, AMRWB_SFR_SIZE);

    /* emphasize pitch vector contribution in low bitrate modes */
    if (ctx->pitch_gain[0] > 0.5 && ctx->fr_cur_mode <= MODE_8k85) {
        int i;
        float energy = ctx->celpm_ctx.dot_productf(excitation, excitation,
                                                    AMRWB_SFR_SIZE);

        // XXX: Weird part in both ref code and spec. A unknown parameter
        // {beta} seems to be identical to the current pitch gain
        float pitch_factor = 0.25 * ctx->pitch_gain[0] * ctx->pitch_gain[0];

        for (i = 0; i < AMRWB_SFR_SIZE; i++)
            excitation[i] += pitch_factor * ctx->pitch_vector[i];

        ff_scale_vector_to_given_sum_of_squares(excitation, excitation,
                                                energy, AMRWB_SFR_SIZE);
    }

    ctx->celpf_ctx.celp_lp_synthesis_filterf(samples, lpc, excitation,
                                 AMRWB_SFR_SIZE, LP_ORDER);
}
```

```c
void ff_celp_filter_init(CELPFContext *c)
{
    c->celp_lp_synthesis_filterf        = ff_celp_lp_synthesis_filterf;
    c->celp_lp_zero_synthesis_filterf   = ff_celp_lp_zero_synthesis_filterf;

#if HAVE_MIPSFPU
    ff_celp_filter_init_mips(c);
#endif
}
```

```c
void ff_celp_filter_init_mips(CELPFContext *c)
{
#if HAVE_INLINE_ASM
#if !HAVE_MIPS32R6 && !HAVE_MIPS64R6
    c->celp_lp_synthesis_filterf        = ff_celp_lp_synthesis_filterf_mips;
    c->celp_lp_zero_synthesis_filterf   = ff_celp_lp_zero_synthesis_filterf_mips;
#endif
#endif
}
```

# Example 18

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/openssh-build/../openssh-9.6p1/kex.c:1425:6*

fnptr: *kex->verify_host_key*

targets: key_print_wrapper, _ssh_verify_host_key

## Related Code Snippets

```c
int
kex_verify_host_key(struct ssh *ssh, struct sshkey *server_host_key)
{
	struct kex *kex = ssh->kex;

	if (kex->verify_host_key == NULL) {
		error_f("missing hostkey verifier");
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if (server_host_key->type != kex->hostkey_type ||
	    (kex->hostkey_type == KEY_ECDSA &&
	    server_host_key->ecdsa_nid != kex->hostkey_nid))
		return SSH_ERR_KEY_TYPE_MISMATCH;
	if (kex->verify_host_key(server_host_key, ssh) == -1)
		return  SSH_ERR_SIGNATURE_INVALID;
	return 0;
}
```

```c
int
ssh_init(struct ssh **sshp, int is_server, struct kex_params *kex_params)
{
	struct ssh *ssh;

	if ((ssh = ssh_packet_set_connection(NULL, -1, -1)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (is_server)
		ssh_packet_set_server(ssh);

	ssh->kex->server = is_server;
	if (is_server) {
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
		ssh->kex->verify_host_key =&_ssh_verify_host_key;
	}
	*sshp = ssh;
	return 0;
}
```

```c
int
_ssh_verify_host_key(struct sshkey *hostkey, struct ssh *ssh)
{
	struct key_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_keys, next) {
		debug3_f("check %s", sshkey_type(k->key));
		if (sshkey_equal_public(hostkey, k->key))
			return (0);	/* ok */
	}
	return (-1);	/* failed */
}
```

```c
int
ssh_set_verify_host_key_callback(struct ssh *ssh,
    int (*cb)(struct sshkey *, struct ssh *))
{
	if (cb == NULL || ssh->kex == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_key = cb;

	return 0;
}
```

```c
static void
keygrab_ssh2(con *c)
{
	ssh_set_verify_host_key_callback(c->c_ssh, key_print_wrapper);
}
```

```c
static int
key_print_wrapper(struct sshkey *hostkey, struct ssh *ssh)
{
	con *c;

	if ((c = ssh_get_app_data(ssh)) != NULL)
		keyprint(c, hostkey);
	/* always abort key exchange */
	return -1;
}

```

# Example 19

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/openssh-build/../openssh-9.6p1/channels.c:2168:14*

fnptr: *c->output_filter*

targets: sys_tun_outfilter

## Related Code Snippets

```c
static int
channel_handle_wfd(struct ssh *ssh, Channel *c)
{
	u_char *data = NULL, *buf; /* XXX const; need filter API change */
	size_t dlen, olen = 0;
	int r, len;

	/* Send buffered output data to the socket. */
	olen = sshbuf_len(c->output);
	if (c->output_filter != NULL) {
		if ((buf = c->output_filter(ssh, c, &data, &dlen)) == NULL) {
			debug2("channel %d: filter stops", c->self);
			if (c->type != SSH_CHANNEL_OPEN)
				chan_mark_dead(ssh, c);
			else
				chan_write_failed(ssh, c);
			return -1;
		}
	}

 out:
	c->local_consumed += olen - sshbuf_len(c->output);
	return 1;
}
```

```c
void
channel_register_filter(struct ssh *ssh, int id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn, channel_filter_cleanup_fn *cfn, void *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	if (c == NULL) {
		logit_f("%d: bad id", id);
		return;
	}
	c->input_filter = ifn;
	c->output_filter = ofn;
	c->filter_ctx = ctx;
	c->filter_cleanup = cfn;
}
```

```c
int
client_loop(struct ssh *ssh, int have_pty, int escape_char_arg,
    int ssh2_chan_id)
{
	if (session_ident != -1) {
		if (escape_char_arg != SSH_ESCAPECHAR_NONE) {
			channel_register_filter(ssh, session_ident,
			    client_simple_escape_filter, NULL,
			    client_filter_cleanup,
			    client_new_escape_filter_ctx(
			    escape_char_arg));
		}
	}

	return exit_status;
}
```

```c
char *
client_request_tun_fwd(struct ssh *ssh, int tun_mode,
    int local_tun, int remote_tun, channel_open_fn *cb, void *cbctx)
{
	Channel *c;
	int r, fd;
	char *ifname = NULL;

	if (tun_mode == SSH_TUNMODE_NO)
		return 0;

	debug("Requesting tun unit %d in mode %d", local_tun, tun_mode);

	/* Open local tunnel device */
	if ((fd = tun_open(local_tun, tun_mode, &ifname)) == -1) {
		error("Tunnel device open failed.");
		return NULL;
	}
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun-connection", SSH_CHANNEL_OPENING, fd, fd, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;

#if defined(SSH_TUN_FILTER)
	if (options.tun_open == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, NULL, NULL);
#endif

	if (cb != NULL)
		channel_register_open_confirm(ssh, c->self, cb, cbctx);

	if ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "tun@openssh.com")) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window_max)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
	    (r = sshpkt_put_u32(ssh, tun_mode)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_tun)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send reply", __func__);

	return ifname;
}
```

# Example 20

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/openssh-build/../openssh-9.6p1/channels.c:3612:3*

fnptr: *c->open_confirm*

targets: mux_session_confirm, mux_stdio_confirm, ssh_stdio_confirm, ssh_session2_setup, ssh_tun_confirm

## Related Code Snippets

```c
int
channel_input_open_failure(int type, u_int32_t seq, struct ssh *ssh)
{
	Channel *c = channel_from_packet_id(ssh, __func__, "open failure");
	u_int32_t reason;
	char *msg = NULL;
	int r;

	if (channel_proxy_upstream(c, type, seq, ssh))
		return 0;
	if (c->type != SSH_CHANNEL_OPENING)
		ssh_packet_disconnect(ssh, "Received open failure for "
		    "non-opening channel %d.", c->self);
	if ((r = sshpkt_get_u32(ssh, &reason)) != 0) {
		error_fr(r, "parse reason");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	/* skip language */
	if ((r = sshpkt_get_cstring(ssh, &msg, NULL)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, NULL, NULL)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error_fr(r, "parse msg/lang");
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	}
	logit("channel %d: open failed: %s%s%s", c->self,
	    reason2txt(reason), msg ? ": ": "", msg ? msg : "");
	free(msg);
	if (c->open_confirm) {
		debug2_f("channel %d: callback start", c->self);
		c->open_confirm(ssh, c->self, 0, c->open_confirm_ctx);
		debug2_f("channel %d: callback done", c->self);
	}
	/* Schedule the channel for cleanup/deletion. */
	chan_mark_dead(ssh, c);
	return 0;
}
```

```c
void
channel_register_open_confirm(struct ssh *ssh, int id,
    channel_open_fn *fn, void *ctx)
{
	Channel *c = channel_lookup(ssh, id);

	if (c == NULL) {
		logit_f("%d: bad id", id);
		return;
	}
	c->open_confirm = fn;
	c->open_confirm_ctx = ctx;
}
```

```c
char *
client_request_tun_fwd(struct ssh *ssh, int tun_mode,
    int local_tun, int remote_tun, channel_open_fn *cb, void *cbctx)
{
	if (cb != NULL)
		channel_register_open_confirm(ssh, c->self, cb, cbctx);
}
```

```c
static int
mux_master_process_new_session(struct ssh *ssh, u_int rid,
    Channel *c, struct sshbuf *m, struct sshbuf *reply)
{
	channel_register_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
}
```

```c
static int
mux_master_process_stdio_fwd(struct ssh *ssh, u_int rid,
    Channel *c, struct sshbuf *m, struct sshbuf *reply)
{
	channel_register_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
}
```

```c
static void
ssh_init_stdio_forwarding(struct ssh *ssh)
{
	Channel *c;
	int in, out;

	if (options.stdio_forward_host == NULL)
		return;

	debug3_f("%s:%d", options.stdio_forward_host,
	    options.stdio_forward_port);

	if ((in = dup(STDIN_FILENO)) == -1 ||
	    (out = dup(STDOUT_FILENO)) == -1)
		fatal_f("dup() in/out failed");
	if ((c = channel_connect_stdio_fwd(ssh, options.stdio_forward_host,
	    options.stdio_forward_port, in, out,
	    CHANNEL_NONBLOCK_STDIO)) == NULL)
		fatal_f("channel_connect_stdio_fwd failed");
	channel_register_cleanup(ssh, c->self, client_cleanup_stdio_fwd, 0);
	channel_register_open_confirm(ssh, c->self, ssh_stdio_confirm, NULL);
}
```

```c
static int
ssh_session2_open(struct ssh *ssh)
{
	Channel *c;
	int window, packetmax, in, out, err;

	if (options.stdin_null) {
		in = open(_PATH_DEVNULL, O_RDONLY);
	} else {
		in = dup(STDIN_FILENO);
	}
	out = dup(STDOUT_FILENO);
	err = dup(STDERR_FILENO);

	if (in == -1 || out == -1 || err == -1)
		fatal("dup() in/out/err failed");

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	if (tty_flag) {
		window >>= 1;
		packetmax >>= 1;
	}
	c = channel_new(ssh,
	    "session", SSH_CHANNEL_OPENING, in, out, err,
	    window, packetmax, CHAN_EXTENDED_WRITE,
	    "client-session", CHANNEL_NONBLOCK_STDIO);

	debug3_f("channel_new: %d", c->self);

	channel_send_open(ssh, c->self);
	if (options.session_type != SESSION_TYPE_NONE)
		channel_register_open_confirm(ssh, c->self,
		    ssh_session2_setup, NULL);

	return c->self;
}
```

```c
static void
ssh_init_forwarding(struct ssh *ssh, char **ifname)
{
	/* Initiate tunnel forwarding. */
	if (options.tun_open != SSH_TUNMODE_NO) {
		if ((*ifname = client_request_tun_fwd(ssh,
		    options.tun_open, options.tun_local,
		    options.tun_remote, ssh_tun_confirm, NULL)) != NULL)
			forward_confirms_pending++;
	}
}
```