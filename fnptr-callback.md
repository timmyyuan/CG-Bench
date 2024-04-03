# Example 1

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/curl-build/lib/../../curl-8.5.0/lib/vauth/digest.c:806:3*

fnptr: *convert_to_ascii*

targets: auth_digest_md5_to_ascii, auth_digest_sha256_to_ascii

## Related Code Snippets

```c
static CURLcode auth_create_digest_http_message(
                  struct Curl_easy *data,
                  const char *userp,
                  const char *passwdp,
                  const unsigned char *request,
                  const unsigned char *uripath,
                  struct digestdata *digest,
                  char **outptr, size_t *outlen,
                  void (*convert_to_ascii)(unsigned char *, unsigned char *),
                  CURLcode (*hash)(unsigned char *, const unsigned char *,
                                   const size_t))
{
    if(digest->userhash) {
    hashthis = aprintf("%s:%s", userp, digest->realm ? digest->realm : "");
    if(!hashthis)
        return CURLE_OUT_OF_MEMORY;
    
    hash(hashbuf, (unsigned char *) hashthis, strlen(hashthis));
    free(hashthis);
    convert_to_ascii(hashbuf, (unsigned char *)userh);
    }
}
```

```c
CURLcode Curl_auth_create_digest_http_message(struct Curl_easy *data,
                                              const char *userp,
                                              const char *passwdp,
                                              const unsigned char *request,
                                              const unsigned char *uripath,
                                              struct digestdata *digest,
                                              char **outptr, size_t *outlen)
{
  if(digest->algo <= ALGO_MD5SESS)
    return auth_create_digest_http_message(data, userp, passwdp,
                                           request, uripath, digest,
                                           outptr, outlen,
                                           auth_digest_md5_to_ascii,
                                           Curl_md5it);
  DEBUGASSERT(digest->algo <= ALGO_SHA512_256SESS);
  return auth_create_digest_http_message(data, userp, passwdp,
                                         request, uripath, digest,
                                         outptr, outlen,
                                         auth_digest_sha256_to_ascii,
                                         Curl_sha256it);
}
```

# Example 2

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/wrk-4.2.0/src/wrk.c:551:17*

fnptr: *fmt*

targets: format_time_us, format_metric

## Related Code Snippets

```c
static void print_units(long double n, char *(*fmt)(long double), int width) {
char *msg = fmt(n);
    int len = strlen(msg), pad = 2;

    if (isalpha(msg[len-1])) pad--;
    if (isalpha(msg[len-2])) pad--;
    width -= pad;

    printf("%*.*s%.*s", width, width, msg, pad, "  ");

    free(msg);
}
```

```c
static void print_stats_latency(stats *stats) {
    long double percentiles[] = { 50.0, 75.0, 90.0, 99.0 };
    printf("  Latency Distribution\n");
    for (size_t i = 0; i < sizeof(percentiles) / sizeof(long double); i++) {
        long double p = percentiles[i];
        uint64_t n = stats_percentile(stats, p);
        printf("%7.0Lf%%", p);
        print_units(n, format_time_us, 10);
        printf("\n");
    }
}
```

```c
static void print_stats(char *name, stats *stats, char *(*fmt)(long double)) {
    uint64_t max = stats->max;
    long double mean  = stats_mean(stats);
    long double stdev = stats_stdev(stats, mean);

    printf("    %-10s", name);
    print_units(mean,  fmt, 8);
    print_units(stdev, fmt, 10);
    print_units(max,   fmt, 9);
    printf("%8.2Lf%%\n", stats_within_stdev(stats, mean, stdev, 1));
}
```

```c
int main(int argc, char **argv) {
    char *url, **headers = zmalloc(argc * sizeof(char *));
    struct http_parser_url parts = {};

    if (parse_args(&cfg, &url, &parts, headers, argc, argv)) {
        usage();
        exit(1);
    }
    ...
    print_stats_header();
    print_stats("Latency", statistics.latency, format_time_us);
    print_stats("Req/Sec", statistics.requests, format_metric);
    ...
}
```

# Example 3

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/lib/libshare/nfs.c:202:11*

fnptr: *cbk*

targets: nfs_is_shared_cb, nfs_copy_entries_cb

## Related Code Snippets

```c
static nfs_process_exports(const char *exports, const char *mountpoint,
    boolean_t (*cbk)(void *userdata, char *line, boolean_t found_mountpoint),
    void *userdata)
{
	int error = SA_OK;
	boolean_t cont = B_TRUE;

	FILE *oldfp = fopen(exports, "re");
	if (oldfp != NULL) {
		...

		while (cont && getline(&buf, &buflen, oldfp) != -1) {
			if (buf[0] == '\n' || buf[0] == '#')
				continue;

			cont = cbk(userdata, buf,
			    (sep = strpbrk(buf, "\t \n")) != NULL &&
			    sep - buf == mplen &&
			    strncmp(buf, mp, mplen) == 0);
		... 
	    }

	    return (error);
    }
}
```

```c
static nfs_copy_entries(FILE *newfp, const char *exports, const char *mountpoint)
{
	fputs(FILE_HEADER, newfp);

	int error = nfs_process_exports(
	    exports, mountpoint, nfs_copy_entries_cb, newfp);

	if (error == SA_OK && ferror(newfp) != 0)
		error = ferror(newfp);

	return (error);
}
```

```c
boolean_t nfs_is_shared_impl(const char *exports, sa_share_impl_t impl_share)
{
	boolean_t found = B_FALSE;
	nfs_process_exports(exports, impl_share->sa_mountpoint,
	    nfs_is_shared_cb, &found);
	return (found);
}
```

# Example 4

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/ffmpeg-6.1.1/libavcodec/allcodecs.c:957:14*

fnptr: *x*

targets: av_codec_is_decoder, av_codec_is_encoder

## Related Code Snippets

```c
static const AVCodec *find_codec(enum AVCodecID id, int (*x)(const AVCodec *))
{
    const AVCodec *p, *experimental = NULL;
    void *i = 0;

    id = remap_deprecated_codec_id(id);

    while ((p = av_codec_iterate(&i))) {
        if (!x(p))
            continue;
        if (p->id == id) {
            if (p->capabilities & AV_CODEC_CAP_EXPERIMENTAL && !experimental) {
                experimental = p;
            } else
                return p;
        }
    }

    return experimental;
}
```

```c
const AVCodec *avcodec_find_encoder(enum AVCodecID id)
{
    return find_codec(id, av_codec_is_encoder);
}

const AVCodec *avcodec_find_decoder(enum AVCodecID id)
{
    return find_codec(id, av_codec_is_decoder);
}

```

# Example 5

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/src/quicklist.c:1543:21*

fnptr: *saver*

targets: _quicklistSaver, listPopSaver

## Related Code Snippets

```c
int quicklistPopCustom(quicklist *quicklist, int where, unsigned char **data,
                       size_t *sz, long long *sval,
                       void *(*saver)(unsigned char *data, size_t sz)) {
    unsigned char *p;
    unsigned char *vstr;
    unsigned int vlen;
    long long vlong;
    int pos = (where == QUICKLIST_HEAD) ? 0 : -1;

    ...

    if (unlikely(QL_NODE_IS_PLAIN(node))) {
        if (data)
            *data = saver(node->entry, node->sz);
        if (sz)
            *sz = node->sz;
        quicklistDelIndex(quicklist, node, NULL);
        return 1;
    }
    ...
}
```

```c
robj *listTypePop(robj *subject, int where) {
    robj *value = NULL;

    if (subject->encoding == OBJ_ENCODING_QUICKLIST) {
        long long vlong;
        int ql_where = where == LIST_HEAD ? QUICKLIST_HEAD : QUICKLIST_TAIL;
        if (quicklistPopCustom(subject->ptr, ql_where, (unsigned char **)&value,
                               NULL, &vlong, listPopSaver)) {
            if (!value)
                value = createStringObjectFromLongLong(vlong);
        }
        ...
    }
}
```

```c
int quicklistPop(quicklist *quicklist, int where, unsigned char **data,
                 size_t *sz, long long *slong) {
    unsigned char *vstr = NULL;
    size_t vlen = 0;
    long long vlong = 0;
    if (quicklist->count == 0)
        return 0;
    int ret = quicklistPopCustom(quicklist, where, &vstr, &vlen, &vlong,
                                 _quicklistSaver);
    ...
}
```

# Example 6

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/deps/jemalloc/include/jemalloc/internal/emap.h:329:21*

fnptr: *ptr_getter*

targets: tcache_bin_flush_ptr_getter

## Related Code Snippets

```c
JEMALLOC_ALWAYS_INLINE void
emap_edata_lookup_batch(tsd_t *tsd, emap_t *emap, size_t nptrs,
    emap_ptr_getter ptr_getter, void *ptr_getter_ctx,
    emap_metadata_visitor metadata_visitor, void *metadata_visitor_ctx,
    emap_batch_lookup_result_t *result) {
	...

	for (size_t i = 0; i < nptrs; i++) {
		const void *ptr = ptr_getter(ptr_getter_ctx, i);

		result[i].rtree_leaf = rtree_leaf_elm_lookup(tsd_tsdn(tsd),
		    &emap->rtree, rtree_ctx, (uintptr_t)ptr,
		    /* dependent */ true, /* init_missing */ false);
	}

	...
}
```

```c
static void
tcache_bin_flush_edatas_lookup(tsd_t *tsd, cache_bin_ptr_array_t *arr,
    szind_t binind, size_t nflush, emap_batch_lookup_result_t *edatas) {

	size_t szind_sum = binind * nflush;
	emap_edata_lookup_batch(tsd, &arena_emap_global, nflush,
	    &tcache_bin_flush_ptr_getter, (void *)arr,
	    &tcache_bin_flush_metadata_visitor, (void *)&szind_sum,
	    edatas);
	if (config_opt_safety_checks && unlikely(szind_sum != 0)) {
		tcache_bin_flush_size_check_fail(arr, binind, nflush, edatas);
	}
}
```

# Example 7

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/src/defrag.c:583:23*

fnptr: *element_cb*

targets: defragStreamConsumerPendingEntry, defragStreamConsumer, defragStreamConsumerGroup

## Related Code Snippets

```c
void defragRadixTree(rax **raxref, int defrag_data, raxDefragFunction *element_cb, void *element_cb_data) {
    raxIterator ri;
    rax* rax;
    ...
    while (raxNext(&ri)) {
        void *newdata = NULL;
        if (element_cb)
            newdata = element_cb(&ri, element_cb_data);
        if (defrag_data && !newdata)
            newdata = activeDefragAlloc(ri.data);
        if (newdata)
            raxSetData(ri.node, ri.data=newdata);
    }
    raxStop(&ri);
}
```

```c
void* defragStreamConsumer(raxIterator *ri, void *privdata) {
    streamConsumer *c = ri->data;
    streamCG *cg = privdata;
    void *newc = activeDefragAlloc(c);
    if (newc) {
        c = newc;
    }
    sds newsds = activeDefragSds(c->name);
    if (newsds)
        c->name = newsds;
    if (c->pel) {
        PendingEntryContext pel_ctx = {cg, c};
        defragRadixTree(&c->pel, 0, defragStreamConsumerPendingEntry, &pel_ctx);
    }
    return newc; /* returns NULL if c was not defragged */
}
```

```c
void* defragStreamConsumerGroup(raxIterator *ri, void *privdata) {
    streamCG *cg = ri->data;
    UNUSED(privdata);
    if (cg->consumers)
        defragRadixTree(&cg->consumers, 0, defragStreamConsumer, cg);
    if (cg->pel)
        defragRadixTree(&cg->pel, 0, NULL, NULL);
    return NULL;
}
```

```c
void defragStream(redisDb *db, dictEntry *kde) {
    robj *ob = dictGetVal(kde);
    serverAssert(ob->type == OBJ_STREAM && ob->encoding == OBJ_ENCODING_STREAM);
    stream *s = ob->ptr, *news;

    /* handle the main struct */
    if ((news = activeDefragAlloc(s)))
        ob->ptr = s = news;

    if (raxSize(s->rax) > server.active_defrag_max_scan_fields) {
        rax *newrax = activeDefragAlloc(s->rax);
        if (newrax)
            s->rax = newrax;
        defragLater(db, kde);
    } else
        defragRadixTree(&s->rax, 1, NULL, NULL);

    if (s->cgroups)
        defragRadixTree(&s->cgroups, 1, defragStreamConsumerGroup, NULL);
}
```

# Example 8

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/src/pqsort.c:95:38*

fnptr: *cmp*

targets: sort_gp_asc, sort_gp_desc, sortCompare

## Related Code Snippets

```c
static inline char *
med3(char *a, char *b, char *c,
    int (*cmp) (const void *, const void *))
{

	return cmp(a, b) < 0 ?
	       (cmp(b, c) < 0 ? b : (cmp(a, c) < 0 ? c : a ))
              :(cmp(b, c) > 0 ? b : (cmp(a, c) < 0 ? a : c ));
}
```

```c
static void _pqsort(void *a, size_t n, size_t es,
    int (*cmp) (const void *, const void *), void *lrange, void *rrange)
{
	char *pa, *pb, *pc, *pd, *pl, *pm, *pn;
	size_t d, r;
	int swaptype, cmp_result;

loop:	SWAPINIT(a, es);
	if (n < 7) {
		for (pm = (char *) a + es; pm < (char *) a + n * es; pm += es)
			for (pl = pm; pl > (char *) a && cmp(pl - es, pl) > 0;
			     pl -= es)
				swap(pl, pl - es);
		return;
	}
	pm = (char *) a + (n / 2) * es;
	if (n > 7) {
		pl = (char *) a;
		pn = (char *) a + (n - 1) * es;
		if (n > 40) {
			d = (n / 8) * es;
			pl = med3(pl, pl + d, pl + 2 * d, cmp);
			pm = med3(pm - d, pm, pm + d, cmp);
			pn = med3(pn - 2 * d, pn - d, pn, cmp);
		}
		pm = med3(pl, pm, pn, cmp);
	}
}
```

```c
void
pqsort(void *a, size_t n, size_t es,
    int (*cmp) (const void *, const void *), size_t lrange, size_t rrange)
{
    _pqsort(a,n,es,cmp,((unsigned char*)a)+(lrange*es),
                       ((unsigned char*)a)+((rrange+1)*es)-1);
}
```

```c
void georadiusGeneric(client *c, int srcKeyIndex, int flags) {
    robj *storekey = NULL;
    ...

    /* Process [optional] requested sorting */
    if (sort != SORT_NONE) {
        int (*sort_gp_callback)(const void *a, const void *b) = NULL;
        if (sort == SORT_ASC) {
            sort_gp_callback = sort_gp_asc;
        } else if (sort == SORT_DESC) {
            sort_gp_callback = sort_gp_desc;
        }

        if (returned_items == result_length) {
            qsort(ga->array, result_length, sizeof(geoPoint), sort_gp_callback);
        } else {
            pqsort(ga->array, result_length, sizeof(geoPoint), sort_gp_callback,
                0, (returned_items - 1));
        }
    }
}
```

```c
void sortCommandGeneric(client *c, int readonly) {
    ...

    /* Now it's time to load the right scores in the sorting vector */
    if (!dontsort) {
        ...
        if (sortby && (start != 0 || end != vectorlen-1))
            pqsort(vector,vectorlen,sizeof(redisSortObject),sortCompare, start,end);
        else
            qsort(vector,vectorlen,sizeof(redisSortObject),sortCompare);
    }
}
```

# Example 9

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/src/server.c:4872:9*

fnptr: *reply_function*

targets: addReplyCommandInfo, addReplyCommandDocs

## Related Code Snippets

```c
void addReplyCommandSubCommands(client *c, struct redisCommand *cmd, void (*reply_function)(client*, struct redisCommand*), int use_map) {
    if (!cmd->subcommands_dict) {
        addReplySetLen(c, 0);
        return;
    }

    if (use_map)
        addReplyMapLen(c, dictSize(cmd->subcommands_dict));
    else
        addReplyArrayLen(c, dictSize(cmd->subcommands_dict));
    dictEntry *de;
    dictIterator *di = dictGetSafeIterator(cmd->subcommands_dict);
    while((de = dictNext(di)) != NULL) {
        struct redisCommand *sub = (struct redisCommand *)dictGetVal(de);
        if (use_map)
            addReplyBulkCBuffer(c, sub->fullname, sdslen(sub->fullname));
        reply_function(c, sub);
    }
    dictReleaseIterator(di);
}
```

```c
void addReplyCommandInfo(client *c, struct redisCommand *cmd) {
    if (!cmd) {
        addReplyNull(c);
    } else {
        int firstkey = 0, lastkey = 0, keystep = 0;
        if (cmd->legacy_range_key_spec.begin_search_type != KSPEC_BS_INVALID) {
            firstkey = cmd->legacy_range_key_spec.bs.index.pos;
            lastkey = cmd->legacy_range_key_spec.fk.range.lastkey;
            if (lastkey >= 0)
                lastkey += firstkey;
            keystep = cmd->legacy_range_key_spec.fk.range.keystep;
        }

        addReplyArrayLen(c, 10);
        addReplyBulkCBuffer(c, cmd->fullname, sdslen(cmd->fullname));
        addReplyLongLong(c, cmd->arity);
        addReplyFlagsForCommand(c, cmd);
        addReplyLongLong(c, firstkey);
        addReplyLongLong(c, lastkey);
        addReplyLongLong(c, keystep);
        addReplyCommandCategories(c, cmd);
        addReplyCommandTips(c, cmd);
        addReplyCommandKeySpecs(c, cmd);
        addReplyCommandSubCommands(c, cmd, addReplyCommandInfo, 0);
    }
}
```

```c
void addReplyCommandDocs(client *c, struct redisCommand *cmd) {
    /* Count our reply len so we don't have to use deferred reply. */
    long maplen = 1;
    ...
    if (cmd->args) {
        addReplyBulkCString(c, "arguments");
        addReplyCommandArgList(c, cmd->args, cmd->num_args);
    }
    if (cmd->subcommands_dict) {
        addReplyBulkCString(c, "subcommands");
        addReplyCommandSubCommands(c, cmd, addReplyCommandDocs, 1);
    }
}
```

# Example 10

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/module/icp/algs/modes/ccm.c:97:3*

fnptr: *encrypt_block*

targets: aes_encrypt_block

## Related Code Snippets

```c
int ccm_mode_encrypt_contiguous_blocks(ccm_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out, size_t block_size,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
    size_t remainder = length;
	...

	if (length + ctx->ccm_remainder_len < block_size) {
		/* accumulate bytes here and return */
		memcpy((uint8_t *)ctx->ccm_remainder + ctx->ccm_remainder_len,
		    datap,
		    length);
		ctx->ccm_remainder_len += length;
		ctx->ccm_copy_to = datap;
		return (CRYPTO_SUCCESS);
	}

	crypto_init_ptrs(out, &iov_or_mp, &offset);

	mac_buf = (uint8_t *)ctx->ccm_mac_buf;

	do {
		/* Unprocessed data from last call. */
		...

		xor_block(blockp, mac_buf);
		encrypt_block(ctx->ccm_keysched, mac_buf, mac_buf);

		/* ccm_cb is the counter block */
		encrypt_block(ctx->ccm_keysched, (uint8_t *)ctx->ccm_cb,
		    (uint8_t *)ctx->ccm_tmp);

		...
		ctx->ccm_copy_to = NULL;

	} while (remainder > 0);

out:
	return (CRYPTO_SUCCESS);
}
```

```c
int aes_encrypt_contiguous_blocks(void *ctx, char *data, size_t length,
    crypto_data_t *out)
{
	aes_ctx_t *aes_ctx = ctx;
	int rv;

	if (aes_ctx->ac_flags & CTR_MODE) {
		rv = ctr_mode_contiguous_blocks(ctx, data, length, out,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
	} else if (aes_ctx->ac_flags & CCM_MODE) {
		rv = ccm_mode_encrypt_contiguous_blocks(ctx, data, length,
		    out, AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
    }
    ...
}
```

# Example 11

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/module/icp/algs/modes/ccm.c:232:3*

fnptr: *xor_block*

targets: aes_xor_block

## Related Code Snippets

```c
int ccm_encrypt_final(ccm_ctx_t *ctx, crypto_data_t *out, size_t block_size,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	...

	if (ctx->ccm_remainder_len > 0) {

		...

		/* calculate the CBC MAC */
		xor_block(macp, mac_buf);
		encrypt_block(ctx->ccm_keysched, mac_buf, mac_buf);

		/* calculate the counter mode */
		lastp = (uint8_t *)ctx->ccm_tmp;
		encrypt_block(ctx->ccm_keysched, (uint8_t *)ctx->ccm_cb, lastp);

		/* XOR with counter block */
		for (i = 0; i < ctx->ccm_remainder_len; i++) {
			macp[i] ^= lastp[i];
		}
		ctx->ccm_processed_data_len += ctx->ccm_remainder_len;
	}
}
```

```c
static int
aes_encrypt_atomic(crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *plaintext, crypto_data_t *ciphertext,
    crypto_spi_ctx_template_t template)
{
	...

	if (ret == CRYPTO_SUCCESS) {
		if (mechanism->cm_type == AES_CCM_MECH_INFO_TYPE) {
			ret = ccm_encrypt_final((ccm_ctx_t *)&aes_ctx,
			    ciphertext, AES_BLOCK_LEN, aes_encrypt_block,
			    aes_xor_block);
        }
    }
    ...
}
```

```c
static int
aes_encrypt_final(crypto_ctx_t *ctx, crypto_data_t *data)
{
	aes_ctx_t *aes_ctx;
	...

	if (aes_ctx->ac_flags & CTR_MODE) {
		...
	} else if (aes_ctx->ac_flags & CCM_MODE) {
		ret = ccm_encrypt_final((ccm_ctx_t *)aes_ctx, data,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
    }
}
```

```c
static int
aes_encrypt(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext)
{
	...
	if (aes_ctx->ac_flags & CCM_MODE) {
		/*
		 * ccm_encrypt_final() will compute the MAC and append
		 * it to existing ciphertext. So, need to adjust the left over
		 * length value accordingly
		 */

		/* order of following 2 lines MUST not be reversed */
		ciphertext->cd_offset = ciphertext->cd_length;
		ciphertext->cd_length = saved_length - ciphertext->cd_length;
		ret = ccm_encrypt_final((ccm_ctx_t *)aes_ctx, ciphertext,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		if (ret != CRYPTO_SUCCESS) {
			return (ret);
		}
    }
}
```

# Example 12

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/curl-build/lib/../../curl-8.5.0/lib/vauth/digest.c:789:3*

fnptr: *hash*

targets: Curl_md5it, Curl_sha256it

## Related Code Snippets

```c
static CURLcode auth_create_digest_http_message(
                  struct Curl_easy *data,
                  const char *userp,
                  const char *passwdp,
                  const unsigned char *request,
                  const unsigned char *uripath,
                  struct digestdata *digest,
                  char **outptr, size_t *outlen,
                  void (*convert_to_ascii)(unsigned char *, unsigned char *),
                  CURLcode (*hash)(unsigned char *, const unsigned char *,
                                   const size_t))
{
  ...
  if(!hashthis)
    return CURLE_OUT_OF_MEMORY;

  hash(hashbuf, (unsigned char *) hashthis, strlen(hashthis));
  ...
}
```

```c
CURLcode Curl_auth_create_digest_http_message(struct Curl_easy *data,
                                              const char *userp,
                                              const char *passwdp,
                                              const unsigned char *request,
                                              const unsigned char *uripath,
                                              struct digestdata *digest,
                                              char **outptr, size_t *outlen)
{
  if(digest->algo <= ALGO_MD5SESS)
    return auth_create_digest_http_message(data, userp, passwdp,
                                           request, uripath, digest,
                                           outptr, outlen,
                                           auth_digest_md5_to_ascii,
                                           Curl_md5it);
  DEBUGASSERT(digest->algo <= ALGO_SHA512_256SESS);
  return auth_create_digest_http_message(data, userp, passwdp,
                                         request, uripath, digest,
                                         outptr, outlen,
                                         auth_digest_sha256_to_ascii,
                                         Curl_sha256it);
}
```

# Example 13

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/gcc-clang-build/gcc/../../gcc-13.2.0/gcc/gimple-fold.cc:7670:17*

fnptr: *valueize*

targets: pta_valueize, threadedge_valueize, vn_valueize, dom_valueize, valueize_val, valueize_op, do_valueize

## Related Code Snippets

```c
tree
gimple_fold_stmt_to_constant_1 (gimple *stmt, tree (*valueize) (tree),
				tree (*gvalueize) (tree))
{
  gimple_match_op res_op;
  ...
	if (gimple_call_internal_p (stmt))
	  {
	    tree arg0 = gimple_call_arg (stmt, 0);
	    tree arg1 = gimple_call_arg (stmt, 1);
	    tree op0 = (*valueize) (arg0);
	    tree op1 = (*valueize) (arg1);
      }
   ...
}
```

```c
tree
gimple_fold_stmt_to_constant (gimple *stmt, tree (*valueize) (tree))
{
  tree res = gimple_fold_stmt_to_constant_1 (stmt, valueize);
  if (res && is_gimple_min_invariant (res))
    return res;
  return NULL_TREE;
}
```

```c
static unsigned int
object_sizes_execute (function *fun, bool early)
{
    basic_block bb;
    ...

    result = gimple_fold_stmt_to_constant (call, do_valueize);
    ...
}
```

```c
static tree
ccp_fold (gimple *stmt)
{
  switch (gimple_code (stmt))
    {
    case GIMPLE_SWITCH:
      {
	/* Return the constant switch index.  */
        return valueize_op (gimple_switch_index (as_a <gswitch *> (stmt)));
      }

    case GIMPLE_COND:
    case GIMPLE_ASSIGN:
    case GIMPLE_CALL:
      return gimple_fold_stmt_to_constant_1 (stmt,
					     valueize_op, valueize_op_1);

    default:
      gcc_unreachable ();
    }
}
```

```c
static enum ssa_prop_result
copy_prop_visit_assignment (gimple *stmt, tree *result_p)
{
  tree lhs = gimple_assign_lhs (stmt);
  tree rhs = gimple_fold_stmt_to_constant_1 (stmt, valueize_val);
  if (rhs
      && (TREE_CODE (rhs) == SSA_NAME
	  || is_gimple_min_invariant (rhs)))
    {
      if (!may_propagate_copy (lhs, rhs))
	rhs = lhs;
    }
  else
    rhs = lhs;
}
```

```c
static void
back_propagate_equivalences (tree lhs, edge e,
			     class const_and_copies *const_and_copies,
			     bitmap domby)
{
  ...

        tree res = gimple_fold_stmt_to_constant_1 (use_stmt, dom_valueize,
                            no_follow_ssa_edges);
        if (res && (TREE_CODE (res) == SSA_NAME || is_gimple_min_invariant (res)))
    record_equality (lhs2, res, const_and_copies);
  ...
}
```

```c
static tree
try_to_simplify (gassign *stmt)
{
  enum tree_code code = gimple_assign_rhs_code (stmt);
  tree tem;

  /* For stores we can end up simplifying a SSA_NAME rhs.  Just return
     in this case, there is no point in doing extra work.  */
  if (code == SSA_NAME)
    return NULL_TREE;

  /* First try constant folding based on our current lattice.  */
  mprts_hook = vn_lookup_simplify_result;
  tem = gimple_fold_stmt_to_constant_1 (stmt, vn_valueize, vn_valueize);
  mprts_hook = NULL;
  if (tem
      && (TREE_CODE (tem) == SSA_NAME
	  || is_gimple_min_invariant (tem)))
    return tem;

  return NULL_TREE;
}
```

```c
static bool
visit_stmt (gimple *stmt, bool backedges_varying_p = false)
{
  bool changed = false;
  ...
  	  tree simplified = gimple_fold_stmt_to_constant_1 (call_stmt,
							    vn_valueize);
	  if (simplified)
	    {
	      if (dump_file && (dump_flags & TDF_DETAILS))
		{
		  fprintf (dump_file, "call ");
		  print_gimple_expr (dump_file, call_stmt, 0);
		  fprintf (dump_file, " simplified to ");
		  print_generic_expr (dump_file, simplified);
		  fprintf (dump_file, "\n");
		}
	    }
  ...
}
```

```c
void
jt_state::register_equivs_stmt (gimple *stmt, basic_block bb,
				jt_simplifier *simplifier)
{
     tree cached_lhs = NULL;
     ...
  if (gimple_assign_single_p (stmt)
      && TREE_CODE (gimple_assign_rhs1 (stmt)) == SSA_NAME)
    cached_lhs = gimple_assign_rhs1 (stmt);
  else
    {
        ...
      cached_lhs = gimple_fold_stmt_to_constant_1 (stmt, threadedge_valueize);
    }
    ...
}
```

```c
void
pointer_equiv_analyzer::visit_stmt (gimple *stmt)
{
  if (gimple_code (stmt) != GIMPLE_ASSIGN)
    return;

  tree lhs = gimple_assign_lhs (stmt);
  if (!supported_pointer_equiv_p (lhs))
    return;

  tree rhs = gimple_assign_rhs1 (stmt);
  rhs = get_equiv_expr (gimple_assign_rhs_code (stmt), rhs);
  if (rhs)
    {
      set_global_equiv (lhs, rhs);
      return;
    }

  // If we couldn't find anything, try fold.
  x_fold_context = { stmt, m_ranger, this};
  rhs = gimple_fold_stmt_to_constant_1 (stmt, pta_valueize, pta_valueize);
  if (rhs)
    {
      rhs = get_equiv_expr (TREE_CODE (rhs), rhs);
      if (rhs)
	{
	  set_global_equiv (lhs, rhs);
	  return;
	}
    }
}
```

# Example 14

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/gcc-clang-build/gcc/./gtype-lto.h:1256:13*

fnptr: *op*

targets: relocate_ptrs

## Related Code Snippets

```c
void
gt_pch_p_14lang_tree_node (ATTRIBUTE_UNUSED void *this_obj,
	void *x_p,
	ATTRIBUTE_UNUSED gt_pointer_operator op,
	ATTRIBUTE_UNUSED void *cookie)
{
  union lang_tree_node * x ATTRIBUTE_UNUSED = (union lang_tree_node *)x_p;
  switch ((int) (lto_tree_node_structure (&((*x)))))
    {
    case TS_LTO_GENERIC:
      switch ((int) (tree_node_structure (&((*x).generic))))
        {
        case TS_BASE:
          break;
        case TS_TYPED:
          if ((void *)(x) == this_obj)
            op (&((*x).generic.typed.type), NULL, cookie);
          break;
        }
    }
}
```

```c
void
gt_pch_nx_lang_tree_node (void *x_p)
{
  union lang_tree_node * x = (union lang_tree_node *)x_p;
  union lang_tree_node * xlimit = x;
  while (gt_pch_note_object (xlimit, xlimit, gt_pch_p_14lang_tree_node))
   xlimit = (CODE_CONTAINS_STRUCT (TREE_CODE (&(*xlimit).generic), TS_TYPE_COMMON) ? ((union lang_tree_node *) (*xlimit).generic.type_common.next_variant) : CODE_CONTAINS_STRUCT (TREE_CODE (&(*xlimit).generic), TS_COMMON) ? ((union lang_tree_node *) (*xlimit).generic.common.chain) : NULL);
}
```

```c
int
gt_pch_note_object (void *obj, void *note_ptr_cookie,
		    gt_note_pointers note_ptr_fn,
		    size_t length_override)
{
  struct ptr_data **slot;

  if (obj == NULL || obj == (void *) 1)
    return 0;

  slot = (struct ptr_data **)
    saving_htab->find_slot_with_hash (obj, POINTER_HASH (obj), INSERT);
  if (*slot != NULL)
    {
      gcc_assert ((*slot)->note_ptr_fn == note_ptr_fn
		  && (*slot)->note_ptr_cookie == note_ptr_cookie);
      return 0;
    }

  *slot = XCNEW (struct ptr_data);
  (*slot)->obj = obj;
  (*slot)->note_ptr_fn = note_ptr_fn;
  (*slot)->note_ptr_cookie = note_ptr_cookie;
  if (length_override != (size_t)-1)
    (*slot)->size = length_override;
  else if (note_ptr_fn == gt_pch_p_S)
    (*slot)->size = strlen ((const char *)obj) + 1;
  else
    (*slot)->size = ggc_get_size (obj);
  return 1;
}
```

```c
void
gt_pch_save (FILE *f)
{
    state.ptrs[i]->note_ptr_fn (state.ptrs[i]->obj,
                state.ptrs[i]->note_ptr_cookie,
                relocate_ptrs, &state);
}
```

```c
static void
relocate_ptrs (void *ptr_p, void *real_ptr_p, void *state_p)
{
  void **ptr = (void **)ptr_p;
  struct traversal_state *state
    = (struct traversal_state *)state_p;
  struct ptr_data *result;

  if (*ptr == NULL || *ptr == (void *)1)
    return;

  result = (struct ptr_data *)
    saving_htab->find_with_hash (*ptr, POINTER_HASH (*ptr));
  gcc_assert (result);
  *ptr = result->new_addr;
  if (ptr_p == real_ptr_p)
    return;
  if (real_ptr_p == NULL)
    real_ptr_p = ptr_p;
  gcc_assert (real_ptr_p >= state->ptrs[state->ptrs_i]->obj
	      && ((char *) real_ptr_p + sizeof (void *)
		  <= ((char *) state->ptrs[state->ptrs_i]->obj
		      + state->ptrs[state->ptrs_i]->size)));
  void *addr
    = (void *) ((char *) state->ptrs[state->ptrs_i]->new_addr
		+ ((char *) real_ptr_p
		   - (char *) state->ptrs[state->ptrs_i]->obj));
  reloc_addrs_vec.safe_push (addr);
}
```

# Example 15

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/openssh-build/../openssh-9.6p1/atomicio.c:71:23*

fnptr: *cb*

targets: scpio, sftpio

## Related Code Snippets

```c
size_t
atomicio6(ssize_t (*f) (int, void *, size_t), int fd, void *_s, size_t n,
    int (*cb)(void *, size_t), void *cb_arg)
{
	char *s = _s;
	size_t pos = 0;
	ssize_t res;
	struct pollfd pfd;

	pfd.fd = fd;
#ifndef BROKEN_READ_COMPARISON
	pfd.events = f == read ? POLLIN : POLLOUT;
#else
	pfd.events = POLLIN|POLLOUT;
#endif
	while (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		switch (res) {
		case -1:
			if (errno == EINTR) {
				/* possible SIGALARM, update callback */
				if (cb != NULL && cb(cb_arg, 0) == -1) {
					errno = EINTR;
					return pos;
				}
				continue;
			} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				(void)poll(&pfd, 1, -1);
				continue;
			}
			return 0;
		case 0:
			errno = EPIPE;
			return pos;
		default:
			pos += (size_t)res;
			if (cb != NULL && cb(cb_arg, (size_t)res) == -1) {
				errno = EINTR;
				return pos;
			}
		}
	}
	return pos;
}
```

```c
void
source(int argc, char **argv)
{
  if (atomicio6(vwrite, remout, bp->buf, amt, scpio,
      &statbytes) != amt)
    haderr = errno;
}
```

```c
static int
scpio(void *_cnt, size_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	if (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	return 0;
}
```

```c
static void
get_msg_extended(struct sftp_conn *conn, struct sshbuf *m, int initial)
{
	u_int msg_len;
	u_char *p;
	int r;

	sshbuf_reset(m);
	if ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	if (atomicio6(read, conn->fd_in, p, 4, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : NULL) != 4) {
		if (errno == EPIPE || errno == ECONNRESET)
			fatal("Connection closed");
		else
			fatal("Couldn't read packet: %s", strerror(errno));
	}

	if ((r = sshbuf_get_u32(m, &msg_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	if (msg_len > SFTP_MAX_MSG_LENGTH) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", msg_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	if ((r = sshbuf_reserve(m, msg_len, &p)) != 0)
		fatal_fr(r, "reserve");
	if (atomicio6(read, conn->fd_in, p, msg_len, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : NULL)
	    != msg_len) {
		if (errno == EPIPE)
			fatal("Connection closed");
		else
			fatal("Read packet: %s", strerror(errno));
	}
}
```

```c
static int
sftpio(void *_bwlimit, size_t amount)
{
	struct bwlimit *bwlimit = (struct bwlimit *)_bwlimit;

	refresh_progress_meter(0);
	if (bwlimit != NULL)
		bandwidth_limit(bwlimit, amount);
	return 0;
}
```