# Example 1

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/src/cluster.c:498:21*

fnptr: *auxFieldHandlers[j].setter*

targets: auxShardIdSetter, auxHumanNodenameSetter, auxTcpPortSetter, auxTlsPortSetter

## Related Code Snippets

```c
auxFieldHandler auxFieldHandlers[] = {
    {"shard-id", auxShardIdSetter, auxShardIdGetter, auxShardIdPresent},
    {"nodename", auxHumanNodenameSetter, auxHumanNodenameGetter, auxHumanNodenamePresent},
    {"tcp-port", auxTcpPortSetter, auxTcpPortGetter, auxTcpPortPresent},
    {"tls-port", auxTlsPortSetter, auxTlsPortGetter, auxTlsPortPresent},
};
```

```c
for (unsigned j = 0; j < numElements(auxFieldHandlers); j++) {
    if (sdslen(field_argv[0]) != strlen(auxFieldHandlers[j].field) ||
        memcmp(field_argv[0], auxFieldHandlers[j].field, sdslen(field_argv[0])) != 0) {
        continue;
    }
    field_found = 1;
    aux_tcp_port |= j == af_tcp_port;
    aux_tls_port |= j == af_tls_port;
    if (auxFieldHandlers[j].setter(n, field_argv[1], sdslen(field_argv[1])) != C_OK) {
        /* Invalid aux field format */
        sdsfreesplitres(field_argv, field_argc);
        sdsfreesplitres(argv,argc);
        goto fmterr;
    }
}
```

# Example 2

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/curl-build/lib/../../curl-8.5.0/lib/version.c:665:23*

fnptr: *p->present*

targets: https_proxy_present

## Related Code Snippets

```c
curl_version_info_data *curl_version_info(CURLversion stamp)
{
  size_t n;
  const struct feat *p;
  int features = 0;
  ...
  n = 0;
  for(p = features_table; p->name; p++)
    if(!p->present || p->present(&version_info)) {
      features |= p->bitmask;
      feature_names[n++] = p->name;
    }

  feature_names[n] = NULL;  /* Terminate array. */
  version_info.features = features;

  return &version_info;
}
```

```c
#define FEATURE(name, present, bitmask) {(name), (present), (bitmask)}

struct feat {
  const char *name;
  int        (*present)(curl_version_info_data *info);
  int        bitmask;
};

static const struct feat features_table[] = {
#ifndef CURL_DISABLE_ALTSVC
  FEATURE("alt-svc",     NULL,                CURL_VERSION_ALTSVC),
#endif
...
#if defined(USE_SSL) && !defined(CURL_DISABLE_PROXY) && \
  !defined(CURL_DISABLE_HTTP)
  FEATURE("HTTPS-proxy", https_proxy_present, CURL_VERSION_HTTPS_PROXY),
#endif
...
}
```

# Example 3

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/curl-build/src/../../curl-8.5.0/src/tool_writeout_json.c:112:8*

fnptr: *mappings[i].writefunc*

targets: writeLong, writeOffset, writeString, writeTime

## Related Code Snippets

```c
void ourWriteOutJSON(FILE *stream, const struct writeoutvar mappings[],
                     struct per_transfer *per, CURLcode per_result)
{
  int i;

  fputs("{", stream);

  for(i = 0; mappings[i].name != NULL; i++) {
    if(mappings[i].writefunc &&
       mappings[i].writefunc(stream, &mappings[i], per, per_result, true))
      fputs(",", stream);
  }

  /* The variables are sorted in alphabetical order but as a special case
     curl_version (which is not actually a --write-out variable) is last. */
  fprintf(stream, "\"curl_version\":");
  jsonWriteString(stream, curl_version(), FALSE);
  fprintf(stream, "}");
}
```

```c
void ourWriteOut(struct OperationConfig *config, struct per_transfer *per,
                 CURLcode per_result)
{
  FILE *stream = stdout;
  const char *writeinfo = config->writeout;
  const char *ptr = writeinfo;
  bool done = FALSE;
  struct curl_certinfo *certinfo;
  CURLcode res = curl_easy_getinfo(per->curl, CURLINFO_CERTINFO, &certinfo);
  bool fclose_stream = FALSE;
  ...
       case VAR_JSON:
         ourWriteOutJSON(stream, variables, per, per_result);
         break;
  ...
}
```

```c
static const struct writeoutvar variables[] = {
{"certs", VAR_CERT, CURLINFO_NONE, writeString},
 ...
  {"onerror", VAR_ONERROR, CURLINFO_NONE, NULL},
  {"proxy_ssl_verify_result", VAR_PROXY_SSL_VERIFY_RESULT,
   CURLINFO_PROXY_SSL_VERIFYRESULT, writeLong},
  ...
  {"scheme", VAR_SCHEME, CURLINFO_SCHEME, writeString},
  {"size_download", VAR_SIZE_DOWNLOAD, CURLINFO_SIZE_DOWNLOAD_T, writeOffset},
  ...
  {"time_connect", VAR_CONNECT_TIME, CURLINFO_CONNECT_TIME_T, writeTime},
  {"time_namelookup", VAR_NAMELOOKUP_TIME, CURLINFO_NAMELOOKUP_TIME_T,
   writeTime},
  {"time_total", VAR_TOTAL_TIME, CURLINFO_TOTAL_TIME_T, writeTime},
  {"url", VAR_INPUT_URL, CURLINFO_NONE, writeString},
  {"url.scheme", VAR_INPUT_URLSCHEME, CURLINFO_NONE, writeString},
  {"url.user", VAR_INPUT_URLUSER, CURLINFO_NONE, writeString},
  {"url.password", VAR_INPUT_URLPASSWORD, CURLINFO_NONE, writeString},
  ...
};
```

# Example 4

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/cmd/zstream/zstream_recompress.c:274:14*

fnptr: *ci_decompress*

targets: lzjb_decompress, gzip_decompress, zle_decompress, lz4_decompress_zfs, zfs_zstd_decompress

## Related Code Snippets

```c
int zstream_do_recompress(int argc, char *argv[])
{
	int bufsz = SPA_MAXBLOCKSIZE;
	char *buf = safe_malloc(bufsz);
	dmu_replay_record_t thedrr;
	dmu_replay_record_t *drr = &thedrr;
	zio_cksum_t stream_cksum;
	int c;
	int level = -1;
    ...
                    (void) sfread(cbuf, payload_size, stdin);
                    if (dinfo->ci_decompress != NULL) {
	                  if (0 != dinfo->ci_decompress(cbuf, dbuf,
				        payload_size, MIN(bufsz,
				        drrw->drr_logical_size), dinfo->ci_level))
    ...
                    }
}
```

```c
/*
 * Compression vectors.
 */
zio_compress_info_t zio_compress_table[ZIO_COMPRESS_FUNCTIONS] = {
	{"inherit",	0,	NULL,		NULL, NULL},
	{"on",		0,	NULL,		NULL, NULL},
	{"uncompressed", 0,	NULL,		NULL, NULL},
	{"lzjb",	0,	lzjb_compress,	lzjb_decompress, NULL},
	{"empty",	0,	NULL,		NULL, NULL},
	{"gzip-1",	1,	gzip_compress,	gzip_decompress, NULL},
	{"gzip-2",	2,	gzip_compress,	gzip_decompress, NULL},
	{"gzip-3",	3,	gzip_compress,	gzip_decompress, NULL},
	{"gzip-4",	4,	gzip_compress,	gzip_decompress, NULL},
	{"gzip-5",	5,	gzip_compress,	gzip_decompress, NULL},
	{"gzip-6",	6,	gzip_compress,	gzip_decompress, NULL},
	{"gzip-7",	7,	gzip_compress,	gzip_decompress, NULL},
	{"gzip-8",	8,	gzip_compress,	gzip_decompress, NULL},
	{"gzip-9",	9,	gzip_compress,	gzip_decompress, NULL},
	{"zle",		64,	zle_compress,	zle_decompress, NULL},
	{"lz4",		0,	lz4_compress_zfs, lz4_decompress_zfs, NULL},
	{"zstd",	ZIO_ZSTD_LEVEL_DEFAULT,	zfs_zstd_compress_wrap,
	    zfs_zstd_decompress, zfs_zstd_decompress_level},
};
```

```c
typedef const struct zio_compress_info {
	const char			*ci_name;
	int				ci_level;
	zio_compress_func_t		*ci_compress;
	zio_decompress_func_t		*ci_decompress;
	zio_decompresslevel_func_t	*ci_decompress_level;
} zio_compress_info_t;
```

# Example 5

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/lib/libshare/libshare.c:96:2*

fnptr: *fstypes[protocol]->commit_shares*

targets: nfs_commit_shares, smb_update_shares

## Related Code Snippets

```c
void sa_commit_shares(enum sa_protocol protocol)
{
	/* CSTYLED */
	VALIDATE_PROTOCOL(protocol, );

	fstypes[protocol]->commit_shares();
}
```

```c
static const sa_fstype_t *fstypes[SA_PROTOCOL_COUNT] =
	{&libshare_nfs_type, &libshare_smb_type};

```

```c
const sa_fstype_t libshare_nfs_type = {
        .enable_share = nfs_enable_share,
	.disable_share = nfs_disable_share,
	.is_shared = nfs_is_shared,

	.validate_shareopts = nfs_validate_shareopts,
	.commit_shares = nfs_commit_shares,
	.truncate_shares = nfs_truncate_shares,
};

const sa_fstype_t libshare_smb_type = {
	.enable_share = smb_enable_share,
	.disable_share = smb_disable_share,
	.is_shared = smb_is_share_active,

	.validate_shareopts = smb_validate_shareopts,
	.commit_shares = smb_update_shares,
};
```


# Example 6

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/cmd/zfs/zfs_main.c:8850:9*

fnptr: *command_table[i].func*

targets: zfs_do_version, zfs_do_create, zfs_do_destroy, zfs_do_snapshot, zfs_do_rollback, zfs_do_clone, zfs_do_promote, zfs_do_rename, zfs_do_bookmark, zfs_do_channel_program, zfs_do_list, zfs_do_set, zfs_do_get, zfs_do_inherit, zfs_do_upgrade, zfs_do_userspace, zfs_do_project, zfs_do_mount, zfs_do_unmount, zfs_do_share, zfs_do_unshare, zfs_do_send, zfs_do_receive, zfs_do_allow, zfs_do_receive, zfs_do_allow, zfs_do_unallow, zfs_do_hold, zfs_do_holds, zfs_do_release, zfs_do_diff, zfs_do_load_key, zfs_do_unload_key, zfs_do_change_key, zfs_do_redact, zfs_do_wait, zfs_do_zone, zfs_do_unzone

## Related Code Snippets

```c
int
main(int argc, char **argv)
{
	...
	libzfs_mnttab_cache(g_zfs, B_TRUE);
	if (find_command_idx(cmdname, &i) == 0) {
		current_command = &command_table[i];
		ret = command_table[i].func(argc - 1, newargv + 1);
  }
}
```

```c
static zfs_command_t command_table[] = {
	{ "version",	zfs_do_version, 	HELP_VERSION		},
	{ NULL },
	{ "create",	zfs_do_create,		HELP_CREATE		},
	{ "destroy",	zfs_do_destroy,		HELP_DESTROY		},
	{ NULL },
	{ "snapshot",	zfs_do_snapshot,	HELP_SNAPSHOT		},
	{ "rollback",	zfs_do_rollback,	HELP_ROLLBACK		},
	{ "clone",	zfs_do_clone,		HELP_CLONE		},
	{ "promote",	zfs_do_promote,		HELP_PROMOTE		},
	{ "rename",	zfs_do_rename,		HELP_RENAME		},
	{ "bookmark",	zfs_do_bookmark,	HELP_BOOKMARK		},
	{ "program",    zfs_do_channel_program, HELP_CHANNEL_PROGRAM    },
	{ NULL },
	{ "list",	zfs_do_list,		HELP_LIST		},
	{ NULL },
	{ "set",	zfs_do_set,		HELP_SET		},
	{ "get",	zfs_do_get,		HELP_GET		},
	{ "inherit",	zfs_do_inherit,		HELP_INHERIT		},
	{ "upgrade",	zfs_do_upgrade,		HELP_UPGRADE		},
	{ NULL },
	{ "userspace",	zfs_do_userspace,	HELP_USERSPACE		},
	{ "groupspace",	zfs_do_userspace,	HELP_GROUPSPACE		},
	{ "projectspace", zfs_do_userspace,	HELP_PROJECTSPACE	},
	{ NULL },
	{ "project",	zfs_do_project,		HELP_PROJECT		},
	{ NULL },
	{ "mount",	zfs_do_mount,		HELP_MOUNT		},
	{ "unmount",	zfs_do_unmount,		HELP_UNMOUNT		},
	{ "share",	zfs_do_share,		HELP_SHARE		},
	{ "unshare",	zfs_do_unshare,		HELP_UNSHARE		},
	{ NULL },
	{ "send",	zfs_do_send,		HELP_SEND		},
	{ "receive",	zfs_do_receive,		HELP_RECEIVE		},
	{ NULL },
	{ "allow",	zfs_do_allow,		HELP_ALLOW		},
	{ NULL },
	{ "unallow",	zfs_do_unallow,		HELP_UNALLOW		},
	{ NULL },
	{ "hold",	zfs_do_hold,		HELP_HOLD		},
	{ "holds",	zfs_do_holds,		HELP_HOLDS		},
	{ "release",	zfs_do_release,		HELP_RELEASE		},
	{ "diff",	zfs_do_diff,		HELP_DIFF		},
	{ "load-key",	zfs_do_load_key,	HELP_LOAD_KEY		},
	{ "unload-key",	zfs_do_unload_key,	HELP_UNLOAD_KEY		},
	{ "change-key",	zfs_do_change_key,	HELP_CHANGE_KEY		},
	{ "redact",	zfs_do_redact,		HELP_REDACT		},
	{ "wait",	zfs_do_wait,		HELP_WAIT		},

#ifdef __FreeBSD__
	{ "jail",	zfs_do_jail,		HELP_JAIL		},
	{ "unjail",	zfs_do_unjail,		HELP_UNJAIL		},
#endif

#ifdef __linux__
	{ "zone",	zfs_do_zone,		HELP_ZONE		},
	{ "unzone",	zfs_do_unzone,		HELP_UNZONE		},
#endif
};
```

# Example 7

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/module/icp/algs/sha2/sha2_generic.c:237:3*

fnptr: *ops->transform*

targets: sha256_generic, sha512_generic, tf_sha512_transform_x64, tf_sha256_transform_x64

## Related Code Snippets

```c
static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
	uint64_t pos = ctx->count[0];
	uint64_t total = ctx->count[1];
	uint8_t *m = ctx->wbuf;
	const sha256_ops_t *ops = ctx->ops;

	if (pos && pos + len >= 64) {
		memcpy(m + pos, data, 64 - pos);
		ops->transform(ctx->state, m, 1);
		len -= 64 - pos;
		total += (64 - pos) * 8;
		data += 64 - pos;
		pos = 0;
	}

	if (len >= 64) {
		uint32_t blocks = len / 64;
		uint32_t bytes = blocks * 64;
		ops->transform(ctx->state, data, blocks);
		len -= bytes;
		total += (bytes) * 8;
		data += bytes;
	}
	memcpy(m + pos, data, len);

	pos += len;
	total += len * 8;
	ctx->count[0] = pos;
	ctx->count[1] = total;
}
```

```c
void
SHA2Update(SHA2_CTX *ctx, const void *data, size_t len)
{
	/* check for zero input length */
	if (len == 0)
		return;

	ASSERT3P(data, !=, NULL);

	switch (ctx->algotype) {
		case SHA256_MECH_INFO_TYPE:
		case SHA256_HMAC_MECH_INFO_TYPE:
		case SHA256_HMAC_GEN_MECH_INFO_TYPE:
			sha256_update(&ctx->sha256, data, len);
			break;
		case SHA384_MECH_INFO_TYPE:
		case SHA384_HMAC_MECH_INFO_TYPE:
		case SHA384_HMAC_GEN_MECH_INFO_TYPE:
			sha512_update(&ctx->sha512, data, len);
			break;
		case SHA512_MECH_INFO_TYPE:
		case SHA512_HMAC_MECH_INFO_TYPE:
		case SHA512_HMAC_GEN_MECH_INFO_TYPE:
			sha512_update(&ctx->sha512, data, len);
			break;
		case SHA512_224_MECH_INFO_TYPE:
			sha512_update(&ctx->sha512, data, len);
			break;
		case SHA512_256_MECH_INFO_TYPE:
			sha512_update(&ctx->sha512, data, len);
			break;
	}
}
```

```c
static void
sha2_mac_init_ctx(sha2_hmac_ctx_t *ctx, void *keyval, uint_t length_in_bytes)
{
	uint64_t ipad[SHA512_HMAC_BLOCK_SIZE / sizeof (uint64_t)] = {0};
	uint64_t opad[SHA512_HMAC_BLOCK_SIZE / sizeof (uint64_t)] = {0};
	int i, block_size, blocks_per_int64;

	/* Determine the block size */
	if (ctx->hc_mech_type <= SHA256_HMAC_GEN_MECH_INFO_TYPE) {
		block_size = SHA256_HMAC_BLOCK_SIZE;
		blocks_per_int64 = SHA256_HMAC_BLOCK_SIZE / sizeof (uint64_t);
	} else {
		block_size = SHA512_HMAC_BLOCK_SIZE;
		blocks_per_int64 = SHA512_HMAC_BLOCK_SIZE / sizeof (uint64_t);
	}

	(void) memset(ipad, 0, block_size);
	(void) memset(opad, 0, block_size);

	if (keyval != NULL) {
		(void) memcpy(ipad, keyval, length_in_bytes);
		(void) memcpy(opad, keyval, length_in_bytes);
	} else {
		ASSERT0(length_in_bytes);
	}

	/* XOR key with ipad (0x36) and opad (0x5c) */
	for (i = 0; i < blocks_per_int64; i ++) {
		ipad[i] ^= 0x3636363636363636;
		opad[i] ^= 0x5c5c5c5c5c5c5c5c;
	}

	/* perform SHA2 on ipad */
	SHA2Init(ctx->hc_mech_type, &ctx->hc_icontext);
	SHA2Update(&ctx->hc_icontext, (uint8_t *)ipad, block_size);

	/* perform SHA2 on opad */
	SHA2Init(ctx->hc_mech_type, &ctx->hc_ocontext);
	SHA2Update(&ctx->hc_ocontext, (uint8_t *)opad, block_size);
}
```

```c
void
SHA2Init(int algotype, SHA2_CTX *ctx)
{
	sha256_ctx *ctx256 = &ctx->sha256;
	sha512_ctx *ctx512 = &ctx->sha512;

	ASSERT3S(algotype, >=, SHA256_MECH_INFO_TYPE);
	ASSERT3S(algotype, <=, SHA512_256_MECH_INFO_TYPE);

	memset(ctx, 0, sizeof (*ctx));
	ctx->algotype = algotype;
	switch (ctx->algotype) {
		case SHA256_MECH_INFO_TYPE:
		case SHA256_HMAC_MECH_INFO_TYPE:
		case SHA256_HMAC_GEN_MECH_INFO_TYPE:
			ctx256->state[0] = 0x6a09e667;
			ctx256->state[1] = 0xbb67ae85;
			ctx256->state[2] = 0x3c6ef372;
			ctx256->state[3] = 0xa54ff53a;
			ctx256->state[4] = 0x510e527f;
			ctx256->state[5] = 0x9b05688c;
			ctx256->state[6] = 0x1f83d9ab;
			ctx256->state[7] = 0x5be0cd19;
			ctx256->count[0] = 0;
			ctx256->ops = sha256_get_ops();
			break;
		case SHA384_MECH_INFO_TYPE:
		case SHA384_HMAC_MECH_INFO_TYPE:
		case SHA384_HMAC_GEN_MECH_INFO_TYPE:
			ctx512->state[0] = 0xcbbb9d5dc1059ed8ULL;
			ctx512->state[1] = 0x629a292a367cd507ULL;
			ctx512->state[2] = 0x9159015a3070dd17ULL;
			ctx512->state[3] = 0x152fecd8f70e5939ULL;
			ctx512->state[4] = 0x67332667ffc00b31ULL;
			ctx512->state[5] = 0x8eb44a8768581511ULL;
			ctx512->state[6] = 0xdb0c2e0d64f98fa7ULL;
			ctx512->state[7] = 0x47b5481dbefa4fa4ULL;
			ctx512->count[0] = 0;
			ctx512->count[1] = 0;
			ctx512->ops = sha512_get_ops();
			break;
		case SHA512_MECH_INFO_TYPE:
		case SHA512_HMAC_MECH_INFO_TYPE:
		case SHA512_HMAC_GEN_MECH_INFO_TYPE:
			ctx512->state[0] = 0x6a09e667f3bcc908ULL;
			ctx512->state[1] = 0xbb67ae8584caa73bULL;
			ctx512->state[2] = 0x3c6ef372fe94f82bULL;
			ctx512->state[3] = 0xa54ff53a5f1d36f1ULL;
			ctx512->state[4] = 0x510e527fade682d1ULL;
			ctx512->state[5] = 0x9b05688c2b3e6c1fULL;
			ctx512->state[6] = 0x1f83d9abfb41bd6bULL;
			ctx512->state[7] = 0x5be0cd19137e2179ULL;
			ctx512->count[0] = 0;
			ctx512->count[1] = 0;
			ctx512->ops = sha512_get_ops();
			break;
		case SHA512_224_MECH_INFO_TYPE:
			ctx512->state[0] = 0x8c3d37c819544da2ULL;
			ctx512->state[1] = 0x73e1996689dcd4d6ULL;
			ctx512->state[2] = 0x1dfab7ae32ff9c82ULL;
			ctx512->state[3] = 0x679dd514582f9fcfULL;
			ctx512->state[4] = 0x0f6d2b697bd44da8ULL;
			ctx512->state[5] = 0x77e36f7304c48942ULL;
			ctx512->state[6] = 0x3f9d85a86a1d36c8ULL;
			ctx512->state[7] = 0x1112e6ad91d692a1ULL;
			ctx512->count[0] = 0;
			ctx512->count[1] = 0;
			ctx512->ops = sha512_get_ops();
			break;
		case SHA512_256_MECH_INFO_TYPE:
			ctx512->state[0] = 0x22312194fc2bf72cULL;
			ctx512->state[1] = 0x9f555fa3c84c64c2ULL;
			ctx512->state[2] = 0x2393b86b6f53b151ULL;
			ctx512->state[3] = 0x963877195940eabdULL;
			ctx512->state[4] = 0x96283ee2a88effe3ULL;
			ctx512->state[5] = 0xbe5e1e2553863992ULL;
			ctx512->state[6] = 0x2b0199fc2c85b8aaULL;
			ctx512->state[7] = 0x0eb72ddc81c52ca2ULL;
			ctx512->count[0] = 0;
			ctx512->count[1] = 0;
			ctx512->ops = sha512_get_ops();
			break;
	}
}
```

```c
#define	IMPL_NAME		"sha256"
#define	IMPL_OPS_T		sha256_ops_t
#define	IMPL_ARRAY		sha256_impls
#define	IMPL_GET_OPS		sha256_get_ops
#define	ZFS_IMPL_OPS		zfs_sha256_ops
```

```c
#define	IMPL_NAME		"sha512"
#define	IMPL_OPS_T		sha512_ops_t
#define	IMPL_ARRAY		sha512_impls
#define	IMPL_GET_OPS		sha512_get_ops
#define	ZFS_IMPL_OPS		zfs_sha512_ops
```

```c
const IMPL_OPS_T *
IMPL_GET_OPS(void)
{
	const IMPL_OPS_T *ops = NULL;
	uint32_t idx, impl = IMPL_READ(generic_impl_chosen);
	static uint32_t cycle_count = 0;

	generic_impl_init();
	switch (impl) {
	case IMPL_FASTEST:
		ops = &generic_fastest_impl;
		break;
	case IMPL_CYCLE:
		idx = (++cycle_count) % generic_supp_impls_cnt;
		ops = generic_supp_impls[idx];
		break;
	default:
		ASSERT3U(impl, <, generic_supp_impls_cnt);
		ops = generic_supp_impls[impl];
		break;
	}

	ASSERT3P(ops, !=, NULL);
	return (ops);
}
```

```c
/* Implementation that contains the fastest method */
static IMPL_OPS_T generic_fastest_impl = {
	.name = "fastest"
};

static void
generic_impl_init(void)
{
	int i, c;

	/* init only once */
	if (likely(generic_supp_impls_cnt != 0))
		return;

	/* Move supported implementations into generic_supp_impls */
	for (i = 0, c = 0; i < ARRAY_SIZE(IMPL_ARRAY); i++) {
		const IMPL_OPS_T *impl = IMPL_ARRAY[i];

		if (impl->is_supported && impl->is_supported())
			generic_supp_impls[c++] = impl;
	}
	generic_supp_impls_cnt = c;

	/* first init generic impl, may be changed via set_fastest() */
	memcpy(&generic_fastest_impl, generic_supp_impls[0],
	    sizeof (generic_fastest_impl));
}

static void
generic_impl_set_fastest(uint32_t id)
{
	generic_impl_init();
	memcpy(&generic_fastest_impl, generic_supp_impls[id],
	    sizeof (generic_fastest_impl));
}
```

```c
static const IMPL_OPS_T *generic_supp_impls[ARRAY_SIZE(IMPL_ARRAY)];

static void
generic_impl_init(void)
{
	int i, c;

	/* init only once */
	if (likely(generic_supp_impls_cnt != 0))
		return;

	/* Move supported implementations into generic_supp_impls */
	for (i = 0, c = 0; i < ARRAY_SIZE(IMPL_ARRAY); i++) {
		const IMPL_OPS_T *impl = IMPL_ARRAY[i];

		if (impl->is_supported && impl->is_supported())
			generic_supp_impls[c++] = impl;
	}
	generic_supp_impls_cnt = c;

	/* first init generic impl, may be changed via set_fastest() */
	memcpy(&generic_fastest_impl, generic_supp_impls[0],
	    sizeof (generic_fastest_impl));
}
```

```c
static const sha256_ops_t *const sha256_impls[] = {
	&sha256_generic_impl,
#if defined(__x86_64)
	&sha256_x64_impl,
#endif
#if defined(__x86_64) && defined(HAVE_SSSE3)
	&sha256_ssse3_impl,
#endif
#if defined(__x86_64) && defined(HAVE_AVX)
	&sha256_avx_impl,
#endif
#if defined(__x86_64) && defined(HAVE_AVX2)
	&sha256_avx2_impl,
#endif
#if defined(__x86_64) && defined(HAVE_SSE4_1)
	&sha256_shani_impl,
#endif
#if defined(__aarch64__) || (defined(__arm__) && __ARM_ARCH > 6)
	&sha256_armv7_impl,
	&sha256_neon_impl,
	&sha256_armv8_impl,
#endif
#if defined(__PPC64__)
	&sha256_ppc_impl,
	&sha256_power8_impl,
#endif /* __PPC64__ */
};
```

```c
const sha256_ops_t sha256_generic_impl = {
	.name = "generic",
	.transform = sha256_generic,
	.is_supported = sha2_is_supported
};

const sha512_ops_t sha512_generic_impl = {
	.name = "generic",
	.transform = sha512_generic,
	.is_supported = sha2_is_supported
};
```

```c
static const sha512_ops_t *const sha512_impls[] = {
	&sha512_generic_impl,
#if defined(__x86_64)
	&sha512_x64_impl,
#endif
#if defined(__x86_64) && defined(HAVE_AVX)
	&sha512_avx_impl,
#endif
#if defined(__x86_64) && defined(HAVE_AVX2)
	&sha512_avx2_impl,
#endif
#if defined(__aarch64__)
	&sha512_armv7_impl,
	&sha512_armv8_impl,
#endif
#if defined(__arm__) && __ARM_ARCH > 6
	&sha512_armv7_impl,
	&sha512_neon_impl,
#endif
#if defined(__PPC64__)
	&sha512_ppc_impl,
	&sha512_power8_impl,
#endif /* __PPC64__ */
};
```

```c
const sha512_ops_t sha512_x64_impl = {
	.is_supported = sha2_is_supported,
	.transform = tf_sha512_transform_x64,
	.name = "x64"
};
```

```c
const sha256_ops_t sha256_x64_impl = {
	.is_supported = sha2_is_supported,
	.transform = tf_sha256_transform_x64,
	.name = "x64"
};
```

# Example 8

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/module/zfs/ddt.c:181:10*

fnptr: *ddt_ops[type]->ddt_op_lookup*

targets: ddt_zap_lookup

## Related Code Snippets

```c
static int
ddt_object_lookup(ddt_t *ddt, enum ddt_type type, enum ddt_class class,
    ddt_entry_t *dde)
{
	if (!ddt_object_exists(ddt, type, class))
		return (SET_ERROR(ENOENT));

	return (ddt_ops[type]->ddt_op_lookup(ddt->ddt_os,
	    ddt->ddt_object[type][class], dde));
}

```

```c
static const ddt_ops_t *const ddt_ops[DDT_TYPES] = {
	&ddt_zap_ops,
};
```

```c
const ddt_ops_t ddt_zap_ops = {
	"zap",
	ddt_zap_create,
	ddt_zap_destroy,
	ddt_zap_lookup,
	ddt_zap_prefetch,
	ddt_zap_update,
	ddt_zap_remove,
	ddt_zap_walk,
	ddt_zap_count,
};
```

```c
typedef struct ddt_ops {
	char ddt_op_name[32];
	int (*ddt_op_create)(objset_t *os, uint64_t *object, dmu_tx_t *tx,
	    boolean_t prehash);
	int (*ddt_op_destroy)(objset_t *os, uint64_t object, dmu_tx_t *tx);
	int (*ddt_op_lookup)(objset_t *os, uint64_t object, ddt_entry_t *dde);
	void (*ddt_op_prefetch)(objset_t *os, uint64_t object,
	    ddt_entry_t *dde);
	int (*ddt_op_update)(objset_t *os, uint64_t object, ddt_entry_t *dde,
	    dmu_tx_t *tx);
	int (*ddt_op_remove)(objset_t *os, uint64_t object, ddt_entry_t *dde,
	    dmu_tx_t *tx);
	int (*ddt_op_walk)(objset_t *os, uint64_t object, ddt_entry_t *dde,
	    uint64_t *walk);
	int (*ddt_op_count)(objset_t *os, uint64_t object, uint64_t *count);
} ddt_ops_t;
```

# Example 9

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/ffmpeg-6.1.1/libavcodec/speexdec.c:1557:15*

fnptr: *speex_modes[s->mode].decode*

targets: nb_decode, sb_decode

## Related Code Snippets

```c
static int speex_decode_frame(AVCodecContext *avctx, AVFrame *frame,
                              int *got_frame_ptr, AVPacket *avpkt)
{
    SpeexContext *s = avctx->priv_data;
    int frames_per_packet = s->frames_per_packet;
    const float scale = 1.f / 32768.f;
    int buf_size = avpkt->size;
    float *dst;
    int ret;

    if (s->pkt_size && avpkt->size == 62)
        buf_size = s->pkt_size;
    if ((ret = init_get_bits8(&s->gb, avpkt->data, buf_size)) < 0)
        return ret;

    frame->nb_samples = FFALIGN(s->frame_size * frames_per_packet, 4);
    if ((ret = ff_get_buffer(avctx, frame, 0)) < 0)
        return ret;

    dst = (float *)frame->extended_data[0];
    for (int i = 0; i < frames_per_packet; i++) {
        ret = speex_modes[s->mode].decode(avctx, &s->st[s->mode], &s->gb, dst + i * s->frame_size);
        if (ret < 0)
            return ret;
        if (avctx->ch_layout.nb_channels == 2)
            speex_decode_stereo(dst + i * s->frame_size, s->frame_size, &s->stereo);
        if (get_bits_left(&s->gb) < 5 ||
            show_bits(&s->gb, 5) == 15) {
            frames_per_packet = i + 1;
            break;
        }
    }

    dst = (float *)frame->extended_data[0];
    s->fdsp->vector_fmul_scalar(dst, dst, scale, frame->nb_samples * frame->ch_layout.nb_channels);
    frame->nb_samples = s->frame_size * frames_per_packet;

    *got_frame_ptr = 1;

    return (get_bits_count(&s->gb) + 7) >> 3;
}
```

```c
static const SpeexMode speex_modes[SPEEX_NB_MODES] = {
    {
        .modeID = 0,
        .decode = nb_decode,
        .frame_size = NB_FRAME_SIZE,
        .subframe_size = NB_SUBFRAME_SIZE,
        .lpc_size = NB_ORDER,
        .submodes = {
            NULL, &nb_submode1, &nb_submode2, &nb_submode3, &nb_submode4,
            &nb_submode5, &nb_submode6, &nb_submode7, &nb_submode8
        },
        .default_submode = 5,
    },
    {
        .modeID = 1,
        .decode = sb_decode,
        .frame_size = NB_FRAME_SIZE,
        .subframe_size = NB_SUBFRAME_SIZE,
        .lpc_size = 8,
        .folding_gain = 0.9f,
        .submodes = {
            NULL, &wb_submode1, &wb_submode2, &wb_submode3, &wb_submode4
        },
        .default_submode = 3,
    },
    {
        .modeID = 2,
        .decode = sb_decode,
        .frame_size = 320,
        .subframe_size = 80,
        .lpc_size = 8,
        .folding_gain = 0.7f,
        .submodes = {
            NULL, &wb_submode1
        },
        .default_submode = 1,
    },
};
```

# Example 10

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/openssh-build/../openssh-9.6p1/sshkey.c:394:10*

fnptr: *impl->funcs->size*

targets: ssh_rsa_size

## Related Code Snippets

```c
u_int
sshkey_size(const struct sshkey *k)
{
	const struct sshkey_impl *impl;

	if ((impl = sshkey_impl_from_key(k)) == NULL)
		return 0;
	if (impl->funcs->size != NULL)
		return impl->funcs->size(k);
	return impl->keybits;
}
```

```c
static const struct sshkey_impl *
sshkey_impl_from_key(const struct sshkey *k)
{
	if (k == NULL)
		return NULL;
	return sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}
```

```c
static const struct sshkey_impl *
sshkey_impl_from_type_nid(int type, int nid)
{
	int i;

	for (i = 0; keyimpls[i] != NULL; i++) {
		if (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			return keyimpls[i];
	}
	return NULL;
}
```

```c
const struct sshkey_impl * const keyimpls[] = {
	&sshkey_ed25519_impl,
	&sshkey_ed25519_cert_impl,
#ifdef ENABLE_SK
	&sshkey_ed25519_sk_impl,
	&sshkey_ed25519_sk_cert_impl,
#endif
#ifdef WITH_OPENSSL
# ifdef OPENSSL_HAS_ECC
	&sshkey_ecdsa_nistp256_impl,
	&sshkey_ecdsa_nistp256_cert_impl,
	&sshkey_ecdsa_nistp384_impl,
	&sshkey_ecdsa_nistp384_cert_impl,
#  ifdef OPENSSL_HAS_NISTP521
	&sshkey_ecdsa_nistp521_impl,
	&sshkey_ecdsa_nistp521_cert_impl,
#  endif /* OPENSSL_HAS_NISTP521 */
#  ifdef ENABLE_SK
	&sshkey_ecdsa_sk_impl,
	&sshkey_ecdsa_sk_cert_impl,
	&sshkey_ecdsa_sk_webauthn_impl,
#  endif /* ENABLE_SK */
# endif /* OPENSSL_HAS_ECC */
	&sshkey_dss_impl,
	&sshkey_dsa_cert_impl,
	&sshkey_rsa_impl,
	&sshkey_rsa_cert_impl,
	&sshkey_rsa_sha256_impl,
	&sshkey_rsa_sha256_cert_impl,
	&sshkey_rsa_sha512_impl,
	&sshkey_rsa_sha512_cert_impl,
#endif /* WITH_OPENSSL */
#ifdef WITH_XMSS
	&sshkey_xmss_impl,
	&sshkey_xmss_cert_impl,
#endif
	NULL
};
```

```c
const struct sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
```

```c
static const struct sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_size,
	/* .alloc = */		ssh_rsa_alloc,
	/* .cleanup = */	ssh_rsa_cleanup,
	/* .equal = */		ssh_rsa_equal,
	/* .ssh_serialize_public = */ ssh_rsa_serialize_public,
	/* .ssh_deserialize_public = */ ssh_rsa_deserialize_public,
	/* .ssh_serialize_private = */ ssh_rsa_serialize_private,
	/* .ssh_deserialize_private = */ ssh_rsa_deserialize_private,
	/* .generate = */	ssh_rsa_generate,
	/* .copy_public = */	ssh_rsa_copy_public,
	/* .sign = */		ssh_rsa_sign,
	/* .verify = */		ssh_rsa_verify,
};
```

# Example 11

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/openssh-build/../openssh-9.6p1/sshkey.c:620:7*

fnptr: *impl->funcs->alloc*

targets: ssh_rsa_alloc

## Related Code Snippets

```c
struct sshkey *
sshkey_new(int type)
{
	struct sshkey *k;
	const struct sshkey_impl *impl = NULL;

	if (type != KEY_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == NULL)
		return NULL;

	/* All non-certificate types may act as CAs */
	if ((k = calloc(1, sizeof(*k))) == NULL)
		return NULL;
	k->type = type;
	k->ecdsa_nid = -1;
	if (impl != NULL && impl->funcs->alloc != NULL) {
		if (impl->funcs->alloc(k) != 0) {
			free(k);
			return NULL;
		}
	}
	if (sshkey_is_cert(k)) {
		if ((k->cert = cert_new()) == NULL) {
			sshkey_free(k);
			return NULL;
		}
	}

	return k;
}
```

```c
static const struct sshkey_impl *
sshkey_impl_from_type(int type)
{
	int i;

	for (i = 0; keyimpls[i] != NULL; i++) {
		if (keyimpls[i]->type == type)
			return keyimpls[i];
	}
	return NULL;
}
```

```c
const struct sshkey_impl * const keyimpls[] = {
	&sshkey_ed25519_impl,
	&sshkey_ed25519_cert_impl,
#ifdef ENABLE_SK
	&sshkey_ed25519_sk_impl,
	&sshkey_ed25519_sk_cert_impl,
#endif
#ifdef WITH_OPENSSL
# ifdef OPENSSL_HAS_ECC
	&sshkey_ecdsa_nistp256_impl,
	&sshkey_ecdsa_nistp256_cert_impl,
	&sshkey_ecdsa_nistp384_impl,
	&sshkey_ecdsa_nistp384_cert_impl,
#  ifdef OPENSSL_HAS_NISTP521
	&sshkey_ecdsa_nistp521_impl,
	&sshkey_ecdsa_nistp521_cert_impl,
#  endif /* OPENSSL_HAS_NISTP521 */
#  ifdef ENABLE_SK
	&sshkey_ecdsa_sk_impl,
	&sshkey_ecdsa_sk_cert_impl,
	&sshkey_ecdsa_sk_webauthn_impl,
#  endif /* ENABLE_SK */
# endif /* OPENSSL_HAS_ECC */
	&sshkey_dss_impl,
	&sshkey_dsa_cert_impl,
	&sshkey_rsa_impl,
	&sshkey_rsa_cert_impl,
	&sshkey_rsa_sha256_impl,
	&sshkey_rsa_sha256_cert_impl,
	&sshkey_rsa_sha512_impl,
	&sshkey_rsa_sha512_cert_impl,
#endif /* WITH_OPENSSL */
#ifdef WITH_XMSS
	&sshkey_xmss_impl,
	&sshkey_xmss_cert_impl,
#endif
	NULL
};
```

```c
const struct sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
```

```c
static const struct sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_size,
	/* .alloc = */		ssh_rsa_alloc,
	/* .cleanup = */	ssh_rsa_cleanup,
	/* .equal = */		ssh_rsa_equal,
	/* .ssh_serialize_public = */ ssh_rsa_serialize_public,
	/* .ssh_deserialize_public = */ ssh_rsa_deserialize_public,
	/* .ssh_serialize_private = */ ssh_rsa_serialize_private,
	/* .ssh_deserialize_private = */ ssh_rsa_deserialize_private,
	/* .generate = */	ssh_rsa_generate,
	/* .copy_public = */	ssh_rsa_copy_public,
	/* .sign = */		ssh_rsa_sign,
	/* .verify = */		ssh_rsa_verify,
};
```

# Example 12

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/openssh-build/../openssh-9.6p1/mux.c:1205:10*

fnptr: *mux_master_handlers[i].handler*

targets: mux_master_process_hello, mux_master_process_new_session, mux_master_process_alive_check, mux_master_process_terminate, mux_master_process_open_fwd, mux_master_process_close_fwd, mux_master_process_stdio_fwd, mux_master_process_stop_listening, mux_master_process_proxy

## Related Code Snippets

```c
/* Channel callbacks fired on read/write from mux client fd */
static int
mux_master_read_cb(struct ssh *ssh, Channel *c)
{
	struct sshbuf *in = NULL, *out = NULL;
	u_int type, rid, i;
	int r, ret = -1;

	for (i = 0; mux_master_handlers[i].handler != NULL; i++) {
		if (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, in, out);
			break;
		}
	}
	if (mux_master_handlers[i].handler == NULL) {
		error_f("unsupported mux message 0x%08x", type);
		reply_error(out, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}

 out:
	sshbuf_free(in);
	sshbuf_free(out);
	return ret;
}
```

```c
static const struct {
	u_int type;
	int (*handler)(struct ssh *, u_int, Channel *,
	    struct sshbuf *, struct sshbuf *);
} mux_master_handlers[] = {
	{ MUX_MSG_HELLO, mux_master_process_hello },
	{ MUX_C_NEW_SESSION, mux_master_process_new_session },
	{ MUX_C_ALIVE_CHECK, mux_master_process_alive_check },
	{ MUX_C_TERMINATE, mux_master_process_terminate },
	{ MUX_C_OPEN_FWD, mux_master_process_open_fwd },
	{ MUX_C_CLOSE_FWD, mux_master_process_close_fwd },
	{ MUX_C_NEW_STDIO_FWD, mux_master_process_stdio_fwd },
	{ MUX_C_STOP_LISTENING, mux_master_process_stop_listening },
	{ MUX_C_PROXY, mux_master_process_proxy },
	{ 0, NULL }
};
```