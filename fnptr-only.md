# Example 1

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/src/zmalloc.c:146:15*

fnptr: *zmalloc_oom_handler*

targets: zmalloc_default_oom

## Related Code Snippets

```c
/* Allocate memory or panic */
void *zmalloc(size_t size) {
    void *ptr = ztrymalloc_usable_internal(size, NULL);
    if (!ptr) zmalloc_oom_handler(size);
    return ptr;
}
```

```c
static void (*zmalloc_oom_handler)(size_t) = zmalloc_default_oom;
```

# Example 2

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/curl-build/lib/../../curl-8.5.0/lib/altsvc.c:100:23*

fnptr: *Curl_ccalloc*

targets: calloc

## Related Code Snippets

```c
static const char *dsthost,
                                      enum alpnid srcalpnid,
                                      enum alpnid dstalpnid,
                                      unsigned int srcport,
                                      unsigned int dstport)
{
  struct altsvc *as = calloc(1, sizeof(struct altsvc));
  size_t hlen;
  size_t dlen;
  if(!as)
    return NULL;
}
```

```c
#define calloc(nbelem,size) Curl_ccalloc(nbelem, size)
```

```c
curl_calloc_callback Curl_ccalloc = (curl_calloc_callback)calloc;
```

```c
static CURLcode global_init(long flags, bool memoryfuncs)
{
  if(initialized++)
    return CURLE_OK;

  if(memoryfuncs) {
    /* Setup the default memory functions here (again) */
    Curl_cmalloc = (curl_malloc_callback)malloc;
    Curl_cfree = (curl_free_callback)free;
    Curl_crealloc = (curl_realloc_callback)realloc;
    Curl_cstrdup = (curl_strdup_callback)system_strdup;
    Curl_ccalloc = (curl_calloc_callback)calloc;
    ...
  }
}
```

# Example 3

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/wrk-4.2.0/obj/openssl-1.1.1i/ssl/s3_cbc.c:449:9*

fnptr: *md_final_raw*

targets: tls1_md5_final_raw, tls1_sha1_final_raw, tls1_sha256_final_raw, tls1_sha512_final_raw

## Related Code Snippets

```c
int unsigned char *md_out,
                           size_t *md_out_size,
                           const unsigned char header[13],
                           const unsigned char *data,
                           size_t data_plus_mac_size,
                           size_t data_plus_mac_plus_padding_size,
                           const unsigned char *mac_secret,
                           size_t mac_secret_length, char is_sslv3)
{
    union {
        double align;
        unsigned char c[sizeof(LARGEST_DIGEST_CTX)];
    } md_state;
    void (*md_final_raw) (void *ctx, unsigned char *md_out);
    void (*md_transform) (void *ctx, const unsigned char *block);
...
switch (EVP_MD_CTX_type(ctx)) {
case NID_md5: 
...
    md_final_raw = tls1_md5_final_raw;
    ...
    break;
case NID_sha1:
...
    md_final_raw = tls1_sha1_final_raw;
    md_transform =
        (void (*)(void *ctx, const unsigned char *block))SHA1_Transform;
    md_size = 20;
    break;
case NID_sha224:
...
    md_final_raw = tls1_sha256_final_raw;
    md_transform =
        (void (*)(void *ctx, const unsigned char *block))SHA256_Transform;
...
    break;
case NID_sha256:
    if (SHA256_Init((SHA256_CTX *)md_state.c) <= 0)
        return 0;
    md_final_raw = tls1_sha256_final_raw;
    md_transform =
        (void (*)(void *ctx, const unsigned char *block))SHA256_Transform;
    md_size = 32;
    break;
case NID_sha384:
...
    md_final_raw = tls1_sha512_final_raw;
    md_transform =
        (void (*)(void *ctx, const unsigned char *block))SHA512_Transform;
...
    break;
case NID_sha512:
...
    md_final_raw = tls1_sha512_final_raw;
...
    break;
default:
    ...

for (i = num_starting_blocks; i <= num_starting_blocks + variance_blocks;
     i++) {
...
    md_transform(md_state.c, block);
    md_final_raw(md_state.c, block);
    /* If this is index_b, copy the hash value to |mac_out|. */
    for (j = 0; j < md_size; j++)
        mac_out[j] |= block[j] & is_block_b;
...
     }
}
}
```

# Example 4

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/ffmpeg-6.1.1/libswscale/swscale_unscaled.c:559:13*

fnptr: *conv*

targets: gray8aToPacked32, gray8aToPacked32_1, gray8aToPacked24, sws_convertPalette8ToPacked32, sws_convertPalette8ToPacked24

## Related Code Snippets

```c
static int palToRgbWrapper(SwsContext *c, const uint8_t *src[], int srcStride[],
                           int srcSliceY, int srcSliceH, uint8_t *dst[],
                           int dstStride[])
{
    const enum AVPixelFormat srcFormat = c->srcFormat;
    const enum AVPixelFormat dstFormat = c->dstFormat;
    void (*conv)(const uint8_t *src, uint8_t *dst, int num_pixels,
                 const uint8_t *palette) = NULL;
    int i;
    uint8_t *dstPtr = dst[0] + dstStride[0] * srcSliceY;
    const uint8_t *srcPtr = src[0];

    if (srcFormat == AV_PIX_FMT_YA8) {
        switch (dstFormat) {
        case AV_PIX_FMT_RGB32  : conv = gray8aToPacked32; break;
        case AV_PIX_FMT_BGR32  : conv = gray8aToPacked32; break;
        case AV_PIX_FMT_BGR32_1: conv = gray8aToPacked32_1; break;
        case AV_PIX_FMT_RGB32_1: conv = gray8aToPacked32_1; break;
        case AV_PIX_FMT_RGB24  : conv = gray8aToPacked24; break;
        case AV_PIX_FMT_BGR24  : conv = gray8aToPacked24; break;
        }
    } else if (usePal(srcFormat)) {
        switch (dstFormat) {
        case AV_PIX_FMT_RGB32  : conv = sws_convertPalette8ToPacked32; break;
        case AV_PIX_FMT_BGR32  : conv = sws_convertPalette8ToPacked32; break;
        case AV_PIX_FMT_BGR32_1: conv = sws_convertPalette8ToPacked32; break;
        case AV_PIX_FMT_RGB32_1: conv = sws_convertPalette8ToPacked32; break;
        case AV_PIX_FMT_RGB24  : conv = sws_convertPalette8ToPacked24; break;
        case AV_PIX_FMT_BGR24  : conv = sws_convertPalette8ToPacked24; break;
        }
    }

    if (!conv)
        av_log(c, AV_LOG_ERROR, "internal error %s -> %s converter\n",
               av_get_pix_fmt_name(srcFormat), av_get_pix_fmt_name(dstFormat));
    else {
        for (i = 0; i < srcSliceH; i++) {
            conv(srcPtr, dstPtr, c->srcW, (uint8_t *) c->pal_rgb);
            srcPtr += srcStride[0];
            dstPtr += dstStride[0];
        }
    }

    return srcSliceH;
}
```

# Example 5

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/openssh-build/../openssh-9.6p1/log.c:404:3*

fnptr: *tmp_handler*

targets: mm_log_handler

## Related Code Snippets

```c
static void
do_log(LogLevel level, int force, const char *suffix, const char *fmt,
    va_list args)
{
        ...
	log_handler_fn *tmp_handler;
	const char *progname = argv0 != NULL ? argv0 : __progname;

	if (!force && level > log_level)
		return;

	...
	if (log_handler != NULL) {
		/* Avoid recursion */
		tmp_handler = log_handler;
		log_handler = NULL;
		tmp_handler(level, force, fmtbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} else if (log_on_stderr) {
		snprintf(msgbuf, sizeof msgbuf, "%s%s%.*s\r\n",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (int)sizeof msgbuf - 3, fmtbuf);
		(void)write(log_stderr_fd, msgbuf, strlen(msgbuf));
	} else {
        ...
    }
}
```

```c
static log_handler_fn *log_handler;

void set_log_handler(log_handler_fn *handler, void *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}
```

```c
static int privsep_preauth(struct ssh *ssh)
{
	...

	if (use_privsep == PRIVSEP_ON)
		box = ssh_sandbox_init(pmonitor);
	pid = fork();
	if (pid == -1) {
		fatal("fork of unprivileged child failed");
	} else if (pid != 0) {
		...
	} else {
		...
		/* Arrange for logging to be sent to the monitor */
		set_log_handler(mm_log_handler, pmonitor);
		...
	}
}
```

# Example 6

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/redis-stable/deps/jemalloc/src/jemalloc.c:3825:3*

fnptr: *junk_alloc_callback*

targets: default_junk_alloc

## Related Code Snippets

```c
static void *
do_rallocx(void *ptr, size_t size, int flags, bool is_realloc) {
	...

	if (config_fill && unlikely(opt_junk_alloc) && usize > old_usize
	    && !zero) {
		size_t excess_len = usize - old_usize;
		void *excess_start = (void *)((uintptr_t)p + old_usize);
		junk_alloc_callback(excess_start, excess_len);
	}
}
```

```c
void (*junk_alloc_callback)(void *ptr, size_t size) = &default_junk_alloc;
```

# Example 7

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/cmd/zstream/zstream_decompress.c:304:21*

fnptr: *xfunc*

targets: lzjb_decompress, gzip_decompress, zle_decompress, lz4_decompress_zfs, zfs_zstd_decompress

## Related Code Snippets

```c
int
zstream_do_decompress(int argc, char *argv[])
{
	...

	while (sfread(drr, sizeof (*drr), stdin) != 0) {
		struct drr_write *drrw;
		uint64_t payload_size = 0;

		/*
		 * We need to regenerate the checksum.
		 */
		if (drr->drr_type != DRR_BEGIN) {
			memset(&drr->drr_u.drr_checksum.drr_checksum, 0,
			    sizeof (drr->drr_u.drr_checksum.drr_checksum));
		}

		switch (drr->drr_type) {
		...
		case DRR_WRITE_BYREF:
			VERIFY3S(begin, ==, 1);
			fprintf(stderr,
			    "Deduplicated streams are not supported\n");
			exit(1);
			break;

		case DRR_WRITE:
		{
			VERIFY3S(begin, ==, 1);
			drrw = &thedrr.drr_u.drr_write;
			payload_size = DRR_WRITE_PAYLOAD_SIZE(drrw);
			ENTRY *p;
			char key[KEYSIZE];

			snprintf(key, KEYSIZE, "%llu,%llu",
			    (u_longlong_t)drrw->drr_object,
			    (u_longlong_t)drrw->drr_offset);
			ENTRY e = {.key = key};

			p = hsearch(e, FIND);
			if (p != NULL) {
				zio_decompress_func_t *xfunc = NULL;
				switch ((enum zio_compress)(intptr_t)p->data) {
				case ZIO_COMPRESS_OFF:
					xfunc = NULL;
					break;
				case ZIO_COMPRESS_LZJB:
					xfunc = lzjb_decompress;
					break;
				case ZIO_COMPRESS_GZIP_1:
					xfunc = gzip_decompress;
					break;
				case ZIO_COMPRESS_ZLE:
					xfunc = zle_decompress;
					break;
				case ZIO_COMPRESS_LZ4:
					xfunc = lz4_decompress_zfs;
					break;
				case ZIO_COMPRESS_ZSTD:
					xfunc = zfs_zstd_decompress;
					break;
				default:
					assert(B_FALSE);
				}


				/*
				 * Read and decompress the block
				 */
				char *lzbuf = safe_calloc(payload_size);
				(void) sfread(lzbuf, payload_size, stdin);
				if (xfunc == NULL) {
					memcpy(buf, lzbuf, payload_size);
					drrw->drr_compressiontype =
					    ZIO_COMPRESS_OFF;
					if (verbose)
						fprintf(stderr, "Resetting "
						    "compression type to off "
						    "for ino %llu offset "
						    "%llu\n",
						    (u_longlong_t)
						    drrw->drr_object,
						    (u_longlong_t)
						    drrw->drr_offset);
				} else if (0 != xfunc(lzbuf, buf,
				    payload_size, payload_size, 0)) {
					/*
					 * The block must not be compressed,
					 * at least not with this compression
					 * type, possibly because it gets
					 * written multiple times in this
					 * stream.
					 */
					warnx("decompression failed for "
					    "ino %llu offset %llu",
					    (u_longlong_t)drrw->drr_object,
					    (u_longlong_t)drrw->drr_offset);
					memcpy(buf, lzbuf, payload_size);
				} else if (verbose) {
					drrw->drr_compressiontype =
					    ZIO_COMPRESS_OFF;
					fprintf(stderr, "successfully "
					    "decompressed ino %llu "
					    "offset %llu\n",
					    (u_longlong_t)drrw->drr_object,
					    (u_longlong_t)drrw->drr_offset);
				} else {
					drrw->drr_compressiontype =
					    ZIO_COMPRESS_OFF;
				}
				free(lzbuf);
			} else {
				/*
				 * Read the contents of the block unaltered
				 */
				(void) sfread(buf, payload_size, stdin);
			}
			break;
		}

		case DRR_WRITE_EMBEDDED:
		{
			VERIFY3S(begin, ==, 1);
			struct drr_write_embedded *drrwe =
			    &drr->drr_u.drr_write_embedded;
			payload_size =
			    P2ROUNDUP((uint64_t)drrwe->drr_psize, 8);
			(void) sfread(buf, payload_size, stdin);
			break;
		}

		case DRR_FREEOBJECTS:
		case DRR_FREE:
		case DRR_OBJECT_RANGE:
			VERIFY3S(begin, ==, 1);
			break;

		default:
			(void) fprintf(stderr, "INVALID record type 0x%x\n",
			    drr->drr_type);
			/* should never happen, so assert */
			assert(B_FALSE);
		}
		...
	}
	free(buf);
	fletcher_4_fini();
	hdestroy();

	return (0);
}
```

# Example 8

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/curl-build/lib/../../curl-8.5.0/lib/cookie.c:872:7*

fnptr: *Curl_cfree*

targets: free

## Related Code Snippets

```c
struct Cookie *
Curl_cookie_add(struct Curl_easy *data,
                struct CookieInfo *c,
                bool httpheader, /* TRUE if HTTP header-style line */
                bool noexpire, /* if TRUE, skip remove_expired() */
                const char *lineptr,   /* first character of the line */
                const char *domain, /* default domain */
                const char *path,   /* full path used when this cookie is set,
                                       used to get default path for the cookie
                                       unless set */
                bool secure)  /* TRUE if connection is over secure origin */
{
    ...
    if(lineptr[0]=='#') {
      /* don't even try the comments */
      free(co);
      return NULL;
    }
    ...
}

```

```c
#define free(ptr) Curl_cfree(ptr)
```

```
curl_free_callback Curl_cfree = (curl_free_callback)free;
```

# Example 9

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/curl-build/lib/../../curl-8.5.0/lib/http_digest.c:114:3*

fnptr: *Curl_cfree*

targets: free

## Related Code Snippets

```c
CURLcode Curl_output_digest(struct Curl_easy *data,
                            bool proxy,
                            const unsigned char *request,
                            const unsigned char *uripath)
{
  CURLcode result;
  ...

  Curl_safefree(*allocuserpwd);

  /* not set means empty */
  if(!userp)
    userp = "";

  if(!passwdp)
    passwdp = "";

  ...
  
  return CURLE_OK;
}

```

```c
#define Curl_safefree(ptr) \
  do { free((ptr)); (ptr) = NULL;} while(0)
```

```c
#define free(ptr) Curl_cfree(ptr)
```

```c
curl_free_callback Curl_cfree = (curl_free_callback)free;
```

# Example 10

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/curl-build/lib/../../curl-8.5.0/lib/smtp.c:1847:28*

fnptr: *Curl_cfree*

targets: malloc

## Related Code Snippets

```c
CURLcode Curl_smtp_escape_eob(struct Curl_easy *data,
                              const ssize_t nread,
                              const ssize_t offset)
{
  ...

  /* Do we need to allocate a scratch buffer? */
  if(!scratch || data->set.crlf) {
    oldscratch = scratch;

    scratch = newscratch = malloc(2 * data->set.upload_buffer_size);
    if(!newscratch) {
      failf(data, "Failed to alloc scratch buffer");

      return CURLE_OUT_OF_MEMORY;
    }
  }
  DEBUGASSERT((size_t)data->set.upload_buffer_size >= (size_t)nread);
  ...
}
```

```c
#define malloc(size) Curl_cmalloc(size)
```

```
curl_malloc_callback Curl_cmalloc = (curl_malloc_callback)malloc;
```

# Example 11

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/curl-build/lib/../../curl-8.5.0/lib/cookie.c:945:20*

fnptr: *strdup*

targets: Curl_strdup, strdup

## Related Code Snippets

```c
struct Cookie *
Curl_cookie_add(struct Curl_easy *data,
                struct CookieInfo *c,
                bool httpheader, /* TRUE if HTTP header-style line */
                bool noexpire, /* if TRUE, skip remove_expired() */
                const char *lineptr,   /* first character of the line */
                const char *domain, /* default domain */
                const char *path,   /* full path used when this cookie is set,
                                       used to get default path for the cookie
                                       unless set */
                bool secure)  /* TRUE if connection is over secure origin */
{
    ...
    for(ptr = firstptr, fields = 0; ptr && !badcookie;
        ptr = strtok_r(NULL, "\t", &tok_buf), fields++) {
        switch(fields) {
        ...
        case 5:
        co->name = strdup(ptr);
        ...
        }
    }
}
```

```c
#define strdup(ptr) Curl_cstrdup(ptr)
```

```c
curl_strdup_callback Curl_cstrdup = (curl_strdup_callback)system_strdup;
```

```c
#if defined(_WIN32_WCE)
...
#elif !defined(HAVE_STRDUP)
#define system_strdup Curl_strdup
#else
...
#endif
```

# Example 12

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/ffmpeg-6.1.1/libswscale/swscale_unscaled.c:177:9*

fnptr: *deinterleaveBytes*

targets: deinterleaveBytes_c

## Related Code Snippets

```c
static int nv12ToPlanarWrapper(SwsContext *c, const uint8_t *src[],
                               int srcStride[], int srcSliceY,
                               int srcSliceH, uint8_t *dstParam[],
                               int dstStride[])
{
    uint8_t *dst1 = dstParam[1] + dstStride[1] * srcSliceY / 2;
    uint8_t *dst2 = dstParam[2] + dstStride[2] * srcSliceY / 2;

    copyPlane(src[0], srcStride[0], srcSliceY, srcSliceH, c->srcW,
              dstParam[0], dstStride[0]);

    if (c->srcFormat == AV_PIX_FMT_NV12)
        deinterleaveBytes(src[1], dst1, dst2, c->chrSrcW, (srcSliceH + 1) / 2,
                          srcStride[1], dstStride[1], dstStride[2]);
    else
        deinterleaveBytes(src[1], dst2, dst1, c->chrSrcW, (srcSliceH + 1) / 2,
                          srcStride[1], dstStride[2], dstStride[1]);

    return srcSliceH;
}
```

```c
void (*deinterleaveBytes)(const uint8_t *src, uint8_t *dst1, uint8_t *dst2,
                          int width, int height, int srcStride,
                          int dst1Stride, int dst2Stride);
```

```c
static av_cold void rgb2rgb_init_c(void)
{
    rgb15to16          = rgb15to16_c;
    rgb15tobgr24       = rgb15tobgr24_c;
    rgb15to32          = rgb15to32_c;
    rgb16tobgr24       = rgb16tobgr24_c;
    rgb16to32          = rgb16to32_c;
    rgb16to15          = rgb16to15_c;
    rgb24tobgr16       = rgb24tobgr16_c;
    rgb24tobgr15       = rgb24tobgr15_c;
    rgb24tobgr32       = rgb24tobgr32_c;
    rgb32to16          = rgb32to16_c;
    rgb32to15          = rgb32to15_c;
    rgb32tobgr24       = rgb32tobgr24_c;
    rgb24to15          = rgb24to15_c;
    rgb24to16          = rgb24to16_c;
    rgb24tobgr24       = rgb24tobgr24_c;
#if HAVE_BIGENDIAN
    shuffle_bytes_0321 = shuffle_bytes_2103_c;
    shuffle_bytes_2103 = shuffle_bytes_0321_c;
#else
    shuffle_bytes_0321 = shuffle_bytes_0321_c;
    shuffle_bytes_2103 = shuffle_bytes_2103_c;
#endif
    shuffle_bytes_1230 = shuffle_bytes_1230_c;
    shuffle_bytes_3012 = shuffle_bytes_3012_c;
    shuffle_bytes_3210 = shuffle_bytes_3210_c;
    rgb32tobgr16       = rgb32tobgr16_c;
    rgb32tobgr15       = rgb32tobgr15_c;
    yv12toyuy2         = yv12toyuy2_c;
    yv12touyvy         = yv12touyvy_c;
    yuv422ptoyuy2      = yuv422ptoyuy2_c;
    yuv422ptouyvy      = yuv422ptouyvy_c;
    yuy2toyv12         = yuy2toyv12_c;
    planar2x           = planar2x_c;
    ff_rgb24toyv12     = ff_rgb24toyv12_c;
    interleaveBytes    = interleaveBytes_c;
    deinterleaveBytes  = deinterleaveBytes_c;
    vu9_to_vu12        = vu9_to_vu12_c;
    yvu9_to_yuy2       = yvu9_to_yuy2_c;

    uyvytoyuv420       = uyvytoyuv420_c;
    uyvytoyuv422       = uyvytoyuv422_c;
    yuyvtoyuv420       = yuyvtoyuv420_c;
    yuyvtoyuv422       = yuyvtoyuv422_c;
}
```