# Example 1

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/cmd/zdb/zdb.c:3803:4*

fnptr: *object_viewer[ZDB_OT_TYPE(doi.doi_bonus_type)]*

targets: dump_acl, dump_bpobj, dump_bpobj_subobjs, dump_ddt_zap, dump_dmu_objset, dump_dnode, dump_dsl_dataset, dump_dsl_dir, dump_history_offsets, dump_none, dump_packed_nvlist, dump_sa_attrs, dump_sa_layouts, dump_uint64, dump_uint8, dump_unknown, dump_zap, dump_znode, dump_zpldir

## Related Code Snippets

```c
static void
dump_object(objset_t *os, uint64_t object, int verbosity,
    boolean_t *print_header, uint64_t *dnode_slots_used, uint64_t flags)
{
	if (!dnode_held) {
		object_viewer[ZDB_OT_TYPE(doi.doi_bonus_type)](os,
				object, bonus, bsize);
	} else {
		(void) printf("\t\t(bonus encrypted)\n");
	}
}
```

```c
static object_viewer_t *object_viewer[DMU_OT_NUMTYPES + 1] = {
	dump_none,		/* unallocated			*/
	dump_zap,		/* object directory		*/
	dump_uint64,		/* object array			*/
	dump_none,		/* packed nvlist		*/
	dump_packed_nvlist,	/* packed nvlist size		*/
	dump_none,		/* bpobj			*/
	dump_bpobj,		/* bpobj header			*/
	dump_none,		/* SPA space map header		*/
	dump_none,		/* SPA space map		*/
	dump_none,		/* ZIL intent log		*/
	dump_dnode,		/* DMU dnode			*/
	dump_dmu_objset,	/* DMU objset			*/
	dump_dsl_dir,		/* DSL directory		*/
	dump_zap,		/* DSL directory child map	*/
	dump_zap,		/* DSL dataset snap map		*/
	dump_zap,		/* DSL props			*/
	dump_dsl_dataset,	/* DSL dataset			*/
	dump_znode,		/* ZFS znode			*/
	dump_acl,		/* ZFS V0 ACL			*/
	dump_uint8,		/* ZFS plain file		*/
	dump_zpldir,		/* ZFS directory		*/
	dump_zap,		/* ZFS master node		*/
	dump_zap,		/* ZFS delete queue		*/
	dump_uint8,		/* zvol object			*/
	dump_zap,		/* zvol prop			*/
	dump_uint8,		/* other uint8[]		*/
	dump_uint64,		/* other uint64[]		*/
	dump_zap,		/* other ZAP			*/
	dump_zap,		/* persistent error log		*/
	dump_uint8,		/* SPA history			*/
	dump_history_offsets,	/* SPA history offsets		*/
	dump_zap,		/* Pool properties		*/
	dump_zap,		/* DSL permissions		*/
	dump_acl,		/* ZFS ACL			*/
	dump_uint8,		/* ZFS SYSACL			*/
	dump_none,		/* FUID nvlist			*/
	dump_packed_nvlist,	/* FUID nvlist size		*/
	dump_zap,		/* DSL dataset next clones	*/
	dump_zap,		/* DSL scrub queue		*/
	dump_zap,		/* ZFS user/group/project used	*/
	dump_zap,		/* ZFS user/group/project quota	*/
	dump_zap,		/* snapshot refcount tags	*/
	dump_ddt_zap,		/* DDT ZAP object		*/
	dump_zap,		/* DDT statistics		*/
	dump_znode,		/* SA object			*/
	dump_zap,		/* SA Master Node		*/
	dump_sa_attrs,		/* SA attribute registration	*/
	dump_sa_layouts,	/* SA attribute layouts		*/
	dump_zap,		/* DSL scrub translations	*/
	dump_none,		/* fake dedup BP		*/
	dump_zap,		/* deadlist			*/
	dump_none,		/* deadlist hdr			*/
	dump_zap,		/* dsl clones			*/
	dump_bpobj_subobjs,	/* bpobj subobjs		*/
	dump_unknown,		/* Unknown type, must be last	*/
};
```

# Example 2

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/ffmpeg-6.1.1/libavcodec/aaccoder.c:284:5*

fnptr: *quantize_and_encode_band_cost_rtz_arr : quantize_and_encode_band_cost_arr)[cb]*

targets: quantize_and_encode_band_cost_ZERO, quantize_and_encode_band_cost_SQUAD, quantize_and_encode_band_cost_UQUAD, quantize_and_encode_band_cost_SPAIR, quantize_and_encode_band_cost_UPAIR, quantize_and_encode_band_cost_ESC, quantize_and_encode_band_cost_NONE, quantize_and_encode_band_cost_NOISE, quantize_and_encode_band_cost_STEREO, quantize_and_encode_band_cost_ESC_RTZ

## Related Code Snippets

```c
static inline void quantize_and_encode_band(struct AACEncContext *s, PutBitContext *pb,
                                            const float *in, float *out, int size, int scale_idx,
                                            int cb, const float lambda, int rtz)
{
    (rtz ? quantize_and_encode_band_cost_rtz_arr : quantize_and_encode_band_cost_arr)[cb](s, pb, in, out, NULL, size, scale_idx, cb,
                                     lambda, INFINITY, NULL, NULL);
}
```

```c
static const quantize_and_encode_band_func quantize_and_encode_band_cost_arr[] =
{
    quantize_and_encode_band_cost_ZERO,
    quantize_and_encode_band_cost_SQUAD,
    quantize_and_encode_band_cost_SQUAD,
    quantize_and_encode_band_cost_UQUAD,
    quantize_and_encode_band_cost_UQUAD,
    quantize_and_encode_band_cost_SPAIR,
    quantize_and_encode_band_cost_SPAIR,
    quantize_and_encode_band_cost_UPAIR,
    quantize_and_encode_band_cost_UPAIR,
    quantize_and_encode_band_cost_UPAIR,
    quantize_and_encode_band_cost_UPAIR,
    quantize_and_encode_band_cost_ESC,
    quantize_and_encode_band_cost_NONE,     /* CB 12 doesn't exist */
    quantize_and_encode_band_cost_NOISE,
    quantize_and_encode_band_cost_STEREO,
    quantize_and_encode_band_cost_STEREO,
};

static const quantize_and_encode_band_func quantize_and_encode_band_cost_rtz_arr[] =
{
    quantize_and_encode_band_cost_ZERO,
    quantize_and_encode_band_cost_SQUAD,
    quantize_and_encode_band_cost_SQUAD,
    quantize_and_encode_band_cost_UQUAD,
    quantize_and_encode_band_cost_UQUAD,
    quantize_and_encode_band_cost_SPAIR,
    quantize_and_encode_band_cost_SPAIR,
    quantize_and_encode_band_cost_UPAIR,
    quantize_and_encode_band_cost_UPAIR,
    quantize_and_encode_band_cost_UPAIR,
    quantize_and_encode_band_cost_UPAIR,
    quantize_and_encode_band_cost_ESC_RTZ,
    quantize_and_encode_band_cost_NONE,     /* CB 12 doesn't exist */
    quantize_and_encode_band_cost_NOISE,
    quantize_and_encode_band_cost_STEREO,
    quantize_and_encode_band_cost_STEREO,
};
```

# Example 3

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/ffmpeg-6.1.1/libavcodec/ass_split.c:329:25*

fnptr: *convert_func[type]*

targets: convert_str, convert_int, convert_flt, convert_color, convert_timestamp, convert_alignment

## Related Code Snippets

```c
static const char *ass_split_section(ASSSplitContext *ctx, const char *buf)
{
    const ASSSection *section = &ass_sections[ctx->current_section];
    int *number = &ctx->field_number[ctx->current_section];
    int *order = ctx->field_order[ctx->current_section];
    int i, len;

    while (buf && *buf) {
		...
		buf += len + 1;
		for (i=0; !is_eol(*buf) && i < *number; i++) {
			int last = i == *number - 1;
			buf = skip_space(buf);
			len = strcspn(buf, last ? "\r\n" : ",\r\n");
			if (order[i] >= 0) {
				ASSFieldType type = section->fields[order[i]].type;
				ptr = struct_ptr + section->fields[order[i]].offset;
				convert_func[type](ptr, buf, len);
			}
			buf += len;
			if (!last && *buf) buf++;
			buf = skip_space(buf);
		}
	}
	... 
    return buf;
}
```

```c
static const ASSConvertFunc convert_func[] = {
    [ASS_STR]       = convert_str,
    [ASS_INT]       = convert_int,
    [ASS_FLT]       = convert_flt,
    [ASS_COLOR]     = convert_color,
    [ASS_TIMESTAMP] = convert_timestamp,
    [ASS_ALGN]      = convert_alignment,
};
```

# Example 4

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/ffmpeg-6.1.1/libavcodec/exr.c:2241:19*

fnptr: *trc_func*

targets: trc_bt709, trc_gamma22, trc_gamma28, trc_smpte240M, trc_linear, trc_log, trc_log_sqrt, trc_iec61966_2_4, trc_bt1361, trc_iec61966_2_1, trc_smpte_st2084, trc_smpte_st428_1, trc_arib_std_b67

## Related Code Snippets

```c
static av_cold int decode_init(AVCodecContext *avctx)
{
    EXRContext *s = avctx->priv_data;
    ...
    av_csp_trc_function trc_func = NULL;

    ff_init_half2float_tables(&s->h2f_tables);

    s->avctx              = avctx;

    ff_exrdsp_init(&s->dsp);
    ...

    trc_func = av_csp_trc_func_from_id(s->apply_trc_type);
    if (trc_func) {
        for (i = 0; i < 65536; ++i) {
            t.i = half2float(i, &s->h2f_tables);
            t.f = trc_func(t.f);
            s->gamma_table[i] = t;
        }
        ...
    }
}
```

```c
static const av_csp_trc_function trc_funcs[AVCOL_TRC_NB] = {
    [AVCOL_TRC_BT709] = trc_bt709,
    [AVCOL_TRC_GAMMA22] = trc_gamma22,
    [AVCOL_TRC_GAMMA28] = trc_gamma28,
    [AVCOL_TRC_SMPTE170M] = trc_bt709,
    [AVCOL_TRC_SMPTE240M] = trc_smpte240M,
    [AVCOL_TRC_LINEAR] = trc_linear,
    [AVCOL_TRC_LOG] = trc_log,
    [AVCOL_TRC_LOG_SQRT] = trc_log_sqrt,
    [AVCOL_TRC_IEC61966_2_4] = trc_iec61966_2_4,
    [AVCOL_TRC_BT1361_ECG] = trc_bt1361,
    [AVCOL_TRC_IEC61966_2_1] = trc_iec61966_2_1,
    [AVCOL_TRC_BT2020_10] = trc_bt709,
    [AVCOL_TRC_BT2020_12] = trc_bt709,
    [AVCOL_TRC_SMPTE2084] = trc_smpte_st2084,
    [AVCOL_TRC_SMPTE428] = trc_smpte_st428_1,
    [AVCOL_TRC_ARIB_STD_B67] = trc_arib_std_b67,
};

av_csp_trc_function av_csp_trc_func_from_id(enum AVColorTransferCharacteristic trc)
{
    av_csp_trc_function func;
    if (trc >= AVCOL_TRC_NB)
        return NULL;
    func = trc_funcs[trc];
    if (!func)
        return NULL;
    return func;
}
```

# Example 5

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/curl-build/lib/../../curl-8.5.0/lib/multi.c:196:5*

fnptr: *finit[state]*

targets: Curl_init_CONNECT, before_perform, init_completed

## Related Code Snippets

```c
/* always use this function to change state, to make debugging easier */
static void mstate(struct Curl_easy *data, CURLMstate state
#ifdef DEBUGBUILD
                   , int lineno
#endif
)
{
  CURLMstate oldstate = data->mstate;
  static const init_multistate_func finit[MSTATE_LAST] = {
    NULL,              /* INIT */
    NULL,              /* PENDING */
    Curl_init_CONNECT, /* CONNECT */
    NULL,              /* RESOLVING */
    NULL,              /* CONNECTING */
    NULL,              /* TUNNELING */
    NULL,              /* PROTOCONNECT */
    NULL,              /* PROTOCONNECTING */
    NULL,              /* DO */
    NULL,              /* DOING */
    NULL,              /* DOING_MORE */
    before_perform,    /* DID */
    NULL,              /* PERFORMING */
    NULL,              /* RATELIMITING */
    NULL,              /* DONE */
    init_completed,    /* COMPLETED */
    NULL               /* MSGSENT */
  };
  ...
/* if this state has an init-function, run it */
  if(finit[state])
    finit[state](data);
}
```


# Example 6

## Callsite

*/home/yuanting/work/icall-benchmarks/llm/zfs-build/../zfs-2.2.2/module/zfs/vdev_raidz_math_impl.h:1387:3*

fnptr: *gf_x1_mul_fns[c]*

targets: mul_x1_0, mul_x1_1, mul_x1_2, mul_x1_3, mul_x1_4, mul_x1_5, mul_x1_6, mul_x1_7, mul_x1_8, mul_x1_9, mul_x1_10, mul_x1_11, mul_x1_12, mul_x1_13, mul_x1_14, mul_x1_15, mul_x1_16, mul_x1_17, mul_x1_18, mul_x1_19, mul_x1_20, mul_x1_21, mul_x1_22, mul_x1_23, mul_x1_24, mul_x1_25, mul_x1_26, mul_x1_27, mul_x1_28, mul_x1_29, mul_x1_30, mul_x1_31, mul_x1_32, mul_x1_33, mul_x1_34, mul_x1_35, mul_x1_36, mul_x1_37, mul_x1_38, mul_x1_39, mul_x1_40, mul_x1_41, mul_x1_42, mul_x1_43, mul_x1_44, mul_x1_45, mul_x1_46, mul_x1_47, mul_x1_48, mul_x1_49, mul_x1_50, mul_x1_51, mul_x1_52, mul_x1_53, mul_x1_54, mul_x1_55, mul_x1_56, mul_x1_57, mul_x1_58, mul_x1_59, mul_x1_60, mul_x1_61, mul_x1_62, mul_x1_63, mul_x1_64, mul_x1_65, mul_x1_66, mul_x1_67, mul_x1_68, mul_x1_69, mul_x1_70, mul_x1_71, mul_x1_72, mul_x1_73, mul_x1_74, mul_x1_75, mul_x1_76, mul_x1_77, mul_x1_78, mul_x1_79, mul_x1_80, mul_x1_81, mul_x1_82, mul_x1_83, mul_x1_84, mul_x1_85, mul_x1_86, mul_x1_87, mul_x1_88, mul_x1_89, mul_x1_90, mul_x1_91, mul_x1_92, mul_x1_93, mul_x1_94, mul_x1_95, mul_x1_96, mul_x1_97, mul_x1_98, mul_x1_99, mul_x1_100, mul_x1_101, mul_x1_102, mul_x1_103, mul_x1_104, mul_x1_105, mul_x1_106, mul_x1_107, mul_x1_108, mul_x1_109, mul_x1_110, mul_x1_111, mul_x1_112, mul_x1_113, mul_x1_114, mul_x1_115, mul_x1_116, mul_x1_117, mul_x1_118, mul_x1_119, mul_x1_120, mul_x1_121, mul_x1_122, mul_x1_123, mul_x1_124, mul_x1_125, mul_x1_126, mul_x1_127, mul_x1_128, mul_x1_129, mul_x1_130, mul_x1_131, mul_x1_132, mul_x1_133, mul_x1_134, mul_x1_135, mul_x1_136, mul_x1_137, mul_x1_138, mul_x1_139, mul_x1_140, mul_x1_141, mul_x1_142, mul_x1_143, mul_x1_144, mul_x1_145, mul_x1_146, mul_x1_147, mul_x1_148, mul_x1_149, mul_x1_150, mul_x1_151, mul_x1_152, mul_x1_153, mul_x1_154, mul_x1_155, mul_x1_156, mul_x1_157, mul_x1_158, mul_x1_159, mul_x1_160, mul_x1_161, mul_x1_162, mul_x1_163, mul_x1_164, mul_x1_165, mul_x1_166, mul_x1_167, mul_x1_168, mul_x1_169, mul_x1_170, mul_x1_171, mul_x1_172, mul_x1_173, mul_x1_174, mul_x1_175, mul_x1_176, mul_x1_177, mul_x1_178, mul_x1_179, mul_x1_180, mul_x1_181, mul_x1_182, mul_x1_183, mul_x1_184, mul_x1_185, mul_x1_186, mul_x1_187, mul_x1_188, mul_x1_189, mul_x1_190, mul_x1_191, mul_x1_192, mul_x1_193, mul_x1_194, mul_x1_195, mul_x1_196, mul_x1_197, mul_x1_198, mul_x1_199, mul_x1_200, mul_x1_201, mul_x1_202, mul_x1_203, mul_x1_204, mul_x1_205, mul_x1_206, mul_x1_207, mul_x1_208, mul_x1_209, mul_x1_210, mul_x1_211, mul_x1_212, mul_x1_213, mul_x1_214, mul_x1_215, mul_x1_216, mul_x1_217, mul_x1_218, mul_x1_219, mul_x1_220, mul_x1_221, mul_x1_222, mul_x1_223, mul_x1_224, mul_x1_225, mul_x1_226, mul_x1_227, mul_x1_228, mul_x1_229, mul_x1_230, mul_x1_231, mul_x1_232, mul_x1_233, mul_x1_234, mul_x1_235, mul_x1_236, mul_x1_237, mul_x1_238, mul_x1_239, mul_x1_240, mul_x1_241, mul_x1_242, mul_x1_243, mul_x1_244, mul_x1_245, mul_x1_246, mul_x1_247, mul_x1_248, mul_x1_249, mul_x1_250, mul_x1_251, mul_x1_252, mul_x1_253, mul_x1_254, mul_x1_255

## Related Code Snippets

```c
static void
raidz_rec_pqr_abd(void **t, const size_t tsize, void **c,
    const unsigned * const mul)
{
	...

	for (; x < xend; x += REC_PQR_STRIDE, y += REC_PQR_STRIDE,
	    z += REC_PQR_STRIDE, p += REC_PQR_STRIDE, q += REC_PQR_STRIDE,
	    r += REC_PQR_STRIDE) {
		LOAD(x, REC_PQR_X);
		LOAD(y, REC_PQR_Y);
		LOAD(z, REC_PQR_Z);

		XOR_ACC(p, REC_PQR_X);
		XOR_ACC(q, REC_PQR_Y);
		XOR_ACC(r, REC_PQR_Z);

		/* Save Pxyz and Qxyz */
		COPY(REC_PQR_X, REC_PQR_XS);
		COPY(REC_PQR_Y, REC_PQR_YS);

		/* Calc X */
		MUL(mul[MUL_PQR_XP], REC_PQR_X);	/* Xp = Pxyz * xp   */
		MUL(mul[MUL_PQR_XQ], REC_PQR_Y);	/* Xq = Qxyz * xq   */
		...
        }
    ...
}
```

```c
static const mul_fn_ptr_t __attribute__((aligned(256)))
gf_x1_mul_fns[256] = {
	mul_x1_0, mul_x1_1, mul_x1_2, mul_x1_3, mul_x1_4, mul_x1_5,
	mul_x1_6, mul_x1_7, mul_x1_8, mul_x1_9, mul_x1_10, mul_x1_11,
	mul_x1_12, mul_x1_13, mul_x1_14, mul_x1_15, mul_x1_16, mul_x1_17,
	mul_x1_18, mul_x1_19, mul_x1_20, mul_x1_21, mul_x1_22, mul_x1_23,
	mul_x1_24, mul_x1_25, mul_x1_26, mul_x1_27, mul_x1_28, mul_x1_29,
	mul_x1_30, mul_x1_31, mul_x1_32, mul_x1_33, mul_x1_34, mul_x1_35,
	mul_x1_36, mul_x1_37, mul_x1_38, mul_x1_39, mul_x1_40, mul_x1_41,
	mul_x1_42, mul_x1_43, mul_x1_44, mul_x1_45, mul_x1_46, mul_x1_47,
	mul_x1_48, mul_x1_49, mul_x1_50, mul_x1_51, mul_x1_52, mul_x1_53,
	mul_x1_54, mul_x1_55, mul_x1_56, mul_x1_57, mul_x1_58, mul_x1_59,
	mul_x1_60, mul_x1_61, mul_x1_62, mul_x1_63, mul_x1_64, mul_x1_65,
	mul_x1_66, mul_x1_67, mul_x1_68, mul_x1_69, mul_x1_70, mul_x1_71,
	mul_x1_72, mul_x1_73, mul_x1_74, mul_x1_75, mul_x1_76, mul_x1_77,
	mul_x1_78, mul_x1_79, mul_x1_80, mul_x1_81, mul_x1_82, mul_x1_83,
	mul_x1_84, mul_x1_85, mul_x1_86, mul_x1_87, mul_x1_88, mul_x1_89,
	mul_x1_90, mul_x1_91, mul_x1_92, mul_x1_93, mul_x1_94, mul_x1_95,
	mul_x1_96, mul_x1_97, mul_x1_98, mul_x1_99, mul_x1_100, mul_x1_101,
	mul_x1_102, mul_x1_103, mul_x1_104, mul_x1_105, mul_x1_106, mul_x1_107,
	mul_x1_108, mul_x1_109, mul_x1_110, mul_x1_111, mul_x1_112, mul_x1_113,
	mul_x1_114, mul_x1_115, mul_x1_116, mul_x1_117, mul_x1_118, mul_x1_119,
	mul_x1_120, mul_x1_121, mul_x1_122, mul_x1_123, mul_x1_124, mul_x1_125,
	mul_x1_126, mul_x1_127, mul_x1_128, mul_x1_129, mul_x1_130, mul_x1_131,
	mul_x1_132, mul_x1_133, mul_x1_134, mul_x1_135, mul_x1_136, mul_x1_137,
	mul_x1_138, mul_x1_139, mul_x1_140, mul_x1_141, mul_x1_142, mul_x1_143,
	mul_x1_144, mul_x1_145, mul_x1_146, mul_x1_147, mul_x1_148, mul_x1_149,
	mul_x1_150, mul_x1_151, mul_x1_152, mul_x1_153, mul_x1_154, mul_x1_155,
	mul_x1_156, mul_x1_157, mul_x1_158, mul_x1_159, mul_x1_160, mul_x1_161,
	mul_x1_162, mul_x1_163, mul_x1_164, mul_x1_165, mul_x1_166, mul_x1_167,
	mul_x1_168, mul_x1_169, mul_x1_170, mul_x1_171, mul_x1_172, mul_x1_173,
	mul_x1_174, mul_x1_175, mul_x1_176, mul_x1_177, mul_x1_178, mul_x1_179,
	mul_x1_180, mul_x1_181, mul_x1_182, mul_x1_183, mul_x1_184, mul_x1_185,
	mul_x1_186, mul_x1_187, mul_x1_188, mul_x1_189, mul_x1_190, mul_x1_191,
	mul_x1_192, mul_x1_193, mul_x1_194, mul_x1_195, mul_x1_196, mul_x1_197,
	mul_x1_198, mul_x1_199, mul_x1_200, mul_x1_201, mul_x1_202, mul_x1_203,
	mul_x1_204, mul_x1_205, mul_x1_206, mul_x1_207, mul_x1_208, mul_x1_209,
	mul_x1_210, mul_x1_211, mul_x1_212, mul_x1_213, mul_x1_214, mul_x1_215,
	mul_x1_216, mul_x1_217, mul_x1_218, mul_x1_219, mul_x1_220, mul_x1_221,
	mul_x1_222, mul_x1_223, mul_x1_224, mul_x1_225, mul_x1_226, mul_x1_227,
	mul_x1_228, mul_x1_229, mul_x1_230, mul_x1_231, mul_x1_232, mul_x1_233,
	mul_x1_234, mul_x1_235, mul_x1_236, mul_x1_237, mul_x1_238, mul_x1_239,
	mul_x1_240, mul_x1_241, mul_x1_242, mul_x1_243, mul_x1_244, mul_x1_245,
	mul_x1_246, mul_x1_247, mul_x1_248, mul_x1_249, mul_x1_250, mul_x1_251,
	mul_x1_252, mul_x1_253, mul_x1_254, mul_x1_255
};

#define	MUL(c, r...) 							\
{									\
	switch (REG_CNT(r)) {						\
	case 2:								\
		COPY(r, _mul_x2_in);					\
		gf_x2_mul_fns[c]();					\
		COPY(_mul_x2_acc, r);					\
		break;							\
	case 1:								\
		COPY(r, _mul_x1_in);					\
		gf_x1_mul_fns[c]();					\
		COPY(_mul_x1_acc, r);					\
		break;							\
	default:							\
		VERIFY(0);						\
	}								\
}
```