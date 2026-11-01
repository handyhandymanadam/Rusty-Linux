    # rsa_check_payload
    mut payload-one-ok         'if mpi_cmp_ui(x, 1) <= 0 {' 'if mpi_cmp_ui(x, 1) < 0 {'
    mut payload-zero-ok        'if mpi_cmp_ui(x, 1) <= 0 {' 'if mpi_cmp_ui(x, 0) < 0 {'
    mut payload-nm1-ok         'mpi_cmp(x, n1) >= 0 {' 'mpi_cmp(x, n1) > 0 {'
    mut payload-n-ok           'mpi_cmp(x, n1) >= 0 {' 'mpi_cmp(x, n1) > 1 {'
    mut payload-subui-ignored  'if mpi_sub_ui(n1, n, 1) != 0 || mpi_cmp(x, n1) >= 0 {' 'let _ = mpi_sub_ui(n1, n, 1);
        if mpi_cmp(x, n1) >= 0 {'
    mut payload-n1-leak-ok     'mpi_free(n1);
            return -EINVAL;' 'return -EINVAL;'
    mut payload-n1-leak-final  'mpi_free(n1);
    }
    0' 'let _ = n1;
    }
    0'
    # RSAEP
    mut enc-uses-d             'mpi_powm(c, m, (*key).e, (*key).n)' 'mpi_powm(c, m, (*key).d, (*key).n)'
    mut enc-wrong-modulus      'mpi_powm(c, m, (*key).e, (*key).n)' 'mpi_powm(c, m, (*key).e, (*key).p)'
    mut enc-check-vs-p         'if rsa_check_payload(m, (*key).n) != 0 {' 'if rsa_check_payload(m, (*key).p) != 0 {'
    mut enc-check-ignored      'if rsa_check_payload(m, (*key).n) != 0 {
            return -EINVAL;
        }' 'let _ = rsa_check_payload(m, (*key).n);'
    mut enc-check-errno        'if rsa_check_payload(m, (*key).n) != 0 {
            return -EINVAL;' 'if rsa_check_payload(m, (*key).n) != 0 {
            return -EBADMSG;'
    # RSADP / CRT
    mut crt-check-ignored      'if rsa_check_payload(c, (*key).n) != 0 {
            return -EINVAL;
        }' 'let _ = rsa_check_payload(c, (*key).n);'
    mut crt-dp-dq-swapped      'mpi_powm(m_or_m1_or_h, c, (*key).dp, (*key).p)' 'mpi_powm(m_or_m1_or_h, c, (*key).dq, (*key).p)'
    mut crt-m2-modulus-p       'mpi_powm(m2, c, (*key).dq, (*key).q)' 'mpi_powm(m2, c, (*key).dq, (*key).p)'
    mut crt-sub-reversed       'mpi_sub(m12_or_qh, m_or_m1_or_h, m2)' 'mpi_sub(m12_or_qh, m2, m_or_m1_or_h)'
    mut crt-mulm-mod-q         'mpi_mulm(m_or_m1_or_h, m12_or_qh, (*key).qinv, (*key).p)' 'mpi_mulm(m_or_m1_or_h, m12_or_qh, (*key).qinv, (*key).q)'
    mut crt-qinv-is-dq         'mpi_mulm(m_or_m1_or_h, m12_or_qh, (*key).qinv, (*key).p)' 'mpi_mulm(m_or_m1_or_h, m12_or_qh, (*key).dq, (*key).p)'
    mut crt-mul-by-p           'mpi_mul(m12_or_qh, (*key).q, m_or_m1_or_h)' 'mpi_mul(m12_or_qh, (*key).p, m_or_m1_or_h)'
    mut crt-addm-mod-p         'mpi_addm(m_or_m1_or_h, m2, m12_or_qh, (*key).n)' 'mpi_addm(m_or_m1_or_h, m2, m12_or_qh, (*key).p)'
    mut crt-addm-wrong-term    'mpi_addm(m_or_m1_or_h, m2, m12_or_qh, (*key).n)' 'mpi_addm(m_or_m1_or_h, m12_or_qh, m12_or_qh, (*key).n)'
    mut crt-m2-leak            'mpi_free(m12_or_qh);
        mpi_free(m2);' 'mpi_free(m12_or_qh);'
    mut crt-m12-leak           'mpi_free(m12_or_qh);
        mpi_free(m2);' 'mpi_free(m2);'
    mut crt-error-swallowed    'ret = mpi_powm(m2, c, (*key).dq, (*key).q);
                if ret == 0 {' 'ret = mpi_powm(m2, c, (*key).dq, (*key).q);
                if true {'
    mut crt-sub-error-ignored  'ret = mpi_sub(m12_or_qh, m_or_m1_or_h, m2);
                    if ret == 0 {' 'ret = mpi_sub(m12_or_qh, m_or_m1_or_h, m2);
                    if true {'
    mut crt-alloc-no-check     'if !m2.is_null() && !m12_or_qh.is_null() {' 'if !m2.is_null() || !m12_or_qh.is_null() {'
    # request bodies
    mut enc-key-test-and       'if (*pkey).n.is_null() || (*pkey).e.is_null() {' 'if (*pkey).n.is_null() && (*pkey).e.is_null() {'
    mut enc-key-test-d         'if (*pkey).n.is_null() || (*pkey).e.is_null() {' 'if (*pkey).n.is_null() || (*pkey).d.is_null() {'
    mut enc-m-leak             'mpi_free(m);
        ret
    }
}

/// `rsa_enc()`' 'ret
    }
}

/// `rsa_enc()`'
    mut enc-c-leak             'let ret = enc_body(pkey, c, src, src_len, dst, dst_len);
        mpi_free(c);' 'let ret = enc_body(pkey, c, src, src_len, dst, dst_len);'
    mut enc-sign-wrong         'if ret == 0 && sign < 0 {
                ret = -EBADMSG;' 'if ret == 0 && sign <= 0 {
                ret = -EBADMSG;'
    mut enc-sign-ignored       'if ret == 0 && sign < 0 {
                ret = -EBADMSG;' 'if false && sign < 0 {
                ret = -EBADMSG;'
    mut enc-write-error-lost   'ret = mpi_write_to_sgl(c, dst, dst_len, &mut sign);' 'let _ = mpi_write_to_sgl(c, dst, dst_len, &mut sign);'
    mut enc-read-fail-code     'let m = mpi_read_raw_from_sgl(src, src_len);
        if m.is_null() {
            return -ENOMEM;
        }
        let mut sign: c_int = 0;
        let mut ret = rsa_enc_core' 'let m = mpi_read_raw_from_sgl(src, src_len);
        if m.is_null() {
            return -EINVAL;
        }
        let mut sign: c_int = 0;
        let mut ret = rsa_enc_core'
    mut dec-key-test-e         'if (*pkey).n.is_null() || (*pkey).d.is_null() {' 'if (*pkey).n.is_null() || (*pkey).e.is_null() {'
    mut dec-key-test-and       'if (*pkey).n.is_null() || (*pkey).d.is_null() {' 'if (*pkey).n.is_null() && (*pkey).d.is_null() {'
    mut dec-c-leak             'mpi_free(c);
        ret
    }
}

/// `rsa_dec()`' 'ret
    }
}

/// `rsa_dec()`'
    mut dec-m-leak             'let ret = dec_body(pkey, m, src, src_len, dst, dst_len);
        mpi_free(m);' 'let ret = dec_body(pkey, m, src, src_len, dst, dst_len);'
    mut dec-sign-wrong         'if ret == 0 && sign < 0 {' 'if ret == 0 && sign <= 0 {' 2
    mut dec-sign-ignored       'if ret == 0 && sign < 0 {' 'if false && sign < 0 {' 2
    mut dec-writes-c           'ret = mpi_write_to_sgl(m, dst, dst_len, &mut sign);' 'ret = mpi_write_to_sgl(c, dst, dst_len, &mut sign);'
    # key loading
    mut set-no-free-old        'let mut raw: RsaRawKey = core::mem::zeroed();
        // Free the old MPI key if any
        rsa_rs_free_key(mpi_key);
        let ret = rsa_parse_pub_key' 'let mut raw: RsaRawKey = core::mem::zeroed();
        let ret = rsa_parse_pub_key'
    mut set-priv-no-free-old   'let mut raw: RsaRawKey = core::mem::zeroed();
        // Free the old MPI key if any
        rsa_rs_free_key(mpi_key);
        let ret = rsa_parse_priv_key' 'let mut raw: RsaRawKey = core::mem::zeroed();
        let ret = rsa_parse_priv_key'
    mut set-pub-order          '(*mpi_key).e = mpi_read_raw_data(raw.e as *const c_void, raw.e_sz);
        if (*mpi_key).e.is_null() {
            rsa_rs_free_key(mpi_key);
            return -ENOMEM;
        }
        (*mpi_key).n = mpi_read_raw_data(raw.n as *const c_void, raw.n_sz);' '(*mpi_key).n = mpi_read_raw_data(raw.n as *const c_void, raw.n_sz);
        if (*mpi_key).n.is_null() {
            rsa_rs_free_key(mpi_key);
            return -ENOMEM;
        }
        (*mpi_key).e = mpi_read_raw_data(raw.e as *const c_void, raw.e_sz);'
    mut set-pub-no-free-on-fail '(*mpi_key).n = mpi_read_raw_data(raw.n as *const c_void, raw.n_sz);
        if (*mpi_key).n.is_null() {
            rsa_rs_free_key(mpi_key);
            return -ENOMEM;' '(*mpi_key).n = mpi_read_raw_data(raw.n as *const c_void, raw.n_sz);
        if (*mpi_key).n.is_null() {
            return -ENOMEM;'
    mut set-pub-fail-code      '(*mpi_key).n = mpi_read_raw_data(raw.n as *const c_void, raw.n_sz);
        if (*mpi_key).n.is_null() {
            rsa_rs_free_key(mpi_key);
            return -ENOMEM;' '(*mpi_key).n = mpi_read_raw_data(raw.n as *const c_void, raw.n_sz);
        if (*mpi_key).n.is_null() {
            rsa_rs_free_key(mpi_key);
            return -EINVAL;'
    mut set-parse-error-lost   'let ret = rsa_parse_pub_key(&mut raw, key, keylen);
        if ret != 0 {
            return ret;
        }' 'let ret = rsa_parse_pub_key(&mut raw, key, keylen);
        if ret != 0 {
            return -EINVAL;
        }'
    mut set-priv-field-order   'field!(d, d_sz);
        field!(e, e_sz);' 'field!(e, e_sz);
        field!(d, d_sz);'
    mut set-priv-last-field    'field!(qinv, qinv_sz);' 'let _ = ();'
    mut set-priv-p-q-swapped   'field!(p, p_sz);
        field!(q, q_sz);' 'field!(q, q_sz);
        field!(p, p_sz);'
    mut size-shift             'mpi_get_size((*mpi_key).n).wrapping_shl(3)' 'mpi_get_size((*mpi_key).n).wrapping_shl(2)'
    mut size-no-free           'if rsa_check_key_length(mpi_get_size((*mpi_key).n).wrapping_shl(3)) != 0 {
            rsa_rs_free_key(mpi_key);
            return -EINVAL;
        }' 'if rsa_check_key_length(mpi_get_size((*mpi_key).n).wrapping_shl(3)) != 0 {
            return -EINVAL;
        }'
    mut size-accepts-1536      '512 | 1024 | 1536 => {' '512 | 1024 => {'
    mut size-accepts-4096      '2048 | 3072 | 4096 => 0,' '2048 | 3072 => 0,'
    mut size-accepts-1152      '2048 | 3072 | 4096 => 0,' '2048 | 3072 | 4096 | 1152 => 0,'
    mut size-fips-ignored      'if unsafe { fips_enabled } != 0 {' 'if false {'
    mut fips-exp-odd           'if mpi_test_bit(e, 0) == 0 {' 'if mpi_test_bit(e, 0) != 0 {'
    # `<= 65536` vs `< 65536` and `>= 2^256` vs `> 2^256` differ only at e == 2^16 / 2^256, both EVEN, which the odd test above rejects first: equivalent
    mut fips-exp-low           'if mpi_cmp_ui(e, 65536) <= 0 {' 'if mpi_cmp_ui(e, 65536) < 0 {' 1 equiv
    mut fips-exp-high          'if mpi_cmp(e, e_max) >= 0 {' 'if mpi_cmp(e, e_max) > 0 {' 1 equiv
    mut fips-exp-bit           'mpi_set_bit(e_max, 256)' 'mpi_set_bit(e_max, 255)'
    mut fips-exp-no-check      'if fips_enabled != 0 && rsa_check_exponent_fips((*mpi_key).e) != 0 {' 'if fips_enabled != 0 && rsa_check_exponent_fips((*mpi_key).e) != 0 && false {'
    # size / free
    mut max-size-bits          '(*a).nlimbs.wrapping_mul(8) as c_uint' '(*a).nlimbs.wrapping_mul(4) as c_uint'
    mut free-qinv-missing      'mpi_free((*key).qinv);
        (*key).d' '(*key).d'
    mut free-dq-missing        'mpi_free((*key).dq);' ''
    mut free-no-null           '(*key).qinv = core::ptr::null_mut();
    }' 'let _ = ();
    }'
    mut free-n-missing         'mpi_free((*key).n);' ''
