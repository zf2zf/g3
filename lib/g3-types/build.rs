/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025 ByteDance and/or its affiliates.
 */

use std::env;

fn gen_openssl_flags() {
    println!("cargo:rustc-check-cfg=cfg(libressl)");
    println!("cargo:rustc-check-cfg=cfg(tongsuo)");
    println!("cargo:rustc-check-cfg=cfg(boringssl)");
    println!("cargo:rustc-check-cfg=cfg(awslc)");
    println!("cargo:rustc-check-cfg=cfg(ossl111)");

    if env::var("DEP_OPENSSL_LIBRESSL").is_ok() {
        println!("cargo:rustc-cfg=libressl");
    }

    if env::var("DEP_OPENSSL_TONGSUO").is_ok() {
        println!("cargo:rustc-cfg=tongsuo");
    }

    if env::var("DEP_OPENSSL_BORINGSSL").is_ok() {
        println!("cargo:rustc-cfg=boringssl");
    }

    if env::var("DEP_OPENSSL_AWSLC").is_ok() {
        println!("cargo:rustc-cfg=awslc");
    }

    if let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        // SSL_CIPHER_get_protocol_id 从 OpenSSL 1.1.1 起才是公开接口
        let version = u64::from_str_radix(&version, 16).unwrap();

        if version >= 0x1_01_01_00_0 {
            println!("cargo:rustc-cfg=ossl111");
        }
    }
}

fn main() {
    gen_openssl_flags();
}
