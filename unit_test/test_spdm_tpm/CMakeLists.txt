cmake_minimum_required(VERSION 3.16)

add_executable(test_spdm_tpm)

target_include_directories(test_spdm_tpm
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/unit_test/include
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_tpm
        ${CMAKE_BINARY_DIR}/os_stub/spdm_device_secret_lib_tpm
        ${LIBSPDM_DIR}/os_stub/spdm_cert_verify_callback_sample
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub
)

target_sources(test_spdm_tpm
    PRIVATE
        test_spdm_tpm.c
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/support.c
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/algo.c
)

target_link_libraries(test_spdm_tpm
    PRIVATE
        memlib
        debuglib
        spdm_crypt_lib
        ${CRYPTO_LIB_PATHS}
        cryptlib_${CRYPTO}
        rnglib
        malloclib
        cmockalib
        spdm_device_secret_lib_tpm
        spdm_cert_verify_callback_sample
        spdm_crypt_ext_lib
        spdm_common_lib
        spdm_secured_message_lib
        tss2-esys
        tss2-sys
        tss2-mu
        tss2-tctildr
        tss2-rc
)

# Intercept only the collector's TPM I/O; other tests retain the real backend.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TOOLCHAIN MATCHES "GCC|CLANG")
    target_sources(test_spdm_tpm PRIVATE
        test_tpm_pcr_collection.c
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_tpm/meas.c)
    target_compile_definitions(test_spdm_tpm PRIVATE LIBSPDM_TPM_COLLECTION_TEST=1)
    set_source_files_properties(
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_tpm/meas.c
        PROPERTIES COMPILE_OPTIONS -fno-lto)
    target_link_options(test_spdm_tpm PRIVATE
        -Wl,--wrap=libspdm_tpm_device_init
        -Wl,--wrap=libspdm_tpm_read_pcrs
        -Wl,--wrap=libspdm_tpm_quote
        -Wl,--wrap=libspdm_tpm_get_pub_key_handle)
endif()
