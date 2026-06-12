idf_component_register(SRCS "dsmr.cpp"
                             "dsmr_crypto_impl.cpp"
                             "dsmr_stoen.cpp"
                             "fields.cpp"
                       INCLUDE_DIRS "."
                       REQUIRES mbedtls)
