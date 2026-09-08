# SPHINCS+-SHA2-128s (robust) 纯软件库组件
idf_component_register(
    SRCS "sha256.c"
         "thash.c"
         "wots.c"
         "fors.c"
         "merkle.c"
         "sphincsplus.c"
    INCLUDE_DIRS "include"
)