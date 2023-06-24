include(CheckStructHasMember)

CHECK_STRUCT_HAS_MEMBER("struct sockaddr_in" "sin_len" "sys/types.h;netinet/in.h" HAVE_SOCKADDR_IN_SIN_LEN)
 
CHECK_STRUCT_HAS_MEMBER("struct sockaddr_in6" "sin6_len" "sys/types.h;netinet/in.h" HAVE_SOCKADDR_IN6_SIN6_LEN)
