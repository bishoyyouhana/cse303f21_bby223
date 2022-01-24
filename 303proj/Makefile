# Build a client and server using the student's files

# The executables will have the suffix .exe
EXESUFFIX = exe

# Names for building the client:
CLIENT_MAIN     = client
CLIENT_CXX      =
CLIENT_COMMON   = my_crypto crypto err file net
CLIENT_PROVIDED = client requests #1 files was changed throughout the class by prof.

# Names for building the server
SERVER_MAIN     = server
SERVER_CXX      = my_storage my_functable my_pool my_quota_tracker my_mru
SERVER_COMMON   =
SERVER_PROVIDED = server parsing helpers persist responses concurrenthashmap_factories crypto err file net my_crypto
#first 6 files was changed throughout the class by prof.

# Names for building shared objects
SO_CXX    = all_keys odd_key_vals invalid1 invalid2 broken1 broken2
SO_COMMON = 

# NB: This Makefile does not add extra CXXFLAGS

# Pull in the common build rules
include common.mk