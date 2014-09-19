
MODULE_big = restgres
OBJS = restgres.o util.o master.o backend.o bgwutil.o sendrecvfd.o response_phrase.o routes.o root_route.o jsonbuf.o
SHLIB_LINK += -levent
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
override CC += -std=c99 -ggdb -Og -fno-omit-frame-pointer
