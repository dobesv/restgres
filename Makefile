
MODULE_big = restgres
OBJS = restgres.o
SHLIB_LINK += -levent
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
override CC += -std=c99 -ggdb -Og -fno-omit-frame-pointer
