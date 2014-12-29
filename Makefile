
MODULE_big = restgres
OBJS = restgres.o util.o master.o backend.o 
OBJS += bgwutil.o response_phrase.o routes.o route_funcs.o jsonbuf.o 
OBJS += root_route.o databases_route.o db_route.o roles_route.o role_route.o
OBJS += schemas_route.o schema_route.o
SHLIB_LINK += -levent
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
override CC += -std=c99 -ggdb -Og -fno-omit-frame-pointer

pg_restart: all
	sudo service postgresql restart