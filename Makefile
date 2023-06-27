
all: do_component

do_component:
	cd component && ${MAKE}
