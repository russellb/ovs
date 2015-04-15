# ovn-northbound
bin_PROGRAMS += ovn/northbound/ovn-northbound
ovn_northbound_ovn_northbound_SOURCES = ovn/northbound/ovn-northbound.c
ovn_northbound_ovn_northbound_LDADD = ovn/libovn.la ovsdb/libovsdb.la lib/libopenvswitch.la
