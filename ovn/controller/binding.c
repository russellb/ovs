/* Copyright (c) 2015, 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "binding.h"

#include "lib/bitmap.h"
#include "lib/hmap.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn-controller.h"

VLOG_DEFINE_THIS_MODULE(binding);

static struct sset all_lports = SSET_INITIALIZER(&all_lports);

static bool process_full_binding = false;

void
binding_reset_processing(void)
{
    process_full_binding = true;
}

void
binding_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_bridges);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_interfaces);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_external_ids);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_ingress_policing_rate);
    ovsdb_idl_add_column(ovs_idl,
                         &ovsrec_interface_col_ingress_policing_burst);
}

static bool
get_local_iface_ids(const struct ovsrec_bridge *br_int, struct shash *lports)
{
    int i;
    bool changed = false;

    /* A local copy of ports that we can use to compare with the persisted
     * list. */
    struct shash local_ports = SHASH_INITIALIZER(&local_ports);

    for (i = 0; i < br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = br_int->ports[i];
        const char *iface_id;
        int j;

        if (!strcmp(port_rec->name, br_int->name)) {
            continue;
        }

        for (j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec;

            iface_rec = port_rec->interfaces[j];
            iface_id = smap_get(&iface_rec->external_ids, "iface-id");
            if (!iface_id) {
                continue;
            }
            shash_add(&local_ports, iface_id, iface_rec);
            if (!shash_find(lports, iface_id)) {
                shash_add(lports, iface_id, iface_rec);
                changed = true;
            }
            if (!sset_find(&all_lports, iface_id)) {
                sset_add(&all_lports, iface_id);
                binding_reset_processing();
            }
        }
    }
    struct shash_node *iter, *next;
    SHASH_FOR_EACH_SAFE(iter, next, lports) {
        if (!shash_find_and_delete(&local_ports, iter->name)) {
            shash_delete(lports, iter);
            changed = true;
        }
    }
    shash_destroy(&local_ports);
    return changed;
}

/* Contains "struct local_datpath" nodes whose hash values are the
 * row uuids of datapaths with at least one local port binding. */
static struct hmap local_datapaths_by_uuid =
    HMAP_INITIALIZER(&local_datapaths_by_uuid);

static struct local_datapath *
local_datapath_lookup_by_uuid(struct hmap *hmap_p, const struct uuid *uuid)
{
    struct local_datapath *ld;
    HMAP_FOR_EACH_WITH_HASH(ld, uuid_hmap_node, uuid_hash(uuid), hmap_p) {
        if (uuid_equals(ld->uuid, uuid)) {
            return ld;
        }
    }
    return NULL;
}

static void
remove_local_datapath(struct hmap *local_datapaths, struct local_datapath *ld)
{
    if (ld->logical_port) {
        sset_find_and_delete(&all_lports, ld->logical_port);
        free(ld->logical_port);
        ld->logical_port = NULL;
    }
    hmap_remove(local_datapaths, &ld->hmap_node);
    hmap_remove(&local_datapaths_by_uuid, &ld->uuid_hmap_node);
    free(ld);
}

static void
remove_local_datapath_by_binding(struct hmap *local_datapaths,
                                 const struct sbrec_port_binding *binding_rec)
{
    const struct uuid *uuid = &binding_rec->header_.uuid;
    struct local_datapath *ld = local_datapath_lookup_by_uuid(local_datapaths,
                                                              uuid);
    if (ld) {
        remove_local_datapath(local_datapaths, ld);
    } else {
        struct local_datapath *ld;
        HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
            if (ld->localnet_port == binding_rec) {
                ld->localnet_port = NULL;
            }
        }
    }
}

static void
add_local_datapath(struct hmap *local_datapaths,
        const struct sbrec_port_binding *binding_rec,
        const struct uuid *uuid)
{
    if (get_local_datapath(local_datapaths,
                           binding_rec->datapath->tunnel_key)) {
        return;
    }

    struct local_datapath *ld = xzalloc(sizeof *ld);
    ld->logical_port = xstrdup(binding_rec->logical_port);
    ld->uuid = &binding_rec->header_.uuid;
    hmap_insert(local_datapaths, &ld->hmap_node,
                binding_rec->datapath->tunnel_key);
    hmap_insert(&local_datapaths_by_uuid, &ld->uuid_hmap_node,
                uuid_hash(uuid));
}

static void
update_qos(const struct ovsrec_interface *iface_rec,
           const struct sbrec_port_binding *pb)
{
    int rate = smap_get_int(&pb->options, "policing_rate", 0);
    int burst = smap_get_int(&pb->options, "policing_burst", 0);

    ovsrec_interface_set_ingress_policing_rate(iface_rec, MAX(0, rate));
    ovsrec_interface_set_ingress_policing_burst(iface_rec, MAX(0, burst));
}

static void
consider_local_datapath(struct controller_ctx *ctx, struct shash *lports,
                        const struct sbrec_chassis *chassis_rec,
                        const struct sbrec_port_binding *binding_rec,
                        struct hmap *local_datapaths)
{
    const struct ovsrec_interface *iface_rec
        = shash_find_data(lports, binding_rec->logical_port);
    if (iface_rec
        || (binding_rec->parent_port && binding_rec->parent_port[0] &&
            sset_contains(&all_lports, binding_rec->parent_port))) {
        if (binding_rec->parent_port && binding_rec->parent_port[0]) {
            /* Add child logical port to the set of all local ports. */
            sset_add(&all_lports, binding_rec->logical_port);
        }
        add_local_datapath(local_datapaths, binding_rec,
                           &binding_rec->header_.uuid);
        if (iface_rec && ctx->ovs_idl_txn) {
            update_qos(iface_rec, binding_rec);
        }
        if (binding_rec->chassis == chassis_rec) {
            return;
        }
        if (ctx->ovnsb_idl_txn) {
            if (binding_rec->chassis) {
                VLOG_INFO("Changing chassis for lport %s from %s to %s.",
                          binding_rec->logical_port,
                          binding_rec->chassis->name,
                          chassis_rec->name);
            } else {
                VLOG_INFO("Claiming lport %s for this chassis.",
                          binding_rec->logical_port);
            }
            sbrec_port_binding_set_chassis(binding_rec, chassis_rec);
        }
    } else if (!strcmp(binding_rec->type, "l2gateway")
               && binding_rec->chassis == chassis_rec) {
        /* A locally bound gateway port.
         *
         * ovn-controller does not bind gateway ports itself.
         * Choosing a chassis for a gateway port is left
         * up to an entity external to OVN. */
        sset_add(&all_lports, binding_rec->logical_port);
        add_local_datapath(local_datapaths, binding_rec,
                           &binding_rec->header_.uuid);
    } else if (chassis_rec && binding_rec->chassis == chassis_rec
               && strcmp(binding_rec->type, "gateway")) {
        if (ctx->ovnsb_idl_txn) {
            VLOG_INFO("Releasing lport %s from this chassis.",
                      binding_rec->logical_port);
            sbrec_port_binding_set_chassis(binding_rec, NULL);
        }
    } else if (!binding_rec->chassis
               && !strcmp(binding_rec->type, "localnet")) {
        /* Localnet ports will never be bound to a chassis, but we want
         * to list them in all_lports because we want to allocate
         * a conntrack zone ID for each one, as we'll be creating
         * a patch port for each one. */
        sset_add(&all_lports, binding_rec->logical_port);
    }
}

/* We persist lports because we need to know when it changes to
 * handle ports going away correctly in the binding record. */
static struct shash lports = SHASH_INITIALIZER(&lports);

void
binding_run(struct controller_ctx *ctx, const struct ovsrec_bridge *br_int,
            const char *chassis_id, struct hmap *local_datapaths)
{
    const struct sbrec_chassis *chassis_rec;
    const struct sbrec_port_binding *binding_rec;

    chassis_rec = get_chassis(ctx->ovnsb_idl, chassis_id);
    if (!chassis_rec) {
        return;
    }

    if (br_int) {
        if (get_local_iface_ids(br_int, &lports)) {
            process_full_binding = true;
        }
    } else {
        /* We have no integration bridge, therefore no local logical ports.
         * We'll remove our chassis from all port binding records below. */
        process_full_binding = true;
    }

    /* Run through each binding record to see if it is resident on this
     * chassis and update the binding accordingly.  This includes both
     * directly connected logical ports and children of those ports. */
    if (process_full_binding) {
        struct hmap keep_local_datapath_by_uuid =
            HMAP_INITIALIZER(&keep_local_datapath_by_uuid);
        SBREC_PORT_BINDING_FOR_EACH(binding_rec, ctx->ovnsb_idl) {
            consider_local_datapath(ctx, &lports, chassis_rec, binding_rec,
                                    local_datapaths);
            struct local_datapath *ld = xzalloc(sizeof *ld);
            ld->uuid = &binding_rec->header_.uuid;
            hmap_insert(&keep_local_datapath_by_uuid, &ld->uuid_hmap_node,
                        uuid_hash(ld->uuid));
        }
        struct local_datapath *old_ld, *next;
        HMAP_FOR_EACH_SAFE (old_ld, next, hmap_node, local_datapaths) {
            if (!local_datapath_lookup_by_uuid(&keep_local_datapath_by_uuid,
                                               old_ld->uuid)) {
                remove_local_datapath(local_datapaths, old_ld);
            }
        }
        hmap_destroy(&keep_local_datapath_by_uuid);
        process_full_binding = false;
    } else {
        SBREC_PORT_BINDING_FOR_EACH_TRACKED(binding_rec, ctx->ovnsb_idl) {
            if (sbrec_port_binding_is_deleted(binding_rec)) {
                remove_local_datapath_by_binding(local_datapaths, binding_rec);
            } else {
                consider_local_datapath(ctx, &lports, chassis_rec, binding_rec,
                                        local_datapaths);
            }
        }
    }
}

/* Returns true if the database is all cleaned up, false if more work is
 * required. */
bool
binding_cleanup(struct controller_ctx *ctx, const char *chassis_id)
{
    if (!ctx->ovnsb_idl_txn) {
        return false;
    }

    if (!chassis_id) {
        return true;
    }

    const struct sbrec_chassis *chassis_rec
        = get_chassis(ctx->ovnsb_idl, chassis_id);
    if (!chassis_rec) {
        return true;
    }

    ovsdb_idl_txn_add_comment(
        ctx->ovnsb_idl_txn,
        "ovn-controller: removing all port bindings for '%s'", chassis_id);

    const struct sbrec_port_binding *binding_rec;
    bool any_changes = false;
    SBREC_PORT_BINDING_FOR_EACH(binding_rec, ctx->ovnsb_idl) {
        if (binding_rec->chassis == chassis_rec) {
            sbrec_port_binding_set_chassis(binding_rec, NULL);
            any_changes = true;
        }
    }
    return !any_changes;
}
