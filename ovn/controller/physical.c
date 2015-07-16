/* Copyright (c) 2015 Nicira, Inc.
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
#include "physical.h"
#include "match.h"
#include "ofctrl.h"
#include "ofp-actions.h"
#include "ofpbuf.h"
#include "ovn-controller.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "pipeline.h"
#include "shash.h"
#include "simap.h"
#include "smap.h"
#include "vswitch-idl.h"

/* A register of bit flags for OVN */
#define MFF_OVN_FLAGS MFF_REG5
enum {
    /* Indicates that the packet came in on a localnet port */
    OVN_FLAG_LOCALNET = (1 << 0),
};

void
physical_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_external_ids);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_ofport);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_external_ids);
}

static void
init_input_match(struct match *match, ofp_port_t ofport, int tag)
{
    match_init_catchall(match);
    match_set_in_port(match, ofport);
    if (tag) {
        match_set_dl_vlan(match, htons(tag));
    }
}

void
physical_run(struct controller_ctx *ctx, const struct ovsrec_bridge *br_int,
             const char *this_chassis_id, struct smap *bridge_mappings,
             struct hmap *flow_table)
{
    struct simap lport_to_ofport = SIMAP_INITIALIZER(&lport_to_ofport);
    struct simap chassis_to_ofport = SIMAP_INITIALIZER(&chassis_to_ofport);
    struct simap localnet_to_ofport = SIMAP_INITIALIZER(&localnet_to_ofport);

    for (int i = 0; i < br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = br_int->ports[i];
        if (!strcmp(port_rec->name, br_int->name)) {
            continue;
        }

        const char *chassis_id = smap_get(&port_rec->external_ids,
                                          "ovn-chassis-id");
        if (chassis_id && !strcmp(chassis_id, this_chassis_id)) {
            continue;
        }

        for (int j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec = port_rec->interfaces[j];

            /* Get OpenFlow port number. */
            if (!iface_rec->n_ofport) {
                continue;
            }
            int64_t ofport = iface_rec->ofport[0];
            if (ofport < 1 || ofport > ofp_to_u16(OFPP_MAX)) {
                continue;
            }

            /* Record as patch to local net, chassis, or local logical port. */
            if (!strcmp(iface_rec->type, "patch")) {
                const char *peer = smap_get(&iface_rec->options, "peer");
                if (!peer) {
                    continue;
                }
                const char *localnet = smap_get(bridge_mappings, peer);
                if (localnet) {
                    simap_put(&localnet_to_ofport, localnet, ofport);
                }
            } else if (chassis_id) {
                simap_put(&chassis_to_ofport, chassis_id, ofport);
                break;
            } else {
                const char *iface_id = smap_get(&iface_rec->external_ids,
                                                "iface-id");
                if (iface_id) {
                    simap_put(&lport_to_ofport, iface_id, ofport);
                }
            }
        }
    }

    struct ofpbuf ofpacts;
    ofpbuf_init(&ofpacts, 0);

    struct localnet_flow {
        struct shash_node node;
        struct match match;
        struct ofpbuf ofpacts;
    };
    struct shash localnet_inputs = SHASH_INITIALIZER(&localnet_inputs);

    /* Set up flows in table 0 for physical-to-logical translation and in table
     * 64 for logical-to-physical translation. */
    const struct sbrec_binding *binding;
    SBREC_BINDING_FOR_EACH (binding, ctx->ovnsb_idl) {
        /* Find the OpenFlow port for the logical port, as 'ofport'.  If it's
         * on a remote chassis, this is the OpenFlow port for the tunnel to
         * that chassis (and set 'local' to false).  Otherwise, if it's on the
         * chassis we're managing, this is the OpenFlow port for the vif itself
         * (and set 'local' to true). When 'parent_port' is set for a binding,
         * it implies a container sitting inside a VM reachable via a 'tag'.
         */
        int tag = 0;
        ofp_port_t ofport;
        if (!strcmp(binding->type, "localnet")) {
            const char *network = smap_get(&binding->options, "network_name");
            if (!network) {
                continue;
            }
            ofport = u16_to_ofp(simap_get(&localnet_to_ofport, network));
        } else if (binding->parent_port) {
            ofport = u16_to_ofp(simap_get(&lport_to_ofport,
                                          binding->parent_port));
            if (ofport && binding->tag) {
                tag = *binding->tag;
            }
        } else {
            ofport = u16_to_ofp(simap_get(&lport_to_ofport,
                                          binding->logical_port));
        }

        bool local = ofport != 0;
        if (!local) {
            if (!binding->chassis) {
                continue;
            }
            ofport = u16_to_ofp(simap_get(&chassis_to_ofport,
                                          binding->chassis->name));
            if (!ofport) {
                continue;
            }
        }

        /* Translate the logical datapath into the form we use in
         * MFF_METADATA. */
        uint32_t ldp = ldp_to_integer(&binding->logical_datapath);
        if (!ldp) {
            continue;
        }

        struct match match;
        if (local) {
            struct ofpbuf *local_ofpacts = &ofpacts;
            bool add_input_flow = true;

            /* Packets that arrive from a vif can belong to a VM or
             * to a container located inside that VM. Packets that
             * arrive from containers have a tag (vlan) associated with them.
             */

            /* Table 0, Priority 150 and 100.
             * ==============================
             *
             * Priority 150 is for traffic belonging to containers. For such
             * traffic, match on the tags and then strip the tag.
             * Priority 100 is for traffic belonging to VMs.
             *
             * For both types of traffic: set MFF_LOG_INPORT to the
             * logical input port, MFF_METADATA to the logical datapath, and
             * resubmit into the logical pipeline starting at table 16. */
            if (!strcmp(binding->type, "localnet")) {
                const char *network = smap_get(&binding->options, "network_name");
                struct shash_node *node;
                struct localnet_flow *ln_flow;
                node = shash_find(&localnet_inputs, network);
                if (!node) {
                    ln_flow = xmalloc(sizeof *ln_flow);
                    init_input_match(&ln_flow->match, ofport, tag);
                    ofpbuf_init(&ln_flow->ofpacts, 0);
                    /* Set OVN_FLAG_LOCALNET to indicate that the packet came in from a
                     * localnet port. */
                    struct ofpact_set_field *sf = ofpact_put_SET_FIELD(&ln_flow->ofpacts);
                    sf->field = mf_from_id(MFF_OVN_FLAGS);
                    sf->value.be64 = htonl(OVN_FLAG_LOCALNET);
                    sf->mask.be64 = OVS_BE64_MAX;

                    node = shash_add(&localnet_inputs, network, ln_flow);
                }
                ln_flow = node->data;
                local_ofpacts = &ln_flow->ofpacts;
                add_input_flow = false;
            } else {
                ofpbuf_clear(local_ofpacts);
                init_input_match(&match, ofport, tag);
            }

            /* Set MFF_METADATA. */
            struct ofpact_set_field *sf = ofpact_put_SET_FIELD(local_ofpacts);
            sf->field = mf_from_id(MFF_METADATA);
            sf->value.be64 = htonll(ldp);
            sf->mask.be64 = OVS_BE64_MAX;

            /* Set MFF_LOG_INPORT. */
            sf = ofpact_put_SET_FIELD(local_ofpacts);
            sf->field = mf_from_id(MFF_LOG_INPORT);
            sf->value.be32 = htonl(binding->tunnel_key);
            sf->mask.be32 = OVS_BE32_MAX;

            /* Strip vlans. */
            if (tag) {
                ofpact_put_STRIP_VLAN(local_ofpacts);
            }

            /* Resubmit to first logical pipeline table. */
            struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(local_ofpacts);
            resubmit->in_port = OFPP_IN_PORT;
            resubmit->table_id = 16;
            if (add_input_flow) {
                ofctrl_add_flow(flow_table, 0, tag ? 150 : 100, &match, &ofpacts);

                /* Table 0, Priority 50.
                 * =====================
                 *
                 * For packets that arrive from a remote node destined to this
                 * local vif: deliver directly to the vif. If the destination
                 * is a container sitting behind a vif, tag the packets. */
                match_init_catchall(&match);
                ofpbuf_clear(&ofpacts);
                match_set_tun_id(&match, htonll(binding->tunnel_key));
                if (tag) {
                    struct ofpact_vlan_vid *vlan_vid;
                    vlan_vid = ofpact_put_SET_VLAN_VID(&ofpacts);
                    vlan_vid->vlan_vid = tag;
                    vlan_vid->push_vlan_if_needed = true;
                }
                ofpact_put_OUTPUT(&ofpacts)->port = ofport;
                ofctrl_add_flow(flow_table, 0, 50, &match, &ofpacts);
            }
        }

        /* Table 64, Priority 100.
         * =======================
         *
         * Drop packets whose logical inport and outport are the same. */
        match_init_catchall(&match);
        ofpbuf_clear(&ofpacts);
        match_set_reg(&match, MFF_LOG_INPORT - MFF_REG0, binding->tunnel_key);
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, binding->tunnel_key);
        ofctrl_add_flow(flow_table, 64, 100, &match, &ofpacts);

        /* Table 64, Priority 50.
         * ======================
         *
         * For packets to remote machines, send them over a tunnel to the
         * remote chassis.
         *
         * For packets to local vifs, deliver them directly. */
        match_init_catchall(&match);
        ofpbuf_clear(&ofpacts);
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, binding->tunnel_key);
        if (!local) {
            /* Packets that came in on a localnet port should be output to local
             * vifs only. */
            match_set_reg_masked(&match, MFF_OVN_FLAGS - MFF_REG0, 0, OVN_FLAG_LOCALNET);

            /* Set MFF_TUN_ID. */
            struct ofpact_set_field *sf = ofpact_put_SET_FIELD(&ofpacts);
            sf->field = mf_from_id(MFF_TUN_ID);
            sf->value.be64 = htonll(binding->tunnel_key);
            sf->mask.be64 = OVS_BE64_MAX;
        }
        if (tag) {
            /* For containers sitting behind a local vif, tag the packets
             * before delivering them. Since there is a possibility of
             * packets needing to hair-pin back into the same vif from
             * which it came, push the in_port to stack and make the
             * in_port as zero. */
            struct ofpact_vlan_vid *vlan_vid;
            vlan_vid = ofpact_put_SET_VLAN_VID(&ofpacts);
            vlan_vid->vlan_vid = tag;
            vlan_vid->push_vlan_if_needed = true;

            struct ofpact_stack *stack_action;
            const struct mf_field *field;
            stack_action = ofpact_put_STACK_PUSH(&ofpacts);
            field = mf_from_id(MFF_IN_PORT);
            stack_action->subfield.field = field;
            stack_action->subfield.ofs = 0;
            stack_action->subfield.n_bits = field->n_bits;

            struct ofpact_set_field *sf = ofpact_put_SET_FIELD(&ofpacts);
            sf->field = mf_from_id(MFF_IN_PORT);
            sf->value.be16 = 0;
            sf->mask.be16 = OVS_BE16_MAX;
        }
        ofpact_put_OUTPUT(&ofpacts)->port = ofport;
        if (tag) {
            /* Revert the tag added to the packets headed to containers
             * in the previous step. If we don't do this, the packets
             * that are to be broadcasted to a VM in the same logical
             * switch will also contain the tag. Also revert the zero'd
             * in_port. */
            ofpact_put_STRIP_VLAN(&ofpacts);

            struct ofpact_stack *stack_action;
            const struct mf_field *field;
            stack_action = ofpact_put_STACK_POP(&ofpacts);
            field = mf_from_id(MFF_IN_PORT);
            stack_action->subfield.field = field;
            stack_action->subfield.ofs = 0;
            stack_action->subfield.n_bits = field->n_bits;
        }
        ofctrl_add_flow(flow_table, 64, 50, &match, &ofpacts);
    }

    struct shash_node *ln_flow_node, *ln_flow_node_next;
    struct localnet_flow *ln_flow;
    SHASH_FOR_EACH_SAFE (ln_flow_node, ln_flow_node_next, &localnet_inputs) {
        ln_flow = ln_flow_node->data;
        shash_delete(&localnet_inputs, ln_flow_node);
        ofctrl_add_flow(flow_table, 0, 100, &ln_flow->match, &ln_flow->ofpacts);
        ofpbuf_uninit(&ln_flow->ofpacts);
        free(ln_flow);
    }
    shash_destroy(&localnet_inputs);

    ofpbuf_uninit(&ofpacts);
    simap_destroy(&lport_to_ofport);
    simap_destroy(&chassis_to_ofport);
    simap_destroy(&localnet_to_ofport);
}
