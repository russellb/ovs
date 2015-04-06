/*
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

#include <getopt.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#include "command-line.h"
#include "dirs.h"
#include "fatal-signal.h"
#include "ovn/ovn-nb-idl.h"
#include "poll-loop.h"
#include "process.h"
#include "stream.h"
#include "stream-ssl.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovn_nbctl);

struct nbctl_context {
    struct ovsdb_idl *idl;
    struct ovsdb_idl_txn *txn;
};

static const char *db;

static const char *default_db(void);

static void
usage(void)
{
    printf("\
%s: OVN northbound DB management utility\n\
usage: %s [OPTIONS] COMMAND [ARG...]\n\
\n\
Logical switch commands:\n\
  lswitch-add [LSWITCH]     create a logical switch named LSWITCH\n\
  lswitch-del LSWITCH       delete LSWITCH and all its ports\n\
  lswitch-list              print the names of all logical switches\n\
  lswitch-set-external-id LSWITCH KEY [VALUE]\n\
                            set or delete an external-id on LSWITCH\n\
  lswitch-get-external-id LSWITCH [KEY]\n\
                            list one or all external-ids on LSWITCH\n\
\n\
Logical port commands:\n\
  lport-add LSWITCH LPORT   add logical port LPORT on LSWITCH\n\
  lport-add LSWITCH LPORT PARENT TAG\n\
                            add logical port LPORT on LSWITCH with PARENT\n\
                            on TAG\n\
  lport-del LPORT           delete LPORT from its attached switch\n\
  lport-list LSWITCH        print the names of all logical ports on LSWITCH\n\
  lport-get-parent LPORT    get the parent of LPORT if set\n\
  lport-get-tag LPORT       get the LPORT's tagLPORT if set\n\
  lport-set-external-id LPORT KEY [VALUE]\n\
                            set or delete an external-id on LPORT\n\
  lport-get-external-id LPORT [KEY]\n\
                            list one or all external-ids on LPORT\n\
  lport-set-macs LPORT [MAC] [MAC] [...]\n\
                            set MAC addresses for LPORT. Specify more\n\
                            than one using additional arguments.\n\
  lport-get-macs LPORT      get a list of MAC addresses on LPORT\n\
  lport-get-up LPORT        get state of LPORT ('up' or 'down')\n\
\n\
Options:\n\
  --db=DATABASE             connect to DATABASE\n\
                            (default: %s)\n\
  -h, --help                display this help message\n\
  -o, --options             list available options\n\
  -V, --version             display version information\n\
", program_name, program_name, default_db());
    vlog_usage();
    stream_usage("database", true, true, false);
}

static const struct nbrec_logical_switch *
lswitch_by_name_or_uuid(struct nbctl_context *nb_ctx, const char *id)
{
    const struct nbrec_logical_switch *lswitch = NULL;
    bool is_uuid = false;
    bool duplicate = false;
    struct uuid lswitch_uuid;

    if (uuid_from_string(&lswitch_uuid, id)) {
        is_uuid = true;
        lswitch = nbrec_logical_switch_get_for_uuid(nb_ctx->idl,
                                                    &lswitch_uuid);
    }

    if (!lswitch) {
        const struct nbrec_logical_switch *iter;

        NBREC_LOGICAL_SWITCH_FOR_EACH(iter, nb_ctx->idl) {
            if (strcmp(iter->name, id)) {
                continue;
            }
            if (lswitch) {
                VLOG_WARN("There is more than one logical switch named '%s'. "
                        "Use a UUID.", id);
                lswitch = NULL;
                duplicate = true;
                break;
            }
            lswitch = iter;
        }
    }

    if (!lswitch && !duplicate) {
        VLOG_WARN("lswitch not found for %s: '%s'",
                is_uuid ? "UUID" : "name", id);
    }

    return lswitch;
}

static void
do_lswitch_add(struct ovs_cmdl_context *ctx)
{
    struct nbctl_context *nb_ctx = ctx->pvt;
    struct nbrec_logical_switch *lswitch;

    lswitch = nbrec_logical_switch_insert(nb_ctx->txn);
    if (ctx->argc == 2) {
        nbrec_logical_switch_set_name(lswitch, ctx->argv[1]);
    }
}

static void
do_lswitch_del(struct ovs_cmdl_context *ctx)
{
    struct nbctl_context *nb_ctx = ctx->pvt;
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch *lswitch;

    lswitch = lswitch_by_name_or_uuid(nb_ctx, id);
    if (!lswitch) {
        return;
    }

    nbrec_logical_switch_delete(lswitch);
}

static void
do_lswitch_list(struct ovs_cmdl_context *ctx)
{
    struct nbctl_context *nb_ctx = ctx->pvt;
    const struct nbrec_logical_switch *lswitch;

    NBREC_LOGICAL_SWITCH_FOR_EACH(lswitch, nb_ctx->idl) {
        printf(UUID_FMT " (%s)\n",
               UUID_ARGS(&lswitch->header_.uuid), lswitch->name);
    }
}

static void
do_lswitch_set_external_id(struct ovs_cmdl_context *ctx)
{
    struct nbctl_context *nb_ctx = ctx->pvt;
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch *lswitch;
    struct smap new_external_ids;

    lswitch = lswitch_by_name_or_uuid(nb_ctx, id);
    if (!lswitch) {
        return;
    }

    smap_init(&new_external_ids);
    smap_clone(&new_external_ids, &lswitch->external_ids);
    if (ctx->argc == 4) {
        smap_replace(&new_external_ids, ctx->argv[2], ctx->argv[3]);
    } else {
        smap_remove(&new_external_ids, ctx->argv[2]);
    }
    nbrec_logical_switch_set_external_ids(lswitch, &new_external_ids);
    smap_destroy(&new_external_ids);
}

static void
do_lswitch_get_external_id(struct ovs_cmdl_context *ctx)
{
    struct nbctl_context *nb_ctx = ctx->pvt;
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch *lswitch;

    lswitch = lswitch_by_name_or_uuid(nb_ctx, id);
    if (!lswitch) {
        return;
    }

    if (ctx->argc == 3) {
        const char *key = ctx->argv[2];
        const char *value;

        /* List one external ID */

        value = smap_get(&lswitch->external_ids, key);
        if (value) {
            printf("%s\n", value);
        }
    } else {
        struct smap_node *node;

        /* List all external IDs */

        SMAP_FOR_EACH(node, &lswitch->external_ids) {
            printf("%s=%s\n", node->key, node->value);
        }
    }
}

static const struct nbrec_logical_port *
lport_by_name_or_uuid(struct nbctl_context *nb_ctx, const char *id)
{
    const struct nbrec_logical_port *lport = NULL;
    bool is_uuid = false;
    struct uuid lport_uuid;

    if (uuid_from_string(&lport_uuid, id)) {
        is_uuid = true;
        lport = nbrec_logical_port_get_for_uuid(nb_ctx->idl, &lport_uuid);
    }

    if (!lport) {
        NBREC_LOGICAL_PORT_FOR_EACH(lport, nb_ctx->idl) {
            if (!strcmp(lport->name, id)) {
                break;
            }
        }
    }

    if (!lport) {
        VLOG_WARN("lport not found for %s: '%s'",
                is_uuid ? "UUID" : "name", id);
    }

    return lport;
}

static void
do_lport_add(struct ovs_cmdl_context *ctx)
{
    struct nbctl_context *nb_ctx = ctx->pvt;
    struct nbrec_logical_port *lport;
    const struct nbrec_logical_switch *lswitch;
    int64_t tag;

    lswitch = lswitch_by_name_or_uuid(nb_ctx, ctx->argv[1]);
    if (!lswitch) {
        return;
    }

    if (ctx->argc != 3 && ctx->argc != 5) {
        /* If a parent_name is specififed, a tag must be specified as well. */
        VLOG_WARN("Invalid arguments to lport-add.");
        return;
    }

    if (ctx->argc == 5) {
        /* Validate tag. */
        if (!ovs_scan(ctx->argv[4], "%"SCNd64, &tag) || tag < 0 || tag > 4095) {
            VLOG_WARN("Invalid tag '%s'", ctx->argv[4]);
            return;
        }
    }

    /* Finally, create the transaction. */
    lport = nbrec_logical_port_insert(nb_ctx->txn);
    nbrec_logical_port_set_name(lport, ctx->argv[2]);
    nbrec_logical_port_set_lswitch(lport, lswitch);
    if (ctx->argc == 5) {
        nbrec_logical_port_set_parent_name(lport, ctx->argv[3]);
        nbrec_logical_port_set_tag(lport, &tag, 1);
    }
}

static void
do_lport_del(struct ovs_cmdl_context *ctx)
{
    struct nbctl_context *nb_ctx = ctx->pvt;
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(nb_ctx, ctx->argv[1]);
    if (!lport) {
        return;
    }

    nbrec_logical_port_delete(lport);
}

static bool
is_lswitch(const struct nbrec_logical_switch *lswitch,
        struct uuid *lswitch_uuid, const char *name)
{
    if (lswitch_uuid) {
        return uuid_equals(lswitch_uuid, &lswitch->header_.uuid);
    } else {
        return !strcmp(lswitch->name, name);
    }
}


static void
do_lport_list(struct ovs_cmdl_context *ctx)
{
    struct nbctl_context *nb_ctx = ctx->pvt;
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;
    bool is_uuid = false;
    struct uuid lswitch_uuid;

    if (uuid_from_string(&lswitch_uuid, id)) {
        is_uuid = true;
    }

    NBREC_LOGICAL_PORT_FOR_EACH(lport, nb_ctx->idl) {
        bool match;
        if (is_uuid) {
            match = is_lswitch(lport->lswitch, &lswitch_uuid, NULL);
        } else {
            match = is_lswitch(lport->lswitch, NULL, id);
        }
        if (!match) {
            continue;
        }
        printf(UUID_FMT " (%s)\n",
               UUID_ARGS(&lport->header_.uuid), lport->name);
    }
}

static void
do_lport_get_parent(struct ovs_cmdl_context *ctx)
{
    struct nbctl_context *nb_ctx = ctx->pvt;
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(nb_ctx, ctx->argv[1]);
    if (!lport) {
        return;
    }

    if (lport->parent_name) {
        printf("%s\n", lport->parent_name);
    }
}

static void
do_lport_get_tag(struct ovs_cmdl_context *ctx)
{
    struct nbctl_context *nb_ctx = ctx->pvt;
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(nb_ctx, ctx->argv[1]);
    if (!lport) {
        return;
    }

    if (lport->n_tag > 0) {
        printf("%"PRId64"\n", lport->tag[0]);
    }
}

static void
do_lport_set_external_id(struct ovs_cmdl_context *ctx)
{
    struct nbctl_context *nb_ctx = ctx->pvt;
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;
    struct smap new_external_ids;

    lport = lport_by_name_or_uuid(nb_ctx, id);
    if (!lport) {
        return;
    }

    smap_init(&new_external_ids);
    smap_clone(&new_external_ids, &lport->external_ids);
    if (ctx->argc == 4) {
        smap_replace(&new_external_ids, ctx->argv[2], ctx->argv[3]);
    } else {
        smap_remove(&new_external_ids, ctx->argv[2]);
    }
    nbrec_logical_port_set_external_ids(lport, &new_external_ids);
    smap_destroy(&new_external_ids);
}

static void
do_lport_get_external_id(struct ovs_cmdl_context *ctx)
{
    struct nbctl_context *nb_ctx = ctx->pvt;
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(nb_ctx, id);
    if (!lport) {
        return;
    }

    if (ctx->argc == 3) {
        const char *key = ctx->argv[2];
        const char *value;

        /* List one external ID */

        value = smap_get(&lport->external_ids, key);
        if (value) {
            printf("%s\n", value);
        }
    } else {
        struct smap_node *node;

        /* List all external IDs */

        SMAP_FOR_EACH(node, &lport->external_ids) {
            printf("%s=%s\n", node->key, node->value);
        }
    }
}

static void
do_lport_set_macs(struct ovs_cmdl_context *ctx)
{
    struct nbctl_context *nb_ctx = ctx->pvt;
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(nb_ctx, id);
    if (!lport) {
        return;
    }

    nbrec_logical_port_set_macs(lport,
            (const char **) ctx->argv + 2, ctx->argc - 2);
}

static void
do_lport_get_macs(struct ovs_cmdl_context *ctx)
{
    struct nbctl_context *nb_ctx = ctx->pvt;
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;
    size_t i;

    lport = lport_by_name_or_uuid(nb_ctx, id);
    if (!lport) {
        return;
    }

    for (i = 0; i < lport->n_macs; i++) {
        printf("%s\n", lport->macs[i]);
    }
}

static void
do_lport_get_up(struct ovs_cmdl_context *ctx)
{
    struct nbctl_context *nb_ctx = ctx->pvt;
    const char *id = ctx->argv[1];
    const struct nbrec_logical_port *lport;

    lport = lport_by_name_or_uuid(nb_ctx, id);
    if (!lport) {
        return;
    }

    printf("%s\n", (lport->up && *lport->up) ? "up" : "down");
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        VLOG_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"db", required_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {"options", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        VLOG_OPTION_HANDLERS;
        STREAM_SSL_OPTION_HANDLERS;

        case 'd':
            db = optarg;
            break;

        case 'h':
            usage();
            exit(EXIT_SUCCESS);

        case 'o':
            ovs_cmdl_print_options(long_options);
            exit(EXIT_SUCCESS);

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        default:
            break;
        }
    }

    if (!db) {
        db = default_db();
    }

    free(short_options);
}

static const struct ovs_cmdl_command all_commands[] = {
    {
        .name = "lswitch-add",
        .usage = "[LSWITCH]",
        .min_args = 0,
        .max_args = 1,
        .handler = do_lswitch_add,
    },
    {
        .name = "lswitch-del",
        .usage = "LSWITCH",
        .min_args = 1,
        .max_args = 1,
        .handler = do_lswitch_del,
    },
    {
        .name = "lswitch-list",
        .usage = "",
        .min_args = 0,
        .max_args = 0,
        .handler = do_lswitch_list,
    },
    {
        .name = "lswitch-set-external-id",
        .usage = "LSWITCH KEY [VALUE]",
        .min_args = 2,
        .max_args = 3,
        .handler = do_lswitch_set_external_id,
    },
    {
        .name = "lswitch-get-external-id",
        .usage = "LSWITCH [KEY]",
        .min_args = 1,
        .max_args = 2,
        .handler = do_lswitch_get_external_id,
    },
    {
        .name = "lport-add",
        .usage = "LSWITCH LPORT [PARENT] [TAG]",
        .min_args = 2,
        .max_args = 4,
        .handler = do_lport_add,
    },
    {
        .name = "lport-del",
        .usage = "LPORT",
        .min_args = 1,
        .max_args = 1,
        .handler = do_lport_del,
    },
    {
        .name = "lport-list",
        .usage = "LSWITCH",
        .min_args = 1,
        .max_args = 1,
        .handler = do_lport_list,
    },
    {
        .name = "lport-get-parent",
        .usage = "LPORT",
        .min_args = 1,
        .max_args = 1,
        .handler = do_lport_get_parent,
    },
    {
        .name = "lport-get-tag",
        .usage = "LPORT",
        .min_args = 1,
        .max_args = 1,
        .handler = do_lport_get_tag,
    },
    {
        .name = "lport-set-external-id",
        .usage = "LPORT KEY [VALUE]",
        .min_args = 2,
        .max_args = 3,
        .handler = do_lport_set_external_id,
    },
    {
        .name = "lport-get-external-id",
        .usage = "LPORT [KEY]",
        .min_args = 1,
        .max_args = 2,
        .handler = do_lport_get_external_id,
    },
    {
        .name = "lport-set-macs",
        .usage = "LPORT [MAC] [MAC] [...]",
        .min_args = 1,
        /* Accept however many arguments the system will allow. */
        .max_args = INT_MAX,
        .handler = do_lport_set_macs,
    },
    {
        .name = "lport-get-macs",
        .usage = "LPORT",
        .min_args = 1,
        .max_args = 1,
        .handler = do_lport_get_macs,
    },
    {
        .name = "lport-get-up",
        .usage = "LPORT",
        .min_args = 1,
        .max_args = 1,
        .handler = do_lport_get_up,
    },

    {
        /* sentinel */
        .name = NULL,
    },
};

static const struct ovs_cmdl_command *
get_all_commands(void)
{
    return all_commands;
}

static const char *
default_db(void)
{
    static char *def;
    if (!def) {
        def = xasprintf("unix:%s/db.sock", ovs_rundir());
    }
    return def;
}

int
main(int argc, char *argv[])
{
    extern struct vlog_module VLM_reconnect;
    struct ovs_cmdl_context ctx;
    struct nbctl_context nb_ctx = { .idl = NULL, };
    enum ovsdb_idl_txn_status txn_status;
    unsigned int seqno;
    int res = 0;
    char *args;

    fatal_ignore_sigpipe();
    set_program_name(argv[0]);
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels(&VLM_reconnect, VLF_ANY_DESTINATION, VLL_WARN);
    parse_options(argc, argv);
    nbrec_init();

    args = process_escape_args(argv);

    nb_ctx.idl = ovsdb_idl_create(db, &nbrec_idl_class, true, false);
    ctx.pvt = &nb_ctx;
    ctx.argc = argc - optind;
    ctx.argv = argv + optind;

    seqno = ovsdb_idl_get_seqno(nb_ctx.idl);
    for (;;) {
        ovsdb_idl_run(nb_ctx.idl);

        if (!ovsdb_idl_is_alive(nb_ctx.idl)) {
            int retval = ovsdb_idl_get_last_error(nb_ctx.idl);
            VLOG_ERR("%s: database connection failed (%s)",
                    db, ovs_retval_to_string(retval));
            res = 1;
            break;
        }

        if (seqno != ovsdb_idl_get_seqno(nb_ctx.idl)) {
            nb_ctx.txn = ovsdb_idl_txn_create(nb_ctx.idl);
            ovsdb_idl_txn_add_comment(nb_ctx.txn, "ovn-nbctl: %s", args);
            ovs_cmdl_run_command(&ctx, get_all_commands());
            txn_status = ovsdb_idl_txn_commit_block(nb_ctx.txn);
            if (txn_status == TXN_TRY_AGAIN) {
                ovsdb_idl_txn_destroy(nb_ctx.txn);
                nb_ctx.txn = NULL;
                continue;
            } else {
                break;
            }
        }

        if (seqno == ovsdb_idl_get_seqno(nb_ctx.idl)) {
            ovsdb_idl_wait(nb_ctx.idl);
            poll_block();
        }
    }

    if (nb_ctx.txn) {
        ovsdb_idl_txn_destroy(nb_ctx.txn);
    }
    ovsdb_idl_destroy(nb_ctx.idl);
    free(args);

    exit(res);
}
