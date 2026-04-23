// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <sys/types.h>
#include <sys/socket.h>
#include <argp.h>

#include "bench.h"
#include "bpf_util.h"
#include "bench_local_storage_lookup.skel.h"

#define BPF_MAX_LOOPS (1 << 23)

static struct bench_local_storage_lookup *skel;
static int *sock_fds;

static struct {
	__u32 storage_type;
	__u32 max_entries;
	__u32 nr_entries;
	__u32 nr_loops;
	__u32 do_update;
} args = {
	.storage_type = BPF_MAP_TYPE_SK_STORAGE,
	.max_entries = 1000,
	.nr_entries = 500,
	.nr_loops = 1000000,
	.do_update = 0,
};

enum {
	ARG_STORAGE_TYPE = 9000,
	ARG_MAX_ENTRIES,
	ARG_NR_ENTRIES,
	ARG_NR_LOOPS,
	ARG_OPERATION,
};

static const struct argp_option opts[] = {
	{ "storage-type", ARG_STORAGE_TYPE, "STORAGE_TYPE", 0,
	  "The type of storage to test (socket, hashmap, or rhashtab)" },
	{ "max_entries", ARG_MAX_ENTRIES, "MAX_ENTRIES", 0,
	  "The hashmap max entries" },
	{ "nr_entries", ARG_NR_ENTRIES, "NR_ENTRIES", 0,
	  "The number of sockets to cycle through" },
	{ "nr_loops", ARG_NR_LOOPS, "NR_LOOPS", 0,
	  "The number of loops for the benchmark" },
	{ "operation", ARG_OPERATION, "OPERATION", 0,
	  "The operation to benchmark (lookup or update)" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long ret;

	switch (key) {
	case ARG_STORAGE_TYPE:
		if (!strcmp(arg, "socket")) {
			args.storage_type = BPF_MAP_TYPE_SK_STORAGE;
		} else if (!strcmp(arg, "hashmap")) {
			args.storage_type = BPF_MAP_TYPE_HASH;
		} else if (!strcmp(arg, "rhashtab")) {
			args.storage_type = BPF_MAP_TYPE_RHASH;
		} else {
			fprintf(stderr, "invalid storage-type (socket, hashmap, or rhashtab)\n");
			argp_usage(state);
		}
		break;
	case ARG_MAX_ENTRIES:
		ret = strtol(arg, NULL, 10);
		if (ret < 1 || ret > UINT_MAX) {
			fprintf(stderr, "invalid max_entries\n");
			argp_usage(state);
		}
		args.max_entries = ret;
		break;
	case ARG_NR_ENTRIES:
		ret = strtol(arg, NULL, 10);
		if (ret < 1 || ret > UINT_MAX) {
			fprintf(stderr, "invalid nr_entries\n");
			argp_usage(state);
		}
		args.nr_entries = ret;
		break;
	case ARG_NR_LOOPS:
		ret = strtol(arg, NULL, 10);
		if (ret < 1 || ret > BPF_MAX_LOOPS) {
			fprintf(stderr, "invalid nr_loops: %ld (min=1 max=%d)\n",
				ret, BPF_MAX_LOOPS);
			argp_usage(state);
		}
		args.nr_loops = ret;
		break;
	case ARG_OPERATION:
		if (!strcmp(arg, "lookup")) {
			args.do_update = 0;
		} else if (!strcmp(arg, "update")) {
			args.do_update = 1;
		} else {
			fprintf(stderr, "invalid operation (lookup or update)\n");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_local_storage_lookup_argp = {
	.options = opts,
	.parser = parse_arg,
};

static void validate(void)
{
	if (env.consumer_cnt != 0) {
		fprintf(stderr, "benchmark doesn't support consumer!\n");
		exit(1);
	}

	if (args.nr_entries > args.max_entries) {
		fprintf(stderr, "nr_entries is too big (max %u, got %u)\n",
			args.max_entries, args.nr_entries);
		exit(1);
	}
}

static void *producer(void *input)
{
	socklen_t optlen;
	int type, i;

	while (true) {
		for (i = 0; i < args.nr_entries; i++) {
			optlen = sizeof(type);
			getsockopt(sock_fds[i], SOL_SOCKET, SO_TYPE,
				   &type, &optlen);
		}
	}
	return NULL;
}

static void measure(struct bench_res *res)
{
}

static void setup(void)
{
	int max_entries, i;

	setup_libbpf();

	skel = bench_local_storage_lookup__open();
	if (!skel) {
		fprintf(stderr, "error opening skel\n");
		exit(1);
	}

	if (args.storage_type != BPF_MAP_TYPE_HASH &&
	    args.storage_type != BPF_MAP_TYPE_RHASH)
		bpf_program__set_autoload(skel->progs.hashmap_socket_destroy, false);

	max_entries = args.max_entries < 50000 ? 50000 : args.max_entries * 2;
	bpf_map__set_max_entries(skel->maps.hash_map, max_entries);
	bpf_map__set_max_entries(skel->maps.rhash_map, max_entries);

	skel->bss->nr_loops = args.nr_loops;
	skel->bss->do_update = args.do_update;

	if (bench_local_storage_lookup__load(skel)) {
		fprintf(stderr, "error loading skel\n");
		exit(1);
	}

	skel->bss->bench_pid = getpid();
	if (args.storage_type == BPF_MAP_TYPE_HASH)
		skel->bss->use_hashmap = 1;
	else if (args.storage_type == BPF_MAP_TYPE_RHASH)
		skel->bss->use_rhashtab = 1;

	if (!bpf_program__attach(skel->progs.socket_post_create)) {
		fprintf(stderr, "Error attaching socket_post_create\n");
		exit(1);
	}

	if (args.storage_type == BPF_MAP_TYPE_HASH ||
	    args.storage_type == BPF_MAP_TYPE_RHASH) {
		if (!bpf_program__attach(skel->progs.hashmap_socket_destroy)) {
			fprintf(stderr, "Error attaching hashmap_socket_destroy\n");
			exit(1);
		}
	}

	/* Pre-create sockets; BPF auto-populates their storage */
	sock_fds = calloc(args.nr_entries, sizeof(*sock_fds));
	if (!sock_fds) {
		fprintf(stderr, "cannot alloc sock_fds\n");
		exit(1);
	}

	for (i = 0; i < args.nr_entries; i++) {
		sock_fds[i] = socket(AF_INET6, SOCK_DGRAM, 0);
		if (sock_fds[i] == -1) {
			fprintf(stderr, "failed to create socket %d\n", i);
			exit(1);
		}
	}

	if (skel->bss->setup_errs) {
		fprintf(stderr, "setup errors: %ld\n", skel->bss->setup_errs);
		exit(1);
	}

	skel->bss->setup_done = 1;

	if (!bpf_program__attach(skel->progs.socket_getsockopt)) {
		fprintf(stderr, "Error attaching socket_getsockopt\n");
		exit(1);
	}
}

static inline double events_from_time(u64 time)
{
	if (time)
		return args.nr_loops * 1000000000llu / time / 1000000.0L;

	return 0;
}

static int compute_events(u64 *times, double *events_mean, double *events_stddev, u64 *mean_time)
{
	int i, n = 0;

	*events_mean = 0;
	*events_stddev = 0;
	*mean_time = 0;

	for (i = 0; i < 32; i++) {
		if (!times[i])
			break;
		*mean_time += times[i];
		*events_mean += events_from_time(times[i]);
		n += 1;
	}
	if (!n)
		return 0;

	*mean_time /= n;
	*events_mean /= n;

	if (n > 1) {
		for (i = 0; i < n; i++) {
			double events_i = *events_mean - events_from_time(times[i]);
			*events_stddev += events_i * events_i / (n - 1);
		}
		*events_stddev = sqrt(*events_stddev);
	}

	return n;
}

static void report_final(struct bench_res res[], int res_cnt)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	double events_mean, events_stddev;
	u64 mean_time;
	int i, n;

	for (i = 0; i < nr_cpus; i++) {
		n = compute_events(skel->bss->percpu_times[i], &events_mean,
				   &events_stddev, &mean_time);
		if (n == 0)
			continue;

		if (env.quiet) {
			if (env.affinity)
				printf("%.3lf\n", events_mean);
			else
				printf("cpu%02d %.3lf\n", i, events_mean);
		} else {
			printf("cpu%02d: lookup %.3lfM \u00b1 %.3lfM events/sec"
			       " (approximated from %d samples of ~%lums)\n",
			       i, events_mean, 2 * events_stddev,
			       n, mean_time / 1000000);
		}
	}
}

const struct bench bench_local_storage_lookup = {
	.name = "local-storage-lookup",
	.argp = &bench_local_storage_lookup_argp,
	.validate = validate,
	.setup = setup,
	.producer_thread = producer,
	.measure = measure,
	.report_progress = NULL,
	.report_final = report_final,
};
