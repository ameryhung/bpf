// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include "bpf_tracing_net.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#define NR_SLOTS 32
#define NR_CPUS 256
#define CPU_MASK (NR_CPUS - 1)

/* Configured by userspace */
u64 nr_loops;
__u32 bench_pid = 0;
__u32 use_hashmap = 0;
__u32 use_rhashtab = 0;
__u32 do_update = 0;
__u32 setup_done = 0;

/* In-kernel timing */
u64 __attribute__((__aligned__(256))) percpu_times_index[NR_CPUS];
u64 __attribute__((__aligned__(256))) percpu_times[NR_CPUS][NR_SLOTS];

long setup_errs = 0;

struct storage {
	__u8 data[64];
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct storage);
} sk_storage_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 50000);
	__type(key, __u64);
	__type(value, struct storage);
} hash_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RHASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 50000);
	__type(key, __u64);
	__type(value, struct storage);
} rhash_map SEC(".maps");

SEC("lsm.s/socket_post_create")
int BPF_PROG(socket_post_create, struct socket *sock, int family, int type,
	     int protocol, int kern)
{
	struct sock *sk = sock->sk;
	__u32 pid;

	if (setup_done)
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != bench_pid || !sk)
		return 0;

	if (use_hashmap || use_rhashtab) {
		__u64 sk_key = (unsigned long)sk;
		struct storage val = {};
		void *map = use_rhashtab ? (void *)&rhash_map : (void *)&hash_map;

		if (bpf_map_update_elem(map, &sk_key, &val, BPF_ANY))
			__sync_fetch_and_add(&setup_errs, 1);
	} else {
		struct storage *stg;

		stg = bpf_sk_storage_get(&sk_storage_map, sk, NULL,
					 BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (!stg)
			__sync_fetch_and_add(&setup_errs, 1);
	}

	return 0;
}

SEC("lsm/socket_getsockopt")
int BPF_PROG(socket_getsockopt, struct socket *sock, int level, int optname)
{
	struct sock *sk = sock->sk;
	u32 cpu, times_index;
	u64 start_time;
	int i;

	if (bpf_get_current_pid_tgid() >> 32 != bench_pid || !sk)
		return 0;

	cpu = bpf_get_smp_processor_id();
	times_index = percpu_times_index[cpu & CPU_MASK] % NR_SLOTS;
	start_time = bpf_ktime_get_ns();

	bpf_for(i, 0, nr_loops) {
		struct storage *stg;

		if (use_hashmap || use_rhashtab) {
			__u64 key = (unsigned long)sk;
			void *map = use_rhashtab ? (void *)&rhash_map
						 : (void *)&hash_map;

			stg = bpf_map_lookup_elem(map, &key);
		} else {
			stg = bpf_sk_storage_get(&sk_storage_map, sk, NULL, 0);
		}
		if (stg && do_update)
			stg->data[0]++;
	}

	percpu_times[cpu & CPU_MASK][times_index] = bpf_ktime_get_ns() - start_time;
	percpu_times_index[cpu & CPU_MASK] += 1;

	return 0;
}

SEC("fentry/inet_sock_destruct")
int BPF_PROG(hashmap_socket_destroy, struct sock *sk)
{
	__u64 key;
	__u32 pid;
	void *map;

	if (!use_hashmap && !use_rhashtab)
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != bench_pid)
		return 0;

	key = (unsigned long)sk;
	map = use_rhashtab ? (void *)&rhash_map : (void *)&hash_map;
	bpf_map_delete_elem(map, &key);

	return 0;
}

char __license[] SEC("license") = "GPL";
