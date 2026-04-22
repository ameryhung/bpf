// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include "bpf_tracing_net.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

long create_errs = 0;
long create_cnts = 0;
__u32 bench_pid = 0;
__u32 use_hashmap = 0;

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
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct storage);
} task_storage_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 50000);
	__type(key, __u64);
	__type(value, struct storage);
} hash_map SEC(".maps");

SEC("tp_btf/sched_process_fork")
int BPF_PROG(sched_process_fork, struct task_struct *parent, struct task_struct *child)
{
	struct storage *stg;

	if (parent->tgid != bench_pid)
		return 0;

	stg = bpf_task_storage_get(&task_storage_map, child, NULL,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (stg)
		__sync_fetch_and_add(&create_cnts, 1);
	else
		__sync_fetch_and_add(&create_errs, 1);

	return 0;
}

SEC("lsm.s/socket_post_create")
int BPF_PROG(socket_post_create, struct socket *sock, int family, int type,
	     int protocol, int kern)
{
	struct sock *sk = sock->sk;
	__u32 pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != bench_pid || !sk)
		return 0;

	if (use_hashmap) {
		__u64 key = (unsigned long)sk;
		struct storage val = {};

		if (!bpf_map_update_elem(&hash_map, &key, &val, BPF_ANY))
			__sync_fetch_and_add(&create_cnts, 1);
		else
			__sync_fetch_and_add(&create_errs, 1);
	} else {
		struct storage *stg;

		stg = bpf_sk_storage_get(&sk_storage_map, sk, NULL,
					 BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (stg)
			__sync_fetch_and_add(&create_cnts, 1);
		else
			__sync_fetch_and_add(&create_errs, 1);
	}

	return 0;
}

SEC("fentry/inet_sock_destruct")
int BPF_PROG(hashmap_socket_destroy, struct sock *sk)
{
	__u64 key;
	__u32 pid;

	if (!use_hashmap)
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != bench_pid)
		return 0;

	key = (unsigned long)sk;
	bpf_map_delete_elem(&hash_map, &key);

	return 0;
}

char __license[] SEC("license") = "GPL";
