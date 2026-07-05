/*
 * MIDAS libibverbs QP guard.
 *
 * Usage:
 *   MIDAS_VERBS_PLAN=/path/mitigation_plan.json \
 *   MIDAS_VERBS_LOG=/tmp/midas_verbs_guard.jsonl \
 *   LD_PRELOAD=build/libmidas_verbs_guard.so ./rdma_app
 *
 * The guard enforces the backend-neutral MIDAS mitigation plan at QP granularity
 * before work requests enter the RNIC send queue.
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#define ibv_post_send midas_inline_ibv_post_send
#define ibv_poll_cq midas_inline_ibv_poll_cq
#include <infiniband/verbs.h>
#undef ibv_post_send
#undef ibv_poll_cq
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MIDAS_MAX_QPS 64
#define MIDAS_MAX_RKEYS 256
#define MIDAS_MAX_REGIONS 1024
#define MIDAS_MAX_QP_STATE 256

struct midas_plan {
	int loaded;
	int attack_class;
	unsigned qps[MIDAS_MAX_QPS];
	size_t qp_count;
	unsigned rkeys[MIDAS_MAX_RKEYS];
	size_t rkey_count;
	unsigned queue_depth;
	unsigned max_remote_regions;
	unsigned token_rate;
	unsigned token_burst;
	unsigned wqe_pacing_ns;
	char primary_action[96];
};

struct midas_qp_state {
	unsigned qp_num;
	unsigned outstanding;
	double tokens;
	struct timespec last_refill;
	uint64_t regions[MIDAS_MAX_REGIONS];
	size_t region_count;
};

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct midas_plan g_plan;
static struct midas_qp_state g_states[MIDAS_MAX_QP_STATE];
static time_t g_plan_mtime;
static time_t g_last_check;

static int (*real_ibv_post_send)(struct ibv_qp *, struct ibv_send_wr *, struct ibv_send_wr **) = NULL;
static int (*real_ibv_poll_cq)(struct ibv_cq *, int, struct ibv_wc *) = NULL;

static double elapsed_sec(struct timespec a, struct timespec b)
{
	return (double)(a.tv_sec - b.tv_sec) + (double)(a.tv_nsec - b.tv_nsec) / 1000000000.0;
}

static void log_event(const char *fmt, ...)
{
	const char *path = getenv("MIDAS_VERBS_LOG");
	if (!path || !*path)
		return;
	FILE *fh = fopen(path, "a");
	if (!fh)
		return;
	va_list ap;
	va_start(ap, fmt);
	vfprintf(fh, fmt, ap);
	va_end(ap);
	fputc('\n', fh);
	fclose(fh);
}

static char *read_file(const char *path)
{
	FILE *fh = fopen(path, "rb");
	if (!fh)
		return NULL;
	if (fseek(fh, 0, SEEK_END) != 0) {
		fclose(fh);
		return NULL;
	}
	long n = ftell(fh);
	if (n < 0) {
		fclose(fh);
		return NULL;
	}
	rewind(fh);
	char *buf = calloc((size_t)n + 1, 1);
	if (!buf) {
		fclose(fh);
		return NULL;
	}
	if (fread(buf, 1, (size_t)n, fh) != (size_t)n) {
		free(buf);
		fclose(fh);
		return NULL;
	}
	fclose(fh);
	return buf;
}

static unsigned parse_uint_key(const char *json, const char *key, unsigned def)
{
	char pat[96];
	snprintf(pat, sizeof(pat), "\"%s\"", key);
	const char *p = strstr(json, pat);
	if (!p)
		return def;
	p = strchr(p, ':');
	if (!p)
		return def;
	p++;
	while (*p && !isdigit((unsigned char)*p))
		p++;
	return *p ? (unsigned)strtoul(p, NULL, 10) : def;
}

static int parse_int_key(const char *json, const char *key, int def)
{
	return (int)parse_uint_key(json, key, (unsigned)def);
}

static void parse_string_key(const char *json, const char *key, char *out, size_t out_len)
{
	char pat[96];
	snprintf(pat, sizeof(pat), "\"%s\"", key);
	const char *p = strstr(json, pat);
	if (!p || out_len == 0)
		return;
	p = strchr(p, ':');
	if (!p)
		return;
	p = strchr(p, '"');
	if (!p)
		return;
	p++;
	const char *q = strchr(p, '"');
	if (!q)
		return;
	size_t n = (size_t)(q - p);
	if (n >= out_len)
		n = out_len - 1;
	memcpy(out, p, n);
	out[n] = '\0';
}

static size_t parse_uint_array(const char *json, const char *key, unsigned *out, size_t max)
{
	char pat[96];
	snprintf(pat, sizeof(pat), "\"%s\"", key);
	const char *p = strstr(json, pat);
	if (!p)
		return 0;
	p = strchr(p, '[');
	if (!p)
		return 0;
	p++;
	size_t n = 0;
	while (*p && *p != ']' && n < max) {
		while (*p && !isdigit((unsigned char)*p) && *p != ']')
			p++;
		if (*p == ']' || !*p)
			break;
		out[n++] = (unsigned)strtoul(p, (char **)&p, 10);
	}
	return n;
}

static void reload_plan_locked(void)
{
	const char *path = getenv("MIDAS_VERBS_PLAN");
	struct stat st;
	time_t now = time(NULL);
	if (!path || !*path)
		return;
	if (now == g_last_check)
		return;
	g_last_check = now;
	if (stat(path, &st) != 0 || (g_plan.loaded && st.st_mtime == g_plan_mtime))
		return;

	char *json = read_file(path);
	if (!json)
		return;
	struct midas_plan next;
	memset(&next, 0, sizeof(next));
	next.loaded = 1;
	next.attack_class = parse_int_key(json, "attack_class", 0);
	next.queue_depth = parse_uint_key(json, "queue_depth", 128);
	next.max_remote_regions = parse_uint_key(json, "max_remote_regions", 4);
	next.token_rate = parse_uint_key(json, "token_rate", 4096);
	next.token_burst = parse_uint_key(json, "token_burst", 8192);
	next.wqe_pacing_ns = parse_uint_key(json, "wqe_pacing_ns", 1000);
	next.qp_count = parse_uint_array(json, "target_qps", next.qps, MIDAS_MAX_QPS);
	next.rkey_count = parse_uint_array(json, "target_rkeys", next.rkeys, MIDAS_MAX_RKEYS);
	parse_string_key(json, "primary_action", next.primary_action, sizeof(next.primary_action));
	g_plan = next;
	g_plan_mtime = st.st_mtime;
	free(json);
	log_event("{\"event\":\"plan_reload\",\"attack_class\":%d,\"target_qps\":%zu,\"action\":\"%s\"}",
		  g_plan.attack_class, g_plan.qp_count, g_plan.primary_action);
}

static bool qp_targeted_locked(unsigned qp_num)
{
	if (!g_plan.loaded || g_plan.attack_class == 0 || g_plan.qp_count == 0)
		return false;
	for (size_t i = 0; i < g_plan.qp_count; i++) {
		if (g_plan.qps[i] == qp_num)
			return true;
	}
	return false;
}

static struct midas_qp_state *state_for_qp_locked(unsigned qp_num)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	for (size_t i = 0; i < MIDAS_MAX_QP_STATE; i++) {
		if (g_states[i].qp_num == qp_num)
			return &g_states[i];
	}
	for (size_t i = 0; i < MIDAS_MAX_QP_STATE; i++) {
		if (g_states[i].qp_num == 0) {
			g_states[i].qp_num = qp_num;
			g_states[i].tokens = (double)(g_plan.token_burst ? g_plan.token_burst : 1);
			g_states[i].last_refill = now;
			return &g_states[i];
		}
	}
	return NULL;
}

static unsigned wr_chain_len(struct ibv_send_wr *wr)
{
	unsigned n = 0;
	for (; wr; wr = wr->next)
		n++;
	return n;
}

static bool rkey_targeted_locked(uint32_t rkey)
{
	if (g_plan.rkey_count == 0)
		return true;
	for (size_t i = 0; i < g_plan.rkey_count; i++) {
		if (g_plan.rkeys[i] == rkey)
			return true;
	}
	return false;
}

static bool add_remote_region_locked(struct midas_qp_state *st, uint64_t addr, uint32_t rkey)
{
	uint64_t key = (addr & 0xffffffff00000000ULL) ^ ((uint64_t)rkey << 1) ^ (addr >> 12);
	for (size_t i = 0; i < st->region_count; i++) {
		if (st->regions[i] == key)
			return true;
	}
	if (st->region_count >= MIDAS_MAX_REGIONS)
		return false;
	st->regions[st->region_count++] = key;
	return true;
}

static int enforce_remote_diversity_locked(unsigned qp_num, struct midas_qp_state *st, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr)
{
	unsigned max_regions = g_plan.max_remote_regions ? g_plan.max_remote_regions : 1;
	for (struct ibv_send_wr *cur = wr; cur; cur = cur->next) {
		if (cur->opcode != IBV_WR_RDMA_WRITE && cur->opcode != IBV_WR_RDMA_WRITE_WITH_IMM &&
		    cur->opcode != IBV_WR_RDMA_READ)
			continue;
		if (!rkey_targeted_locked(cur->wr.rdma.rkey))
			continue;
		if (!add_remote_region_locked(st, cur->wr.rdma.remote_addr, cur->wr.rdma.rkey) ||
		    st->region_count > max_regions) {
			if (bad_wr)
				*bad_wr = cur;
			log_event("{\"event\":\"reject\",\"reason\":\"remote_region_limit\",\"qp\":%u,\"regions\":%zu,\"limit\":%u}",
				  qp_num, st->region_count, max_regions);
			errno = EACCES;
			return EACCES;
		}
	}
	return 0;
}

static int enforce_token_bucket_locked(unsigned qp_num, struct midas_qp_state *st, unsigned cost, struct ibv_send_wr **bad_wr, struct ibv_send_wr *wr)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	double rate = (double)(g_plan.token_rate ? g_plan.token_rate : 1);
	double burst = (double)(g_plan.token_burst ? g_plan.token_burst : 1);
	st->tokens += elapsed_sec(now, st->last_refill) * rate;
	if (st->tokens > burst)
		st->tokens = burst;
	st->last_refill = now;
	if (st->tokens < (double)cost) {
		if (bad_wr)
			*bad_wr = wr;
		log_event("{\"event\":\"reject\",\"reason\":\"token_bucket\",\"qp\":%u,\"tokens\":%.3f,\"cost\":%u}",
			  qp_num, st->tokens, cost);
		errno = EAGAIN;
		return EAGAIN;
	}
	st->tokens -= (double)cost;
	return 0;
}

static int enforce_plan_locked(struct ibv_qp *qp, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr)
{
	unsigned qp_num = qp ? qp->qp_num : 0;
	unsigned count = wr_chain_len(wr);
	if (!qp_targeted_locked(qp_num))
		return 0;
	struct midas_qp_state *st = state_for_qp_locked(qp_num);
	if (!st)
		return 0;

	if (g_plan.attack_class == 1) {
		unsigned limit = g_plan.queue_depth ? g_plan.queue_depth : 1;
		if (st->outstanding + count > limit) {
			if (bad_wr)
				*bad_wr = wr;
			log_event("{\"event\":\"reject\",\"reason\":\"queue_depth\",\"qp\":%u,\"outstanding\":%u,\"new_wr\":%u,\"limit\":%u}",
				  qp_num, st->outstanding, count, limit);
			errno = EAGAIN;
			return EAGAIN;
		}
	}

	if (g_plan.attack_class == 2) {
		int rc = enforce_remote_diversity_locked(qp_num, st, wr, bad_wr);
		if (rc)
			return rc;
	}

	if (g_plan.attack_class == 3 || g_plan.attack_class == 4) {
		int rc = enforce_token_bucket_locked(qp_num, st, count, bad_wr, wr);
		if (rc)
			return rc;
		if (g_plan.wqe_pacing_ns > 0) {
			struct timespec req = {
				.tv_sec = g_plan.wqe_pacing_ns / 1000000000U,
				.tv_nsec = g_plan.wqe_pacing_ns % 1000000000U,
			};
			nanosleep(&req, NULL);
		}
	}

	st->outstanding += count;
	return 0;
}

int ibv_post_send(struct ibv_qp *qp, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr)
{
	if (!real_ibv_post_send)
		real_ibv_post_send = dlsym(RTLD_NEXT, "ibv_post_send");
	if (!real_ibv_post_send) {
		errno = ENOSYS;
		return ENOSYS;
	}

	pthread_mutex_lock(&g_lock);
	reload_plan_locked();
	int rc = enforce_plan_locked(qp, wr, bad_wr);
	pthread_mutex_unlock(&g_lock);
	if (rc)
		return rc;
	return real_ibv_post_send(qp, wr, bad_wr);
}

int ibv_poll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *wc)
{
	if (!real_ibv_poll_cq)
		real_ibv_poll_cq = dlsym(RTLD_NEXT, "ibv_poll_cq");
	if (!real_ibv_poll_cq) {
		errno = ENOSYS;
		return -1;
	}
	int n = real_ibv_poll_cq(cq, num_entries, wc);
	if (n <= 0)
		return n;
	pthread_mutex_lock(&g_lock);
	for (int i = 0; i < n; i++) {
		unsigned qp_num = wc[i].qp_num;
		for (size_t s = 0; s < MIDAS_MAX_QP_STATE; s++) {
			if (g_states[s].qp_num == qp_num && g_states[s].outstanding > 0) {
				g_states[s].outstanding--;
				break;
			}
		}
	}
	pthread_mutex_unlock(&g_lock);
	return n;
}
