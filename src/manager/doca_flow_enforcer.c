/*
 * MIDAS DOCA Flow enforcer.
 *
 * Installs RoCEv2 drop rules from a MIDAS mitigation plan. When target_qps are
 * present, the rule matches BTH destination QP in hardware.
 */

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <doca_error.h>
#include <doca_flow.h>

#define MIDAS_MAX_QPS 64
#define MIDAS_MAX_DIPS 64
#define ROCE_UDP_PORT 4791

struct midas_doca_plan {
	int attack_class;
	unsigned qps[MIDAS_MAX_QPS];
	size_t qp_count;
	uint32_t dips[MIDAS_MAX_DIPS];
	size_t dip_count;
};

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
	while (*p && (*p < '0' || *p > '9'))
		p++;
	return *p ? (unsigned)strtoul(p, NULL, 10) : def;
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
		while (*p && (*p < '0' || *p > '9') && *p != ']')
			p++;
		if (!*p || *p == ']')
			break;
		out[n++] = (unsigned)strtoul(p, (char **)&p, 10);
	}
	return n;
}

static size_t parse_ip_array(const char *json, const char *key, uint32_t *out, size_t max)
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
		const char *q = strchr(p, '"');
		if (!q || *q == ']')
			break;
		q++;
		const char *r = strchr(q, '"');
		if (!r)
			break;
		char ip[64];
		size_t len = (size_t)(r - q);
		if (len >= sizeof(ip))
			len = sizeof(ip) - 1;
		memcpy(ip, q, len);
		ip[len] = '\0';
		struct in_addr addr;
		if (inet_pton(AF_INET, ip, &addr) == 1)
			out[n++] = addr.s_addr;
		p = r + 1;
	}
	return n;
}

static int load_plan(const char *path, struct midas_doca_plan *plan)
{
	char *json = read_file(path);
	if (!json)
		return -1;
	memset(plan, 0, sizeof(*plan));
	plan->attack_class = (int)parse_uint_key(json, "attack_class", 0);
	plan->qp_count = parse_uint_array(json, "target_qps", plan->qps, MIDAS_MAX_QPS);
	plan->dip_count = parse_ip_array(json, "target_dips", plan->dips, MIDAS_MAX_DIPS);
	free(json);
	return 0;
}

static void set_qp(uint8_t out[3], unsigned qp)
{
	out[0] = (uint8_t)((qp >> 16) & 0xff);
	out[1] = (uint8_t)((qp >> 8) & 0xff);
	out[2] = (uint8_t)(qp & 0xff);
}

static doca_error_t add_rule(struct doca_flow_port *port,
			     struct doca_flow_pipe *pipe,
			     uint32_t dip,
			     bool has_qp,
			     unsigned qp)
{
	struct doca_flow_match match;
	struct doca_flow_pipe_entry *entry = NULL;
	struct doca_flow_fwd fwd;
	doca_error_t result;

	memset(&match, 0, sizeof(match));
	memset(&fwd, 0, sizeof(fwd));
	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ROCE_V2;
	match.outer.roce_v2.udp.l4_port.dst_port = htons(ROCE_UDP_PORT);
	if (dip != 0)
		match.outer.ip4.dst_ip = dip;
	if (has_qp)
		set_qp(match.outer.roce_v2.bth.dest_qp, qp);
	fwd.type = DOCA_FLOW_FWD_DROP;

	result = doca_flow_pipe_add_entry(0, pipe, &match, NULL, NULL, &fwd, DOCA_FLOW_NO_WAIT, NULL, &entry);
	if (result != DOCA_SUCCESS)
		return result;
	result = doca_flow_entries_process(port, 0, 1000000, 1);
	if (result != DOCA_SUCCESS)
		return result;
	if (doca_flow_pipe_entry_get_status(entry) != DOCA_FLOW_ENTRY_STATUS_SUCCESS)
		return DOCA_ERROR_DRIVER;
	return DOCA_SUCCESS;
}

static doca_error_t create_pipe(struct doca_flow_port *port, struct doca_flow_pipe **pipe)
{
	struct doca_flow_pipe_cfg *cfg = NULL;
	struct doca_flow_match match, mask;
	struct doca_flow_fwd fwd_miss;
	doca_error_t result;

	memset(&match, 0, sizeof(match));
	memset(&mask, 0, sizeof(mask));
	memset(&fwd_miss, 0, sizeof(fwd_miss));
	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	mask.outer.l3_type = 0xff;
	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ROCE_V2;
	mask.outer.l4_type_ext = 0xff;
	match.outer.roce_v2.udp.l4_port.dst_port = htons(ROCE_UDP_PORT);
	mask.outer.roce_v2.udp.l4_port.dst_port = 0xffff;
	mask.outer.ip4.dst_ip = 0xffffffff;
	memset(mask.outer.roce_v2.bth.dest_qp, 0xff, sizeof(mask.outer.roce_v2.bth.dest_qp));
	fwd_miss.type = DOCA_FLOW_FWD_NONE;

	result = doca_flow_pipe_cfg_create(&cfg, port);
	if (result != DOCA_SUCCESS)
		return result;
	result = doca_flow_pipe_cfg_set_name(cfg, "midas_roce_qp_drop");
	if (result != DOCA_SUCCESS)
		goto out;
	result = doca_flow_pipe_cfg_set_type(cfg, DOCA_FLOW_PIPE_BASIC);
	if (result != DOCA_SUCCESS)
		goto out;
	result = doca_flow_pipe_cfg_set_is_root(cfg, true);
	if (result != DOCA_SUCCESS)
		goto out;
	result = doca_flow_pipe_cfg_set_nr_entries(cfg, 4096);
	if (result != DOCA_SUCCESS)
		goto out;
	result = doca_flow_pipe_cfg_set_match(cfg, &match, &mask);
	if (result != DOCA_SUCCESS)
		goto out;
	result = doca_flow_pipe_create(cfg, NULL, &fwd_miss, pipe);
out:
	doca_flow_pipe_cfg_destroy(cfg);
	return result;
}

static doca_error_t start_port(const char *devargs, struct doca_flow_port **port)
{
	struct doca_flow_cfg *flow_cfg = NULL;
	struct doca_flow_port_cfg *port_cfg = NULL;
	doca_error_t result;

	result = doca_flow_cfg_create(&flow_cfg);
	if (result != DOCA_SUCCESS)
		return result;
	doca_flow_cfg_set_pipe_queues(flow_cfg, 1);
	doca_flow_cfg_set_mode_args(flow_cfg, "vnf,hws");
	result = doca_flow_init(flow_cfg);
	doca_flow_cfg_destroy(flow_cfg);
	if (result != DOCA_SUCCESS)
		return result;

	result = doca_flow_port_cfg_create(&port_cfg);
	if (result != DOCA_SUCCESS) {
		doca_flow_destroy();
		return result;
	}
	result = doca_flow_port_cfg_set_devargs(port_cfg, devargs);
	if (result == DOCA_SUCCESS)
		result = doca_flow_port_cfg_set_port_id(port_cfg, 0);
	if (result == DOCA_SUCCESS)
		result = doca_flow_port_start(port_cfg, port);
	doca_flow_port_cfg_destroy(port_cfg);
	if (result != DOCA_SUCCESS)
		doca_flow_destroy();
	return result;
}

static void usage(const char *argv0)
{
	fprintf(stderr, "usage: %s --plan FILE --devargs DEVARGS [--dry-run]\n", argv0);
}

int main(int argc, char **argv)
{
	const char *plan_path = NULL;
	const char *devargs = "mlx5_0";
	bool dry_run = false;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--plan") == 0 && i + 1 < argc)
			plan_path = argv[++i];
		else if (strcmp(argv[i], "--devargs") == 0 && i + 1 < argc)
			devargs = argv[++i];
		else if (strcmp(argv[i], "--dry-run") == 0)
			dry_run = true;
		else {
			usage(argv[0]);
			return 2;
		}
	}
	if (!plan_path) {
		usage(argv[0]);
		return 2;
	}

	struct midas_doca_plan plan;
	if (load_plan(plan_path, &plan) != 0) {
		fprintf(stderr, "failed to read plan: %s\n", plan_path);
		return 1;
	}
	if (plan.attack_class == 0) {
		printf("{\"backend\":\"doca_flow\",\"installed\":0,\"reason\":\"benign\"}\n");
		return 0;
	}
	if (dry_run) {
		printf("{\"backend\":\"doca_flow\",\"devargs\":\"%s\",\"target_qps\":%zu,\"target_dips\":%zu,\"action\":\"drop\"}\n",
		       devargs, plan.qp_count, plan.dip_count);
		return 0;
	}

	struct doca_flow_port *port = NULL;
	struct doca_flow_pipe *pipe = NULL;
	doca_error_t result = start_port(devargs, &port);
	if (result != DOCA_SUCCESS) {
		fprintf(stderr, "doca_flow port start failed: %s\n", doca_error_get_descr(result));
		return 1;
	}
	result = create_pipe(port, &pipe);
	if (result != DOCA_SUCCESS) {
		fprintf(stderr, "doca_flow pipe create failed: %s\n", doca_error_get_descr(result));
		doca_flow_port_stop(port);
		doca_flow_destroy();
		return 1;
	}

	size_t installed = 0;
	size_t qps = plan.qp_count ? plan.qp_count : 1;
	size_t dips = plan.dip_count ? plan.dip_count : 1;
	for (size_t i = 0; i < qps; i++) {
		for (size_t j = 0; j < dips; j++) {
			unsigned qp = plan.qp_count ? plan.qps[i] : 0;
			uint32_t dip = plan.dip_count ? plan.dips[j] : 0;
			result = add_rule(port, pipe, dip, plan.qp_count != 0, qp);
			if (result != DOCA_SUCCESS) {
				fprintf(stderr, "failed to add DOCA Flow rule qp=%u: %s\n",
					qp, doca_error_get_descr(result));
				doca_flow_port_stop(port);
				doca_flow_destroy();
				return 1;
			}
			installed++;
		}
	}

	printf("{\"backend\":\"doca_flow\",\"installed\":%zu,\"action\":\"drop\"}\n", installed);
	doca_flow_port_stop(port);
	doca_flow_destroy();
	return 0;
}
