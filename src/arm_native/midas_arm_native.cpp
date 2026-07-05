// MIDAS Arm-native detector/manager path.
//
// Reads MIDAS JSONL records from stdin or --input and emits one mitigation
// window as JSON. This native path covers EWMA-CUSUM, interval active-QP
// density, hot-QP summarization, heuristic classification, and attack-specific
// mitigation planning. The Python runtime remains the operator-friendly path
// for training, offline reproduction, and numpy LSTM-GRU inference.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

struct Record {
	double ts = 0.0;
	std::string dip = "unknown";
	int dqp = -1;
	int op = 0;
	int len = 0;
	double rate = 0.0;
	int alert = 0;
};

struct QPState {
	bool has_ewma = false;
	double ewma = 0.0;
	double cusum = 0.0;
};

struct Detection {
	Record rec;
	double ewma = 0.0;
	double cusum = 0.0;
	int alert = 0;
};

static std::string json_string(const std::string &s)
{
	std::ostringstream out;
	out << '"';
	for (char c : s) {
		if (c == '"' || c == '\\')
			out << '\\' << c;
		else if (c == '\n')
			out << "\\n";
		else
			out << c;
	}
	out << '"';
	return out.str();
}

static bool find_number(const std::string &line, const std::string &key, double &out)
{
	const std::string needle = "\"" + key + "\"";
	size_t pos = line.find(needle);
	if (pos == std::string::npos)
		return false;
	pos = line.find(':', pos);
	if (pos == std::string::npos)
		return false;
	pos++;
	while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t'))
		pos++;
	size_t end = pos;
	while (end < line.size() && (std::isdigit((unsigned char)line[end]) || line[end] == '-' ||
				     line[end] == '+' || line[end] == '.' || line[end] == 'e' || line[end] == 'E'))
		end++;
	if (end == pos)
		return false;
	out = std::strtod(line.c_str() + pos, nullptr);
	return true;
}

static bool find_string(const std::string &line, const std::string &key, std::string &out)
{
	const std::string needle = "\"" + key + "\"";
	size_t pos = line.find(needle);
	if (pos == std::string::npos)
		return false;
	pos = line.find(':', pos);
	if (pos == std::string::npos)
		return false;
	pos = line.find('"', pos + 1);
	if (pos == std::string::npos)
		return false;
	size_t end = line.find('"', pos + 1);
	if (end == std::string::npos)
		return false;
	out = line.substr(pos + 1, end - pos - 1);
	return true;
}

static Record parse_record(const std::string &line)
{
	Record r;
	double v = 0.0;
	find_string(line, "dip", r.dip);
	if (find_number(line, "ts", v))
		r.ts = v;
	if (find_number(line, "dqp", v))
		r.dqp = (int)v;
	if (find_number(line, "op", v))
		r.op = (int)v;
	if (find_number(line, "len", v))
		r.len = (int)v;
	if (find_number(line, "rate", v))
		r.rate = v;
	if (find_number(line, "alert", v))
		r.alert = (int)v;
	return r;
}

static int alert_level(double score, double threshold, double warm_ratio)
{
	if (threshold <= 0)
		return score > 0 ? 2 : 0;
	if (score >= threshold)
		return 2;
	if (score >= threshold * warm_ratio)
		return 1;
	return 0;
}

static const char *attack_name(int cls)
{
	switch (cls) {
	case 0: return "Benign";
	case 1: return "QueueFlooding";
	case 2: return "CacheDepletion";
	case 3: return "VerbsFlooding";
	case 4: return "VerbsAmplification";
	default: return "Unknown";
	}
}

static const char *primary_action(int cls)
{
	switch (cls) {
	case 0: return "allow";
	case 1: return "queue_depth_limit_or_qp_reallocation";
	case 2: return "address_diversity_limit";
	case 3:
	case 4: return "token_bucket_or_wqe_pacing";
	default: return "rate_limit";
	}
}

int main(int argc, char **argv)
{
	std::string input_path;
	double alpha = 0.3;
	double tau_qp = 1000000.0;
	double tau_cont = 10.0;
	int interval_ms = 100;
	bool trust_input_alert = false;
	for (int i = 1; i < argc; i++) {
		std::string arg = argv[i];
		if (arg == "--input" && i + 1 < argc)
			input_path = argv[++i];
		else if (arg == "--alpha" && i + 1 < argc)
			alpha = std::strtod(argv[++i], nullptr);
		else if (arg == "--tau-qp" && i + 1 < argc)
			tau_qp = std::strtod(argv[++i], nullptr);
		else if (arg == "--tau-cont" && i + 1 < argc)
			tau_cont = std::strtod(argv[++i], nullptr);
		else if (arg == "--interval-ms" && i + 1 < argc)
			interval_ms = std::atoi(argv[++i]);
		else if (arg == "--trust-input-alert")
			trust_input_alert = true;
	}

	std::ifstream file;
	std::istream *in = &std::cin;
	if (!input_path.empty()) {
		file.open(input_path);
		if (!file) {
			std::cerr << "failed to open " << input_path << "\n";
			return 2;
		}
		in = &file;
	}

	std::map<std::string, QPState> qps;
	std::map<std::string, QPState> containers;
	std::map<std::string, int64_t> active_bucket;
	std::map<std::string, std::set<int>> active_qps;
	std::vector<Detection> detections;
	std::string line;
	while (std::getline(*in, line)) {
		if (line.empty())
			continue;
		Record r = parse_record(line);
		std::string key = r.dip + ":" + std::to_string(r.dqp);
		QPState &s = qps[key];
		double ewma = s.has_ewma ? alpha * r.rate + (1.0 - alpha) * s.ewma : r.rate;
		double cusum = std::max(0.0, s.cusum + r.rate - ewma);
		s.has_ewma = true;
		s.ewma = ewma;
		s.cusum = cusum;

		int64_t bucket = (int64_t)std::floor(r.ts / std::max(0.001, interval_ms / 1000.0));
		if (!active_bucket.count(r.dip) || active_bucket[r.dip] != bucket) {
			active_qps[r.dip].clear();
			active_bucket[r.dip] = bucket;
		}
		active_qps[r.dip].insert(r.dqp);
		double count = (double)active_qps[r.dip].size();
		QPState &cs = containers[r.dip];
		double cewma = cs.has_ewma ? alpha * count + (1.0 - alpha) * cs.ewma : count;
		double ccusum = std::max(0.0, cs.cusum + count - cewma);
		cs.has_ewma = true;
		cs.ewma = cewma;
		cs.cusum = ccusum;

		int qalert = alert_level(cusum, tau_qp, 0.5);
		int calert = alert_level(ccusum, tau_cont, 0.5);
		int input_alert = trust_input_alert ? r.alert : 0;
		detections.push_back({r, ewma, cusum, std::max(input_alert, std::max(qalert, calert))});
	}

	std::map<int, int> qp_counts;
	std::map<int, int> op_counts;
	std::set<std::string> dips;
	double max_cusum = 0.0;
	int hot = 0;
	int zero_len = 0;
	for (const auto &d : detections) {
		if (d.rec.dqp >= 0)
			qp_counts[d.rec.dqp]++;
		op_counts[d.rec.op]++;
		dips.insert(d.rec.dip);
		max_cusum = std::max(max_cusum, d.cusum);
		if (d.alert == 2)
			hot++;
		if (d.rec.len <= 0)
			zero_len++;
	}
	double hot_ratio = detections.empty() ? 0.0 : (double)hot / detections.size();
	double zero_ratio = detections.empty() ? 0.0 : (double)zero_len / detections.size();
	int attack_class = 0;
	if (hot_ratio >= 0.05) {
		if (qp_counts.size() >= 2 && zero_ratio > 0.8)
			attack_class = 1;
		else if (op_counts.size() >= 3)
			attack_class = 3;
		else
			attack_class = 1;
	}

	std::vector<std::pair<int, int>> ranked(qp_counts.begin(), qp_counts.end());
	std::sort(ranked.begin(), ranked.end(), [](const auto &a, const auto &b) {
		if (a.second != b.second)
			return a.second > b.second;
		return a.first < b.first;
	});

	std::cout << "{";
	std::cout << "\"samples\":" << detections.size();
	std::cout << ",\"unique_qps\":" << qp_counts.size();
	std::cout << ",\"unique_dips\":" << dips.size();
	std::cout << ",\"hot_ratio\":" << hot_ratio;
	std::cout << ",\"max_cusum\":" << max_cusum;
	std::cout << ",\"attack_class\":" << attack_class;
	std::cout << ",\"attack_name\":" << json_string(attack_name(attack_class));
	std::cout << ",\"mitigation_plan\":{";
	std::cout << "\"primary_action\":" << json_string(primary_action(attack_class));
	std::cout << ",\"backend\":\"tc\"";
	std::cout << ",\"tc_mode\":\"police\"";
	std::cout << ",\"rate\":\"" << (attack_class >= 3 ? "50mbit" : "100mbit") << "\"";
	std::cout << ",\"burst\":\"" << (attack_class >= 3 ? "512kb" : "1mb") << "\"";
	std::cout << ",\"target_qps\":[";
	for (size_t i = 0; i < ranked.size() && i < 8; i++) {
		if (i)
			std::cout << ",";
		std::cout << ranked[i].first;
	}
	std::cout << "],\"target_dips\":[";
	size_t idx = 0;
	for (const auto &dip : dips) {
		if (idx++)
			std::cout << ",";
		std::cout << json_string(dip);
	}
	std::cout << "]}}";
	std::cout << "\n";
	return 0;
}
