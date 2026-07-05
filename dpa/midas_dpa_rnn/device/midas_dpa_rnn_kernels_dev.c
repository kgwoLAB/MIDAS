#include <doca_dpa_dev.h>

#include "midas_rnn_fixed_input.h"
#include "midas_rnn_fixed_weights.h"

static int clamp_i32(long long v, int lo, int hi)
{
	if (v < lo)
		return lo;
	if (v > hi)
		return hi;
	return (int)v;
}

static int qmul(int a, int b)
{
	return (int)(((long long)a * (long long)b) / MIDAS_Q);
}

static int sigmoid_q(int x)
{
	if (x <= -4 * MIDAS_Q)
		return 0;
	if (x >= 4 * MIDAS_Q)
		return MIDAS_Q;
	return clamp_i32((MIDAS_Q / 2) + (x / 4), 0, MIDAS_Q);
}

static int tanh_q(int x)
{
	if (x <= -MIDAS_Q)
		return -MIDAS_Q;
	if (x >= MIDAS_Q)
		return MIDAS_Q;
	return x;
}

static void matvec_add_q(int *out, const int *w, int rows, int cols, const int *x, const int *b)
{
	for (int r = 0; r < rows; r++) {
		long long v = b ? b[r] : 0;
		const int *row = w + r * cols;
		for (int c = 0; c < cols; c++)
			v += ((long long)row[c] * (long long)x[c]) / MIDAS_Q;
		out[r] = clamp_i32(v, -2140000000, 2140000000);
	}
}

static void lstm_forward_q(const int *input_window_q, int h[MIDAS_HIDDEN_DIM])
{
	int c[MIDAS_HIDDEN_DIM] = {0};
	int gates[4 * MIDAS_HIDDEN_DIM];
	int ih[4 * MIDAS_HIDDEN_DIM];
	int hh[4 * MIDAS_HIDDEN_DIM];

	for (int i = 0; i < MIDAS_HIDDEN_DIM; i++)
		h[i] = 0;
	for (int t = 0; t < MIDAS_TIMESTEPS; t++) {
		const int *x = &input_window_q[t * MIDAS_FEATURE_DIM];
		matvec_add_q(ih, midas_lstm_weight_ih_l0_q, 4 * MIDAS_HIDDEN_DIM, MIDAS_FEATURE_DIM, x, NULL);
		matvec_add_q(hh, midas_lstm_weight_hh_l0_q, 4 * MIDAS_HIDDEN_DIM, MIDAS_HIDDEN_DIM, h, NULL);
		for (int i = 0; i < 4 * MIDAS_HIDDEN_DIM; i++)
			gates[i] = ih[i] + hh[i] + midas_lstm_bias_ih_l0_q[i] + midas_lstm_bias_hh_l0_q[i];
		for (int i = 0; i < MIDAS_HIDDEN_DIM; i++) {
			int in_gate = sigmoid_q(gates[i]);
			int forget_gate = sigmoid_q(gates[MIDAS_HIDDEN_DIM + i]);
			int cell_gate = tanh_q(gates[2 * MIDAS_HIDDEN_DIM + i]);
			int out_gate = sigmoid_q(gates[3 * MIDAS_HIDDEN_DIM + i]);
			c[i] = qmul(forget_gate, c[i]) + qmul(in_gate, cell_gate);
			c[i] = clamp_i32(c[i], -4 * MIDAS_Q, 4 * MIDAS_Q);
			h[i] = qmul(out_gate, tanh_q(c[i]));
		}
	}
}

static void gru_forward_q(const int *input_window_q, int h[MIDAS_HIDDEN_DIM])
{
	int gi[3 * MIDAS_HIDDEN_DIM];
	int gh[3 * MIDAS_HIDDEN_DIM];

	for (int i = 0; i < MIDAS_HIDDEN_DIM; i++)
		h[i] = 0;
	for (int t = 0; t < MIDAS_TIMESTEPS; t++) {
		const int *x = &input_window_q[t * MIDAS_FEATURE_DIM];
		matvec_add_q(gi, midas_gru_weight_ih_l0_q, 3 * MIDAS_HIDDEN_DIM, MIDAS_FEATURE_DIM, x, midas_gru_bias_ih_l0_q);
		matvec_add_q(gh, midas_gru_weight_hh_l0_q, 3 * MIDAS_HIDDEN_DIM, MIDAS_HIDDEN_DIM, h, midas_gru_bias_hh_l0_q);
		for (int i = 0; i < MIDAS_HIDDEN_DIM; i++) {
			int r = sigmoid_q(gi[i] + gh[i]);
			int z = sigmoid_q(gi[MIDAS_HIDDEN_DIM + i] + gh[MIDAS_HIDDEN_DIM + i]);
			int n = tanh_q(gi[2 * MIDAS_HIDDEN_DIM + i] + qmul(r, gh[2 * MIDAS_HIDDEN_DIM + i]));
			h[i] = qmul(MIDAS_Q - z, n) + qmul(z, h[i]);
		}
	}
}

static int midas_classify_q(const int *input_window_q, int logits[MIDAS_CLASSES])
{
	int lstm_h[MIDAS_HIDDEN_DIM];
	int gru_h[MIDAS_HIDDEN_DIM];
	int best = 0;

	lstm_forward_q(input_window_q, lstm_h);
	gru_forward_q(input_window_q, gru_h);
	for (int cls = 0; cls < MIDAS_CLASSES; cls++) {
		long long v = midas_fc_bias_q[cls];
		for (int i = 0; i < MIDAS_HIDDEN_DIM; i++) {
			v += ((long long)midas_fc_weight_q[cls * (2 * MIDAS_HIDDEN_DIM) + i] * lstm_h[i]) / MIDAS_Q;
			v += ((long long)midas_fc_weight_q[cls * (2 * MIDAS_HIDDEN_DIM) + MIDAS_HIDDEN_DIM + i] * gru_h[i]) / MIDAS_Q;
		}
		logits[cls] = clamp_i32(v, -2140000000, 2140000000);
		if (cls == 0 || logits[cls] > logits[best])
			best = cls;
	}
	return best;
}

__dpa_global__ void midas_rnn_kernel(doca_dpa_dev_uintptr_t input_windows_q_addr,
				     doca_dpa_dev_uintptr_t output_logits_q_addr,
				     unsigned int window_count)
{
	int logits[MIDAS_CLASSES];
	unsigned int rank = doca_dpa_dev_thread_rank();
	const int *input_window_q = midas_input_window_q;

	if (input_windows_q_addr != 0 && rank < window_count) {
		const int *base = (const int *)input_windows_q_addr;
		input_window_q = &base[rank * MIDAS_TIMESTEPS * MIDAS_FEATURE_DIM];
	}

	int best = midas_classify_q(input_window_q, logits);
	if (output_logits_q_addr != 0 && rank < window_count) {
		int *out = (int *)output_logits_q_addr;
		int *slot = &out[rank * (MIDAS_CLASSES + 1)];
		slot[0] = best;
		for (int cls = 0; cls < MIDAS_CLASSES; cls++)
			slot[cls + 1] = logits[cls];
	}
	DOCA_DPA_DEV_LOG_INFO("MIDAS DPA fixed LSTM-GRU class=%d expected=%d qlogits=%d,%d,%d,%d,%d\n",
			      best,
			      MIDAS_EXPECTED_CLASS,
			      logits[0],
			      logits[1],
			      logits[2],
			      logits[3],
			      logits[4]);
}
