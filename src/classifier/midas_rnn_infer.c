#include "midas_rnn.h"
#include "generated/midas_rnn_weights.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static float sigmoidf_clamped(float x) {
    if (x < -60.0f) x = -60.0f;
    if (x > 60.0f) x = 60.0f;
    return 1.0f / (1.0f + expf(-x));
}

static double json_number(const char *line, const char *key, double fallback) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(line, pattern);
    if (!p) return fallback;
    p = strchr(p + strlen(pattern), ':');
    if (!p) return fallback;
    p++;
    while (*p && isspace((unsigned char)*p)) p++;
    return strtod(p, NULL);
}

static int load_features(const char *path, float x[MIDAS_TIMESTEPS][MIDAS_FEATURE_DIM]) {
    FILE *fh = fopen(path, "r");
    if (!fh) return -1;

    char line[8192];
    int n = 0;
    double prev_psn = -1.0;
    float last[MIDAS_FEATURE_DIM] = {0};

    while (n < MIDAS_TIMESTEPS && fgets(line, sizeof(line), fh)) {
        double rate = json_number(line, "rate", 0.0);
        double ewma = json_number(line, "ewma", json_number(line, "midas_ewma", 0.0));
        double cusum = json_number(line, "cusum", json_number(line, "midas_cusum", 0.0));
        double op = json_number(line, "op", 0.0);
        double len = json_number(line, "len", 0.0);
        double psn = json_number(line, "psn", 0.0);
        double rx_data = json_number(line, "rx_data", json_number(line, "port_rx_data", 0.0));
        double tx_data = json_number(line, "tx_data", json_number(line, "port_tx_data", 0.0));
        double pause = json_number(line, "pause", json_number(line, "port_pause", 0.0));
        double pause_dur = json_number(line, "pause_dur", json_number(line, "port_pause_dur", 0.0));
        double cache_hit = json_number(line, "cache_hit", json_number(line, "port_cache_hit", 0.0));
        double delta_psn = 0.0;
        if (prev_psn >= 0.0 && psn >= prev_psn) delta_psn = psn - prev_psn;
        prev_psn = psn;

        for (int j = 0; j < MIDAS_FEATURE_DIM; j++) last[j] = 0.0f;
        if (MIDAS_FEATURE_DIM > 0) last[0] = log1pf((float)rate);
        if (MIDAS_FEATURE_DIM > 1) last[1] = log1pf((float)ewma);
        if (MIDAS_FEATURE_DIM > 2) last[2] = log1pf((float)cusum);
        if (MIDAS_FEATURE_DIM > 3) last[3] = (float)(op / 255.0);
        if (MIDAS_FEATURE_DIM > 4) last[4] = log1pf((float)len);
        if (MIDAS_FEATURE_DIM > 5) last[5] = log1pf((float)delta_psn);
        if (MIDAS_FEATURE_DIM > 6) last[6] = log1pf((float)rx_data);
        if (MIDAS_FEATURE_DIM > 7) last[7] = log1pf((float)tx_data);
        if (MIDAS_FEATURE_DIM > 8) last[8] = log1pf((float)pause);
        if (MIDAS_FEATURE_DIM > 9) last[9] = log1pf((float)pause_dur);
        if (MIDAS_FEATURE_DIM > 10) last[10] = log1pf((float)cache_hit);
        for (int j = 0; j < MIDAS_FEATURE_DIM; j++) {
            x[n][j] = (last[j] - midas_feature_mean[j]) / midas_feature_std[j];
        }
        n++;
    }
    fclose(fh);

    if (n == 0) {
        for (int j = 0; j < MIDAS_FEATURE_DIM; j++) {
            last[j] = (0.0f - midas_feature_mean[j]) / midas_feature_std[j];
        }
        n = 1;
    }
    for (int i = n; i < MIDAS_TIMESTEPS; i++) {
        for (int j = 0; j < MIDAS_FEATURE_DIM; j++) x[i][j] = x[n - 1][j];
    }
    return n;
}

static void matvec_add(float *out, const float *w, int rows, int cols, const float *x, const float *b) {
    for (int r = 0; r < rows; r++) {
        float v = b ? b[r] : 0.0f;
        const float *row = w + r * cols;
        for (int c = 0; c < cols; c++) v += row[c] * x[c];
        out[r] = v;
    }
}

static void lstm_forward(float x[MIDAS_TIMESTEPS][MIDAS_FEATURE_DIM], float h[MIDAS_HIDDEN_DIM]) {
    float c[MIDAS_HIDDEN_DIM] = {0};
    for (int i = 0; i < MIDAS_HIDDEN_DIM; i++) h[i] = 0.0f;

    float gates[4 * MIDAS_HIDDEN_DIM];
    float ih[4 * MIDAS_HIDDEN_DIM];
    float hh[4 * MIDAS_HIDDEN_DIM];
    float bias[4 * MIDAS_HIDDEN_DIM];
    for (int i = 0; i < 4 * MIDAS_HIDDEN_DIM; i++) {
        bias[i] = midas_lstm_bias_ih_l0[i] + midas_lstm_bias_hh_l0[i];
    }

    for (int t = 0; t < MIDAS_TIMESTEPS; t++) {
        matvec_add(ih, midas_lstm_weight_ih_l0, 4 * MIDAS_HIDDEN_DIM, MIDAS_FEATURE_DIM, x[t], NULL);
        matvec_add(hh, midas_lstm_weight_hh_l0, 4 * MIDAS_HIDDEN_DIM, MIDAS_HIDDEN_DIM, h, NULL);
        for (int i = 0; i < 4 * MIDAS_HIDDEN_DIM; i++) gates[i] = ih[i] + hh[i] + bias[i];
        for (int i = 0; i < MIDAS_HIDDEN_DIM; i++) {
            float in_gate = sigmoidf_clamped(gates[i]);
            float forget_gate = sigmoidf_clamped(gates[MIDAS_HIDDEN_DIM + i]);
            float cell_gate = tanhf(gates[2 * MIDAS_HIDDEN_DIM + i]);
            float out_gate = sigmoidf_clamped(gates[3 * MIDAS_HIDDEN_DIM + i]);
            c[i] = forget_gate * c[i] + in_gate * cell_gate;
            h[i] = out_gate * tanhf(c[i]);
        }
    }
}

static void gru_forward(float x[MIDAS_TIMESTEPS][MIDAS_FEATURE_DIM], float h[MIDAS_HIDDEN_DIM]) {
    for (int i = 0; i < MIDAS_HIDDEN_DIM; i++) h[i] = 0.0f;
    float gi[3 * MIDAS_HIDDEN_DIM];
    float gh[3 * MIDAS_HIDDEN_DIM];

    for (int t = 0; t < MIDAS_TIMESTEPS; t++) {
        matvec_add(gi, midas_gru_weight_ih_l0, 3 * MIDAS_HIDDEN_DIM, MIDAS_FEATURE_DIM, x[t], midas_gru_bias_ih_l0);
        matvec_add(gh, midas_gru_weight_hh_l0, 3 * MIDAS_HIDDEN_DIM, MIDAS_HIDDEN_DIM, h, midas_gru_bias_hh_l0);
        for (int i = 0; i < MIDAS_HIDDEN_DIM; i++) {
            float r = sigmoidf_clamped(gi[i] + gh[i]);
            float z = sigmoidf_clamped(gi[MIDAS_HIDDEN_DIM + i] + gh[MIDAS_HIDDEN_DIM + i]);
            float n = tanhf(gi[2 * MIDAS_HIDDEN_DIM + i] + r * gh[2 * MIDAS_HIDDEN_DIM + i]);
            h[i] = (1.0f - z) * n + z * h[i];
        }
    }
}

int midas_rnn_classify_jsonl(const char *path, float logits[MIDAS_CLASSES]) {
    float x[MIDAS_TIMESTEPS][MIDAS_FEATURE_DIM];
    if (load_features(path, x) < 0) return -1;

    float lstm_h[MIDAS_HIDDEN_DIM];
    float gru_h[MIDAS_HIDDEN_DIM];
    float merged[2 * MIDAS_HIDDEN_DIM];
    lstm_forward(x, lstm_h);
    gru_forward(x, gru_h);
    for (int i = 0; i < MIDAS_HIDDEN_DIM; i++) {
        merged[i] = lstm_h[i];
        merged[MIDAS_HIDDEN_DIM + i] = gru_h[i];
    }

    int best = 0;
    for (int cls = 0; cls < MIDAS_CLASSES; cls++) {
        float v = midas_fc_bias[cls];
        for (int j = 0; j < 2 * MIDAS_HIDDEN_DIM; j++) {
            v += midas_fc_weight[cls * (2 * MIDAS_HIDDEN_DIM) + j] * merged[j];
        }
        logits[cls] = v;
        if (cls == 0 || v > logits[best]) best = cls;
    }
    return best;
}

const char *midas_attack_name(int cls) {
    switch (cls) {
        case 0: return "Benign";
        case 1: return "QueueFlooding";
        case 2: return "CacheDepletion";
        case 3: return "VerbsFlooding";
        case 4: return "VerbsAmplification";
        default: return "Unknown";
    }
}

#ifdef MIDAS_RNN_MAIN
int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s trace.jsonl\n", argv[0]);
        return 2;
    }
    float logits[MIDAS_CLASSES];
    int cls = midas_rnn_classify_jsonl(argv[1], logits);
    if (cls < 0) {
        perror(argv[1]);
        return 1;
    }
    printf("{\"class\":%d,\"name\":\"%s\",\"logits\":[", cls, midas_attack_name(cls));
    for (int i = 0; i < MIDAS_CLASSES; i++) {
        printf("%s%.9g", i ? "," : "", logits[i]);
    }
    printf("]}\n");
    return 0;
}
#endif
