#ifndef MIDAS_RNN_H
#define MIDAS_RNN_H

#ifdef __cplusplus
extern "C" {
#endif

int midas_rnn_classify_jsonl(const char *path, float logits[5]);
const char *midas_attack_name(int cls);

#ifdef __cplusplus
}
#endif

#endif
