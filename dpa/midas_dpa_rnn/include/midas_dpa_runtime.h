#ifndef MIDAS_DPA_RUNTIME_H
#define MIDAS_DPA_RUNTIME_H

#include <stdint.h>

/*
 * Runtime launch ABI for MIDAS DPA inference.
 *
 * input_windows_q_addr points to a DPA-visible int32 array laid out as:
 *   [window][MIDAS_TIMESTEPS][MIDAS_FEATURE_DIM]
 *
 * output_logits_q_addr points to a DPA-visible int32 array laid out as:
 *   [window][1 + MIDAS_CLASSES]
 * where element 0 is the predicted class and elements 1..N are qlogits.
 *
 * Passing zero for either pointer preserves the standalone sample behavior:
 * the device kernel uses the generated midas_rnn_fixed_input.h window and logs
 * the result.
 */
struct midas_dpa_runtime_launch {
	uint64_t input_windows_q_addr;
	uint64_t output_logits_q_addr;
	uint32_t window_count;
};

#endif
