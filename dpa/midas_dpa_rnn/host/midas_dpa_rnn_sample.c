#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include <doca_error.h>
#include <doca_log.h>

#include "dpa_common.h"

DOCA_LOG_REGISTER(MIDAS_DPA_RNN::SAMPLE);

extern doca_dpa_func_t midas_rnn_kernel;

static void *wait_event_update_thread(void *event)
{
	doca_error_t result;

	sleep(1);
	result = doca_sync_event_update_set((struct doca_sync_event *)event, 5);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to update DOCA sync event: %s", doca_error_get_descr(result));
	return NULL;
}

doca_error_t midas_dpa_rnn_launch(struct dpa_resources *resources)
{
	struct doca_sync_event *wait_event = NULL;
	struct doca_sync_event *comp_event = NULL;
	pthread_t tid = 0;
	const uint64_t wait_thresh = 4;
	const uint64_t comp_event_val = 10;
	const unsigned int num_dpa_threads = 1;
	const uint64_t input_windows_q_addr = 0;
	const uint64_t output_logits_q_addr = 0;
	const unsigned int window_count = 1;
	doca_error_t result, tmp_result;
	int res;

	result = create_doca_dpa_wait_sync_event(resources->pf_dpa_ctx, resources->pf_doca_device, &wait_event);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create wait event: %s", doca_error_get_descr(result));
		return result;
	}

	result = create_doca_dpa_completion_sync_event(resources->pf_dpa_ctx,
						       resources->pf_doca_device,
						       &comp_event,
						       NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create completion event: %s", doca_error_get_descr(result));
		goto destroy_wait_event;
	}

	result = doca_dpa_kernel_launch_update_set(resources->pf_dpa_ctx,
						   wait_event,
						   wait_thresh,
						   comp_event,
						   comp_event_val,
						   num_dpa_threads,
						   &midas_rnn_kernel,
						   input_windows_q_addr,
						   output_logits_q_addr,
						   window_count);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to launch MIDAS DPA RNN kernel: %s", doca_error_get_descr(result));
		goto destroy_comp_event;
	}

	res = pthread_create(&tid, NULL, wait_event_update_thread, (void *)wait_event);
	if (res != 0) {
		result = DOCA_ERROR_OPERATING_SYSTEM;
		goto destroy_comp_event;
	}
	pthread_detach(tid);

	result = doca_sync_event_wait_gt(comp_event, comp_event_val - 1, SYNC_EVENT_MASK_FFS);
	if (result == DOCA_SUCCESS)
		DOCA_LOG_INFO("MIDAS DPA RNN kernel completed");
	else
		DOCA_LOG_ERR("Failed waiting for MIDAS DPA RNN completion: %s", doca_error_get_descr(result));

destroy_comp_event:
	sleep(1);
	tmp_result = doca_sync_event_destroy(comp_event);
	if (tmp_result != DOCA_SUCCESS)
		DOCA_ERROR_PROPAGATE(result, tmp_result);
destroy_wait_event:
	tmp_result = doca_sync_event_destroy(wait_event);
	if (tmp_result != DOCA_SUCCESS)
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	return result;
}
