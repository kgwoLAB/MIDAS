#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <doca_argp.h>
#include <doca_error.h>
#include <doca_log.h>

#include "dpa_common.h"

DOCA_LOG_REGISTER(MIDAS_DPA_RNN::MAIN);

doca_error_t midas_dpa_rnn_launch(struct dpa_resources *resources);

int main(int argc, char **argv)
{
	struct dpa_config cfg = {0};
	struct dpa_resources resources = {0};
	doca_error_t result;
	struct doca_log_backend *sdk_log;
	int exit_status = EXIT_FAILURE;

	strcpy(cfg.pf_device_name, DEVICE_DEFAULT_NAME);
	strcpy(cfg.rdma_device_name, DEVICE_DEFAULT_NAME);

	result = doca_log_backend_create_standard();
	if (result != DOCA_SUCCESS)
		goto sample_exit;

	result = doca_log_backend_create_with_file_sdk(stderr, &sdk_log);
	if (result != DOCA_SUCCESS)
		goto sample_exit;
	result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
	if (result != DOCA_SUCCESS)
		goto sample_exit;

	DOCA_LOG_INFO("Starting MIDAS DPA RNN sample");

	result = doca_argp_init(NULL, &cfg);
	if (result != DOCA_SUCCESS)
		goto sample_exit;

	result = register_dpa_params();
	if (result != DOCA_SUCCESS)
		goto argp_cleanup;

	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS)
		goto argp_cleanup;

	result = allocate_dpa_resources(&cfg, &resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate DPA resources: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	result = midas_dpa_rnn_launch(&resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("MIDAS DPA RNN launch failed: %s", doca_error_get_descr(result));
		goto dpa_cleanup;
	}

	exit_status = EXIT_SUCCESS;

dpa_cleanup:
	result = destroy_dpa_resources(&resources);
	if (result != DOCA_SUCCESS)
		exit_status = EXIT_FAILURE;
argp_cleanup:
	doca_argp_destroy();
sample_exit:
	if (exit_status == EXIT_SUCCESS)
		DOCA_LOG_INFO("MIDAS DPA RNN sample finished successfully");
	else
		DOCA_LOG_INFO("MIDAS DPA RNN sample finished with errors");
	return exit_status;
}
