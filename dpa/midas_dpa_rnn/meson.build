project('MIDAS_DPA_RNN', 'C',
	version: '0.1',
	license: 'BSD-3',
	default_options: ['buildtype=debug'],
	meson_version: '>= 0.61.2'
)

SAMPLE_NAME = 'midas_dpa_rnn'
sample_program_name = SAMPLE_NAME + '_program'
doca_dpa_samples = '/opt/mellanox/doca/samples/doca_dpa'

add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: ['c'])

sample_dependencies = []
sample_dependencies += dependency('doca-common')
sample_dependencies += dependency('doca-dpa')
sample_dependencies += dependency('doca-rdma')
sample_dependencies += dependency('doca-argp')
sample_dependencies += dependency('libflexio')
sample_dependencies += dependency('threads')

sample_srcs = [
	'host/' + SAMPLE_NAME + '_sample.c',
	SAMPLE_NAME + '_main.c',
	doca_dpa_samples + '/dpa_common.c',
]

sample_inc_dirs = []
sample_inc_dirs += include_directories('.')
sample_inc_dirs += include_directories('include')
sample_inc_dirs += include_directories('/opt/mellanox/doca/samples/doca_dpa')

dpacc_build_script = doca_dpa_samples + '/build_dpacc_samples.sh'
sample_device_src = meson.project_source_root() + '/device/' + SAMPLE_NAME + '_kernels_dev.c'
doca_dep = dependency('doca-dpa')
doca_lib_dir = doca_dep.get_variable(pkgconfig : 'libdir')
dpacc_mcpu_flag = 'nv-dpa-bf3,nv-dpa-cx7,nv-dpa-cx8'

run_command(dpacc_build_script, meson.project_build_root(), sample_device_src, SAMPLE_NAME,
	    sample_program_name, dpacc_mcpu_flag, doca_lib_dir, check: true)

sample_device_build_dir = meson.project_build_root() + '/' + SAMPLE_NAME + '/device/build_dpacc'
dpa_program_lib = meson.get_compiler('c').find_library(sample_program_name, dirs : sample_device_build_dir,
							static: true)
sample_dependencies += dpa_program_lib

executable('doca_' + SAMPLE_NAME, sample_srcs,
	dependencies : sample_dependencies,
	include_directories: sample_inc_dirs,
	install: false)
