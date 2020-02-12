load("@bazel_tools//tools/cpp:cc_toolchain_config_lib.bzl",
     "feature",
     "flag_group",
     "flag_set",
     "tool_path")
load("@bazel_tools//tools/build_defs/cc:action_names.bzl", "ACTION_NAMES")
def _impl(ctx):
     tool_paths = [
      	  tool_path(
            name = "gcc",
            path = "musl/bin/x86_64-linux-musl-gcc",
        ),
	tool_path(
            name = "g++",
	    path = "musl/bin/x86_64-linux-musl-g++",
	),
        tool_path(
            name = "ld",
            path = "musl/bin/x86_64-linux-musl-ld",
        ),
        tool_path(
            name = "ar",
            path = "musl/bin/ar.py",
        ),
        tool_path(
            name = "cpp",
            path = "musl/bin/x86_64-linux-musl-cpp",
        ),
        tool_path(
            name = "gcov",
            path = "musl/bin/x86_64-linux-musl-gcov",
        ),
        tool_path(
            name = "nm",
            path = "musl/bin/x86_64-linux-musl-nm",
        ),
        tool_path(
            name = "objdump",
            path = "musl/bin/x86_64-linux-musl-objdump",
        ),
        tool_path(
            name = "strip",
            path = "musl/bin/x86_64-linux-musl-strip",
        ),
    ]
     toolchain_include_directories_feature = feature(
        name = "toolchain_include_directories",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.assemble,
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.linkstamp_compile,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_header_parsing,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.cpp_module_codegen,
                    ACTION_NAMES.lto_backend,
                    ACTION_NAMES.clif_match,
                ],
                flag_groups = [
                    flag_group(
                        flags = [
			    "-L",
			    "tools/musl/x86_64-linux-musl/lib",
                            "-I",
			    "tools/musl/x86_64-linux-musl/include/c++/8.3.0/",
			    "-I",
                            "tools/musl/x86_64-linux-musl/include",
                            "-I",
                            "tools/musl/x86_64-linux-musl/include/c++",
			    "-I",
			    "tools/musl/x86_64-linux-musl/include/c++/8.3.0/x86_64-linux-musl",
			    "-I",
			    "tools/musl/x86_64-linux-musl/include/c++/8.3.0/x86_64-linux-musl/bits",
			    "-I",
			    "tools/musl/x86_64-linux-musl/include/c++/8.3.0",
                        ],
                    ),
                ],
            ),
        ],
    )
     toolchain_link_include_feature = feature(
        name = "toolchain_link_includes",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.cpp_link_executable,
		    ACTION_NAMES.cpp_link_dynamic_library,
		    ACTION_NAMES.cpp_link_static_library,
                ],
                flag_groups = [
                    flag_group(
                        flags = [
			    "-L",
                            "tools/musl/x86_64-linux-musl/lib",
			    "-l:libstdc++.a",
                        ],
                    ),
                ],
            ),
        ],
    )

     return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        toolchain_identifier = "gcc-musl",
        host_system_name = "linux",
        target_system_name = "linux",
        target_cpu = "x86_64",
        target_libc = "x86_64",
        compiler = "gcc",
        abi_version = "unknown",
        abi_libc_version = "unknown",
	tool_paths = tool_paths,
	features = [toolchain_include_directories_feature, toolchain_link_include_feature],
    )

cc_toolchain_config = rule(
    implementation = _impl,
    attrs = {},
    provides = [CcToolchainConfigInfo],
)
