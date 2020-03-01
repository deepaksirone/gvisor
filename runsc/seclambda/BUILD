load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "seclambda",
    srcs = [
	"guard.go",
	"msg.go",
	"linked_list.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
        "//test:__subpackages__",
    ],
    deps = [
        "@com_github_zeromq_goczmq//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
        "//runsc/specutils",
        "//pkg/log"
    ],
)
