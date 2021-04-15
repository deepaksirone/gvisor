package(licenses = ["notice"])

load("//tools:defs.bzl", "go_library")

go_library(
    name = "guard",
    srcs = [
        "guard.go",
	"msg.go",
	"linked_list.go",
	"parser.go"
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
	"@com_github_opencontainers_runtime-spec//specs-go:go_default_library",
	"@org_golang_x_sys//unix:go_default_library",
	"//runsc/specutils",
	"//pkg/log"
    ],
)

