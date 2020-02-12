package(licenses = ["notice"])

load("//tools:defs.bzl", "go_library")

go_library(
    name = "guard",
    srcs = [
        "guard.go",
	"msg.go",
	"linked_list.go"
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
	"@com_github_zeromq_goczmq//:go_default_library",
	"//pkg/log"
    ],
)

