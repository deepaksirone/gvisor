package netstack

var ServiceBlackList = map[string]struct{}{
	"nginx-thrift":                 struct{}{},
	"compose-post-redis":           struct{}{},
	"home-timeline-redis":          struct{}{},
	"media-memcached":              struct{}{},
	"media-mongodb":                struct{}{},
	"post-storage-memcached":       struct{}{},
	"post-storage-mongodb":         struct{}{},
	"social-graph-mongodb":         struct{}{},
	"social-graph-redis":           struct{}{},
	"url-shorten-memcached":        struct{}{},
	"url-shorten-mongodb":          struct{}{},
	"user-memcached":               struct{}{},
	"user-mongodb":                 struct{}{},
	"user-timeline-mongodb":        struct{}{},
	"user-timeline-redis":          struct{}{},
	"write-home-timeline-rabbitmq": struct{}{},
	"jaeger":                       struct{}{},
}
