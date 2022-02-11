module github.com/docker/docker

go 1.17

require (
	cloud.google.com/go v0.44.3
	code.cloudfoundry.org/clock v1.0.0
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78
	github.com/BurntSushi/toml v0.3.1
	github.com/Graylog2/go-gelf v0.0.0-20191017102106-1550ee647df0
	github.com/Microsoft/go-winio v0.4.20
	github.com/Microsoft/hcsshim v0.8.10-0.20210709175157-64a2b71405da
	github.com/Microsoft/opengcs v0.3.10-0.20190304234800-a10967154e14
	github.com/RackSec/srslog v0.0.0-20180709174129-a4725f04ec91
	github.com/armon/go-metrics v0.0.0-20150106224455-eb0af217e5e9
	github.com/armon/go-radix v0.0.0-20150105235045-e39d623f12e8
	github.com/aws/aws-sdk-go v1.28.11
	github.com/beorn7/perks v1.0.1
	github.com/bsphere/le_go v0.0.0-20170215134836-7a984a84b549
	github.com/cespare/xxhash/v2 v2.1.1
	github.com/cilium/ebpf v0.0.0-20200702112145-1c8d4c9ef775
	github.com/cloudflare/cfssl v0.0.0-20180323000720-5d63dbd981b5
	github.com/containerd/cgroups v0.0.0-20200824123100-0b889c03f102
	github.com/containerd/console v1.0.1
	github.com/containerd/continuity v0.0.0-20200710164510-efbc4488d8fe
	github.com/containerd/fifo v0.0.0-20201026212402-0724c46b320c
	github.com/containerd/go-runc v1.0.0
	github.com/containerd/ttrpc v1.0.2
	github.com/containerd/typeurl v1.0.1
	github.com/coreos/etcd v3.3.12+incompatible
	github.com/coreos/go-semver v0.2.0
	github.com/coreos/go-systemd v0.0.0-20180511133405-39ca1b05acc7
	github.com/coreos/go-systemd/v22 v22.0.0
	github.com/coreos/pkg v0.0.0-20160727233714-3ac0863d7acf
	github.com/creack/pty v1.1.11
	github.com/cyphar/filepath-securejoin v0.2.2
	github.com/deckarep/golang-set v0.0.0-20141123011944-ef32fa3046d9
	github.com/docker/go-connections v0.4.0
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c
	github.com/docker/go-metrics v0.0.1
	github.com/docker/go-units v0.4.0
	github.com/docker/libkv v0.2.2-0.20180912205406-458977154600
	github.com/docker/libnetwork v0.8.0-dev.2.0.20210525090646-64b7a4574d14
	github.com/docker/libtrust v0.0.0-20150526203908-9cbd2a1374f4
	github.com/docker/swarmkit v1.12.1-0.20210914142428-286f4575a2d2
	github.com/fernet/fernet-go v0.0.0-20180830025343-9eac43b88a5e
	github.com/fluent/fluent-logger-golang v1.4.0
	github.com/fsnotify/fsnotify v1.4.9
	github.com/godbus/dbus/v5 v5.0.3
	github.com/gofrs/flock v0.7.3
	github.com/gogo/googleapis v1.3.2
	github.com/gogo/protobuf v1.3.1
	github.com/golang/gddo v0.0.0-20190904175337-72a348e765d2
	github.com/golang/groupcache v0.0.0-20190702054246-869f871628b6
	github.com/golang/protobuf v1.3.5
	github.com/google/certificate-transparency-go v1.0.20
	github.com/google/go-cmp v0.2.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/google/uuid v1.1.1
	github.com/googleapis/gax-go v1.0.3
	github.com/gorilla/mux v1.8.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/grpc-ecosystem/grpc-opentracing v0.0.0-20180507213350-8e809c8a8645
	github.com/hashicorp/consul v0.5.2
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-memdb v0.0.0-20161216180745-cb9a474f84cc
	github.com/hashicorp/go-msgpack v0.0.0-20140221154404-71c2886f5a67
	github.com/hashicorp/go-multierror v1.0.0
	github.com/hashicorp/go-sockaddr v1.0.2
	github.com/hashicorp/golang-lru v0.5.3
	github.com/hashicorp/memberlist v0.1.1-0.20171201184301-3d8438da9589
	github.com/hashicorp/serf v0.7.1-0.20160317193612-598c54895cc5
	github.com/imdario/mergo v0.3.8
	github.com/inconshreveable/mousetrap v1.0.0
	github.com/ishidawataru/sctp v0.0.0-20210226210310-f2269e66cdee
	github.com/jmespath/go-jmespath v0.3.0
	github.com/matttproud/golang_protobuf_extensions v1.0.1
	github.com/miekg/dns v1.1.27
	github.com/mistifyio/go-zfs v2.1.2-0.20190413222219-f784269be439+incompatible
	github.com/mitchellh/hashstructure v1.0.0
	github.com/moby/buildkit v0.8.4-0.20211117082130-bc07b2b81b1c
	github.com/moby/ipvs v1.0.1
	github.com/moby/locker v1.0.1
	github.com/moby/sys v0.0.0-20201029181738-1bc8673b5755
	github.com/moby/term v0.0.0-20201110203204-bea5bbe245bf
	github.com/morikuni/aec v1.0.0
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2
	github.com/opencontainers/runc v1.0.0-rc92
	github.com/opencontainers/runtime-spec v1.0.3-0.20200728170252-4d89ac9fbff6
	github.com/opencontainers/selinux v1.8.0
	github.com/opentracing-contrib/go-stdlib v1.0.0
	github.com/opentracing/opentracing-go v1.2.0
	github.com/philhofer/fwd v1.0.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.6.0
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/common v0.9.1
	github.com/prometheus/procfs v0.0.11
	github.com/samuel/go-zookeeper v0.0.0-20150415181332-d0e0d8e11f31
	github.com/sean-/seed v0.0.0-20170313163322-e2103e2c3529
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635
	github.com/tchap/go-patricia v2.3.0+incompatible
	github.com/tinylib/msgp v1.1.0
	github.com/tonistiigi/fsutil v0.0.0-20201103201449-0834f99b7b85
	github.com/tonistiigi/units v0.0.0-20180711220420-6950e57a87ea
	github.com/ugorji/go v1.1.1
	github.com/vbatts/tar-split v0.11.1
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae
	github.com/willf/bitset v1.1.11
	go.etcd.io/bbolt v1.3.5
	go.opencensus.io v0.22.3
	golang.org/x/crypto v0.0.0-20201117144127-c1f2f97bffc9
	golang.org/x/net v0.0.0-20200707034311-ab3426394381
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	golang.org/x/sys v0.0.0-20210119212857-b64e53b001e4
	golang.org/x/text v0.3.3
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0
	google.golang.org/api v0.8.0
	google.golang.org/genproto v0.0.0-20200227132054-3f1135a288c9
	google.golang.org/grpc v1.27.1
	gotest.tools/v3 v3.0.3
)
