package enrich

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"ransomware-cti/internal/model"
)

type rng struct{ s uint64 }

func (r *rng) next() uint64 {
	r.s ^= r.s << 13
	r.s ^= r.s >> 7
	r.s ^= r.s << 17
	return r.s
}

func seed(group string) uint64 {
	h := sha256.Sum256([]byte("ioc-seed:" + group))
	v := binary.BigEndian.Uint64(h[:8])
	if v == 0 {
		v = 1
	}
	return v
}

func SyntheticIOCs(group string, n int) []model.IOC {
	r := &rng{s: seed(group)}
	out := make([]model.IOC, 0, n)
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			ip := fmt.Sprintf("%d.%d.%d.%d", 1+r.next()%223, r.next()%256, r.next()%256, 1+r.next()%254)
			out = append(out, model.IOC{Value: ip, Type: "ip", Group: group, MalwareFamily: group, Confidence: 50, Source: "synthetic"})
		} else {
			b := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", group, i, r.next())))
			out = append(out, model.IOC{Value: hex.EncodeToString(b[:]), Type: "hash", Group: group, MalwareFamily: group, Confidence: 50, Source: "synthetic"})
		}
	}
	return out
}
