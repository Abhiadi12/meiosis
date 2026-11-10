package graph_test

import (
	"time"

	"github.com/mindfire-test/meiosis/pkg/storage"
)

func storageBlob(id string) storage.BlobID { return storage.BlobID(id) }
func storageKind(k string) storage.Kind    { return storage.Kind(k) }
func mustTime() time.Time                  { return time.Unix(1_700_000_000, 0).UTC() }
